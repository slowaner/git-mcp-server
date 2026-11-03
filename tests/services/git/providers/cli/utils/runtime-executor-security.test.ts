/**
 * @fileoverview Production executor, provider and SDK lifecycle acceptance.
 * @module tests/services/git/providers/cli/utils/runtime-executor-security.test
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { config } from '../../../../../../src/config/index.js';
import { CliGitProvider } from '../../../../../../src/services/git/providers/cli/CliGitProvider.js';
import { executeGitCommand } from '../../../../../../src/services/git/providers/cli/utils/git-executor.js';
import { withConfiguredGitExecutionContext } from '../../../../../../src/services/git/providers/cli/utils/configured-execution-policy.js';
import { GitExecutionError } from '../../../../../../src/services/git/providers/cli/utils/execution-errors.js';
import { buildTrustedGitEnvironment } from '../../../../../../src/services/git/providers/cli/utils/execution-policy.js';
import { createMcpToolHandler } from '../../../../../../src/mcp-server/tools/utils/toolHandlerFactory.js';
import type { SdkContext } from '../../../../../../src/mcp-server/tools/utils/toolDefinition.js';
import { z } from 'zod';

const reason = (expected: string) => (error: unknown) => {
  assert.ok(error instanceof GitExecutionError);
  assert.equal(error.reason, expected);
  return true;
};

describe('production native Git execution', { timeout: 20000 }, () => {
  let directory: string;
  let home: string;
  let saved: typeof config.git;
  let env: Record<string, string>;
  const context = () => ({
    workingDirectory: directory,
    requestContext: {
      requestId: 'runtime-test',
      timestamp: new Date().toISOString(),
    },
  });
  const git = (...args: string[]) =>
    execFileSync('/usr/bin/git', args, {
      cwd: directory,
      env,
      encoding: 'utf8',
    });
  beforeEach(async () => {
    saved = { ...config.git };
    directory = await mkdtemp(path.join(tmpdir(), 'git-executor-security-'));
    home = path.join(directory, 'home');
    await mkdir(home);
    await writeFile(
      path.join(home, '.gitconfig'),
      '[user]\n name = Runtime Fixture\n email = runtime@example.invalid\n[commit]\n gpgsign = false\n',
    );
    Object.assign(config.git, {
      executionProfile: 'trusted',
      binaryPath: '/usr/bin/git',
      trustedHome: home,
      trustedPath: '/usr/bin:/bin',
      maxCommandTimeoutMs: 5000,
      maxOutputBytes: 65536,
      maxStdoutBytes: 65536,
      maxStderrBytes: 65536,
      terminationGraceMs: 30,
    });
    env = buildTrustedGitEnvironment(
      {
        profile: 'trusted',
        binaryPath: '/usr/bin/git',
        homeDirectory: home,
        helperPath: '/usr/bin:/bin',
      },
      {},
    );
    git('init', '--quiet');
  });
  afterEach(async () => {
    Object.assign(config.git, saved);
    await rm(directory, { recursive: true, force: true });
  });

  it('defaults to restricted and rejects provider init before destination mkdir', async () => {
    config.git.executionProfile = 'restricted';
    const destination = path.join(directory, 'must-not-exist');
    await assert.rejects(
      new CliGitProvider().init(
        { path: destination },
        { ...context(), workingDirectory: destination },
      ),
      reason('POLICY_UNSUPPORTED'),
    );
    await assert.rejects(readFile(path.join(destination, '.git', 'config')));
    await assert.rejects(
      import('node:fs/promises').then(({ stat }) => stat(destination)),
      { code: 'ENOENT' },
    );
    await assert.rejects(
      executeGitCommand(['status'], '/missing'),
      reason('POLICY_UNSUPPORTED'),
    );
  });

  it('runs ordinary provider operations only after explicit trusted opt-in', async () => {
    const provider = new CliGitProvider();
    const status = await provider.status({}, context());
    assert.equal(status.isClean, false); // private fixture HOME is an untracked directory
    assert.match(
      (await executeGitCommand(['--version'], directory)).stdout,
      /^git version /,
    );
  });

  it('returns exact UTF8 blob bytes and poisons the whole request on a nonUTF8 blob', async () => {
    const text = Buffer.from('\uFEFF\uFFFD😀\0line\n\r\t');
    const file = path.join(directory, 'utf8');
    await writeFile(file, text);
    const good = git('hash-object', '-w', file).trim();
    await writeFile(file, Buffer.from([0x61, 0xff, 0x62]));
    const bad = git('hash-object', '-w', file).trim();
    const result = await executeGitCommand(
      ['cat-file', 'blob', good],
      directory,
    );
    assert.deepEqual(Buffer.from(result.stdout, 'utf8'), text);
    await assert.rejects(
      withConfiguredGitExecutionContext(undefined, async () => {
        await assert.rejects(
          executeGitCommand(['cat-file', 'blob', bad], directory),
          reason('INVALID_OUTPUT_ENCODING'),
        );
        await assert.rejects(
          executeGitCommand(['--version'], directory),
          reason('INVALID_OUTPUT_ENCODING'),
        );
      }),
      reason('INVALID_OUTPUT_ENCODING'),
    );
  });

  it('retains explicit trusted native SSH signing and same-HOME effective config', async () => {
    const key = path.join(home, 'signing-key');
    execFileSync(
      '/usr/bin/ssh-keygen',
      ['-q', '-t', 'ed25519', '-N', '', '-f', key],
      { env },
    );
    git('config', 'gpg.format', 'ssh');
    git('config', 'user.signingkey', key);
    await executeGitCommand(
      ['commit', '--allow-empty', '-S', '--message=trusted signing'],
      directory,
    );
    const object = await executeGitCommand(
      ['cat-file', 'commit', 'HEAD'],
      directory,
    );
    assert.match(object.stdout, /gpgsig -----BEGIN SSH SIGNATURE-----/);
    const effective = await executeGitCommand(
      ['config', '--null', '--list', '--includes'],
      directory,
    );
    assert.ok(effective.stdout.includes('user.name\nRuntime Fixture\0'));
    assert.ok(effective.stdout.includes('gpg.format\nssh\0'));
  });

  it('honors configured deadline through the production executor', async () => {
    const shim = path.join(directory, 'git-fixture');
    await writeFile(shim, '#!/bin/sh\ntrap "" TERM\nsleep 30\n');
    await chmod(shim, 0o700);
    config.git.binaryPath = shim;
    config.git.maxCommandTimeoutMs = 100;
    const started = Date.now();
    await assert.rejects(
      executeGitCommand(['--version'], directory),
      reason('DEADLINE'),
    );
    assert.ok(Date.now() - started < 2000);
  });

  it('enforces aggregate raw-byte cap across actual executor metadata calls', async () => {
    config.git.maxOutputBytes = 10;
    await assert.rejects(
      withConfiguredGitExecutionContext(undefined, async () => {
        await assert.rejects(
          executeGitCommand(['--version'], directory),
          reason('OUTPUT_LIMIT'),
        );
        await assert.rejects(
          executeGitCommand(['status'], directory),
          reason('OUTPUT_LIMIT'),
        );
      }),
      reason('OUTPUT_LIMIT'),
    );
  });

  it('SDK cancellation reaches Git and prevents response formatting after failure', async () => {
    const shim = path.join(directory, 'git-fixture');
    await writeFile(shim, '#!/bin/sh\ntrap "" TERM\nsleep 30\n');
    await chmod(shim, 0o700);
    config.git.binaryPath = shim;
    const controller = new AbortController();
    let formatted = false;
    const handler = createMcpToolHandler({
      toolName: 'runtime_fixture',
      inputSchema: z.object({}),
      logic: async () => ({
        output: (await executeGitCommand(['--version'], directory)).stdout,
      }),
      responseFormatter: () => {
        formatted = true;
        return [];
      },
    });
    const pending = handler({}, {
      signal: controller.signal,
      requestId: 'fixture',
    } as unknown as SdkContext);
    setTimeout(() => controller.abort(), 100);
    const result = await pending;
    assert.equal(result.isError, true);
    assert.equal(formatted, false);
  });
});
