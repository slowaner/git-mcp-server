/**
 * @fileoverview Linux-only native filename and production SDK terminal-output qualification.
 * @module scripts/security/linux-filename-profile
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { z } from 'zod';
import { config } from '../../src/config/index.js';
import { createMcpToolHandler } from '../../src/mcp-server/tools/utils/toolHandlerFactory.js';
import type { SdkContext } from '../../src/mcp-server/tools/utils/toolDefinition.js';
import { CliGitProvider } from '../../src/services/git/providers/cli/CliGitProvider.js';
import { getGitExecutionContext } from '../../src/services/git/providers/cli/utils/execution-context.js';
import { GitExecutionError } from '../../src/services/git/providers/cli/utils/execution-errors.js';
import { buildTrustedGitEnvironment } from '../../src/services/git/providers/cli/utils/execution-policy.js';

/** Explicit CI program, never a conditional skip or a supported-local raw probe. */
export async function verifyLinuxFilenameProfile(): Promise<void> {
  if (process.platform !== 'linux')
    throw new Error('Linux native filename profile required.');
  const temporary = realpathSync(
    mkdtempSync(join(tmpdir(), 'native-filename-profile-')),
  );
  const repository = join(temporary, 'repository');
  const home = join(temporary, 'home');
  const log = join(temporary, 'calls');
  const binary = join(temporary, 'git-profile');
  const saved = { ...config.git };
  const quote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
  const calls = () =>
    existsSync(log)
      ? readFileSync(log, 'utf8').split('\n').filter(Boolean).length
      : 0;
  let stage = 'setup';
  let first: unknown;
  let partialResult = false;
  let formatted = false;
  let completed = false;
  try {
    mkdirSync(repository, { mode: 0o700 });
    mkdirSync(home, { mode: 0o700 });
    const env = buildTrustedGitEnvironment(
      {
        profile: 'trusted',
        binaryPath: '/usr/bin/git',
        homeDirectory: home,
        helperPath: '/usr/bin:/bin',
      },
      {},
    );
    execFileSync(
      '/usr/bin/git',
      ['init', '-q', '--initial-branch=main', '--template='],
      { cwd: repository, env },
    );
    writeFileSync(join(repository, 'valid-\ufffd.txt'), 'valid\n');
    const rawName = Buffer.concat([
      Buffer.from('invalid-'),
      Buffer.from([0xff]),
    ]);
    stage = 'create-native-byte-filename';
    writeFileSync(
      Buffer.concat([Buffer.from(`${repository}/`), rawName]),
      'invalid filename bytes\n',
    );
    stage = 'verify-native-byte-filename';
    assert.ok(
      readdirSync(repository, { encoding: 'buffer' }).some((name) =>
        name.equals(rawName),
      ),
    );
    const observed = execFileSync(
      '/usr/bin/git',
      ['ls-files', '--others', '--exclude-standard', '-z'],
      { cwd: repository, env },
    );
    assert.ok(observed.includes(Buffer.concat([rawName, Buffer.from([0])])));
    assert.ok(observed.includes(Buffer.from('valid-\ufffd.txt\0')));
    writeFileSync(
      binary,
      `#!/bin/sh\nprintf 'call\\n' >> ${quote(log)}\nexec /usr/bin/git "$@"\n`,
      { mode: 0o700 },
    );
    Object.assign(config.git, {
      executionProfile: 'trusted',
      binaryPath: binary,
      trustedHome: home,
      trustedPath: '/usr/bin:/bin',
      baseDirs: [repository],
    });
    const context = {
      workingDirectory: repository,
      repositoryRoots: [repository],
      requestContext: {
        requestId: 'native-filename-profile',
        timestamp: new Date().toISOString(),
      },
    };
    const handler = createMcpToolHandler({
      toolName: 'native_filename_profile',
      inputSchema: z.object({}),
      logic: async () => {
        assert.ok(getGitExecutionContext());
        stage = 'production-fatal-utf8';
        await assert.rejects(
          new CliGitProvider()
            .diff({ includeUntracked: true }, context)
            .then((value) => {
              partialResult = true;
              return value;
            }),
          (error) => {
            first = error;
            assert.ok(error instanceof GitExecutionError);
            assert.equal(error.reason, 'INVALID_OUTPUT_ENCODING');
            return true;
          },
        );
        assert.equal(partialResult, false);
        assert.ok(calls() > 0);
        const before = calls();
        stage = 'terminal-no-later-git';
        await assert.rejects(
          new CliGitProvider().validateRepository(repository, context),
          (error) => error === first,
        );
        assert.equal(calls(), before);
        completed = true;
        return { completed: true };
      },
      responseFormatter: () => {
        formatted = true;
        return [];
      },
    });
    const result = await handler({}, {
      signal: new AbortController().signal,
      requestId: 'native-filename-profile',
    } as unknown as SdkContext);
    stage = 'sdk-terminal-result';
    assert.equal(completed, true);
    assert.equal(result.isError, true);
    assert.equal(formatted, false);
    assert.equal(partialResult, false);
    console.log(
      JSON.stringify({
        profile: 'linux-native-filenames',
        platform: process.platform,
        arch: process.arch,
        bunVersion: Bun.version,
        actualNativeFilename: true,
        actualGitBytes: true,
        invalidOutputEncoding: true,
        partialResult,
        formatted,
        terminalNoLaterGit: true,
      }),
    );
  } catch (error) {
    console.error(
      JSON.stringify({
        profile: 'linux-native-filenames',
        stage,
        errorClass:
          error instanceof Error ? error.constructor.name : typeof error,
        firstReason: first instanceof GitExecutionError ? first.reason : null,
        partialResult,
        formatted,
        completed,
      }),
    );
    throw new Error('Native filename profile incomplete.');
  } finally {
    Object.assign(config.git, saved);
    rmSync(temporary, { recursive: true, force: true });
  }
}

if (import.meta.main) {
  try {
    await verifyLinuxFilenameProfile();
  } catch {
    process.exitCode = 1;
  }
}
