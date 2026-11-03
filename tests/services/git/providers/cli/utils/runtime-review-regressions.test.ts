/**
 * @fileoverview Real provider regressions for normal cleanup and nested controls.
 * @module tests/services/git/providers/cli/utils/runtime-review-regressions.test
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';

import { config } from '../../../../../../src/config/index.js';
import { createMcpToolHandler } from '../../../../../../src/mcp-server/tools/utils/toolHandlerFactory.js';
import type { SdkContext } from '../../../../../../src/mcp-server/tools/utils/toolDefinition.js';
import { CliGitProvider } from '../../../../../../src/services/git/providers/cli/CliGitProvider.js';
import { getGitExecutionContext } from '../../../../../../src/services/git/providers/cli/utils/execution-context.js';
import { GitExecutionError } from '../../../../../../src/services/git/providers/cli/utils/execution-errors.js';
import { buildTrustedGitEnvironment } from '../../../../../../src/services/git/providers/cli/utils/execution-policy.js';
import type { GitDiffResult } from '../../../../../../src/services/git/types.js';

const reason = (expected: string) => (error: unknown) => {
  assert.ok(error instanceof GitExecutionError);
  assert.equal(error.reason, expected, error.message);
  return true;
};

describe('native runtime review regressions', { timeout: 90000 }, () => {
  let directory: string;
  let repository: string;
  let saved: typeof config.git;
  const context = () => ({
    workingDirectory: repository,
    requestContext: {
      requestId: 'runtime-review',
      timestamp: new Date().toISOString(),
    },
    repositoryRoots: Object.freeze([repository]),
  });
  const calls = () => path.join(directory, 'calls');

  beforeEach(async () => {
    saved = { ...config.git };
    directory = await mkdtemp(path.join(tmpdir(), 'git-runtime-review-'));
    const home = path.join(directory, 'home');
    repository = path.join(directory, 'repository');
    await mkdir(home);
    await mkdir(repository);
    await writeFile(
      path.join(home, '.gitconfig'),
      '[user]\n name = Runtime Review\n email = runtime-review@example.invalid\n[commit]\n gpgsign = false\n',
    );
    Object.assign(config.git, {
      executionProfile: 'trusted',
      binaryPath: '/usr/bin/git',
      trustedHome: home,
      trustedPath: '/usr/bin:/bin',
      maxCommandTimeoutMs: 8000,
      maxOutputBytes: 1048576,
      maxStdoutBytes: 1048576,
      maxStderrBytes: 1048576,
      terminationGraceMs: 30,
    });
    const env = buildTrustedGitEnvironment(
      {
        profile: 'trusted',
        binaryPath: '/usr/bin/git',
        homeDirectory: home,
        helperPath: '/usr/bin:/bin',
      },
      {},
    );
    const git = (...args: string[]) =>
      execFileSync('/usr/bin/git', args, { cwd: repository, env });
    git('init', '--quiet');
    git('commit', '--quiet', '--allow-empty', '--message=fixture');
  });

  afterEach(async () => {
    Object.assign(config.git, saved);
    await rm(directory, { recursive: true, force: true });
  });

  const installGit = async (source: string) => {
    const binary = path.join(directory, 'git-fixture');
    await writeFile(binary, '#!/bin/sh\n' + source + '\n');
    await chmod(binary, 0o700);
    config.git.binaryPath = binary;
  };

  const runSdk = async (
    operation: () => Promise<void>,
    signal = new AbortController().signal,
  ) => {
    let formatted = false;
    const handler = createMcpToolHandler({
      toolName: 'runtime_review_fixture',
      inputSchema: z.object({}),
      logic: async () => {
        assert.ok(getGitExecutionContext(), 'actual SDK execution scope');
        await operation();
        return { completed: true };
      },
      responseFormatter: () => {
        formatted = true;
        return [];
      },
    });
    const result = await handler({}, {
      signal,
      requestId: 'runtime-review',
    } as unknown as SdkContext);
    return { result, formatted };
  };

  const waitForCalls = async () => {
    const deadline = Date.now() + 2000;
    while (!existsSync(calls()) && Date.now() < deadline) await delay(10);
    assert.ok(existsSync(calls()), 'validation actually started');
  };

  const assertHeartbeatStopped = async () => {
    const heartbeat = path.join(directory, 'heartbeat');
    const before = await readFile(heartbeat, 'utf8');
    assert.ok(before.length > 0, 'child was live before cancellation');
    await delay(100);
    assert.equal(await readFile(heartbeat, 'utf8'), before);
  };

  it('finishes a successful validation before a deadline shorter than TERM grace', async () => {
    config.git.terminationGraceMs = 4000;
    const started = Date.now();
    await new CliGitProvider().validateRepository(repository, {
      ...context(),
      deadline: started + 1500,
    });
    assert.ok(Date.now() - started < 1500);
  });

  it(
    'completes a real 60-file untracked diff inside one 30-second SDK request',
    { timeout: 45000 },
    async () => {
      config.git.maxCommandTimeoutMs = 30000;
      config.git.terminationGraceMs = 250;
      await installGit('printf \'run\\n\' >> ../calls\nexec /usr/bin/git "$@"');
      const count = 60;
      await Promise.all(
        Array.from({ length: count }, (_, index) =>
          writeFile(
            path.join(
              repository,
              'tiny-' + String(index).padStart(2, '0') + '.txt',
            ),
            'line ' + index + '\n',
          ),
        ),
      );
      let diff: GitDiffResult | undefined;
      const started = Date.now();
      const { result, formatted } = await runSdk(async () => {
        diff = await new CliGitProvider().diff(
          { includeUntracked: true },
          context(),
        );
      });
      assert.notEqual(result.isError, true);
      assert.equal(formatted, true);
      assert.ok(diff);
      assert.equal(diff.filesChanged, count);
      assert.equal(diff.insertions, count);
      assert.equal(diff.deletions, 0);
      for (let index = 0; index < count; index++)
        assert.ok(diff.diff.includes('+line ' + index + '\n'));
      assert.ok(
        (await readFile(calls(), 'utf8')).split('\n').filter(Boolean).length >=
          2 * count,
      );
      assert.ok(Date.now() - started < 30000);
    },
  );

  for (const control of [
    'independent abort',
    'shorter provider deadline',
    'outer abort',
    'shorter outer deadline',
  ] as const) {
    it(
      'preserves nested validation control: ' + control,
      { timeout: 10000 },
      async () => {
        await installGit(
          "trap '' TERM\nprintf x >> ../heartbeat\nprintf 'run\\n' >> ../calls\nwhile :; do printf x >> ../heartbeat; sleep 0.02; done",
        );
        const outer = new AbortController();
        const provider = new AbortController();
        if (control === 'shorter outer deadline')
          config.git.maxCommandTimeoutMs = 1200;
        const expected = control.includes('abort') ? 'CANCELLED' : 'DEADLINE';
        let assertionsComplete = false;
        let validationFailure: unknown;
        const started = Date.now();
        const { result, formatted } = await runSdk(async () => {
          const pending = new CliGitProvider().validateRepository(repository, {
            ...context(),
            signal: provider.signal,
            deadline:
              Date.now() +
              (control === 'shorter provider deadline' ? 1200 : 16000),
          });
          void pending.catch(() => {});
          await waitForCalls();
          if (control === 'independent abort') provider.abort();
          if (control === 'outer abort') outer.abort();
          await assert.rejects(pending, (error: unknown) => {
            validationFailure = error;
            return reason(expected)(error);
          });
          // A caught nested failure must still poison the SDK request and prevent
          // another real Git child, rather than letting the tool format success.
          await assert.rejects(
            new CliGitProvider().validateRepository(repository, context()),
            reason(expected),
          );
          assertionsComplete = true;
        }, outer.signal);
        reason(expected)(validationFailure);
        assert.equal(assertionsComplete, true);
        assert.equal(result.isError, true);
        assert.equal(formatted, false);
        assert.ok(
          Date.now() - started < 4000,
          'nested control beats outer 8-second limit',
        );
        assert.equal(await readFile(calls(), 'utf8'), 'run\n');
        await assertHeartbeatStopped();
      },
    );
  }

  it('shares the SDK raw-byte budget across nested real provider validations', async () => {
    config.git.maxOutputBytes = 9; // two successful rev-parse outputs need 10 bytes
    await installGit('printf \'run\\n\' >> ../calls\nexec /usr/bin/git "$@"');
    let assertionsComplete = false;
    const { result, formatted } = await runSdk(async () => {
      const provider = new CliGitProvider();
      const nested = { ...context(), signal: new AbortController().signal };
      await provider.validateRepository(repository, nested);
      await assert.rejects(
        provider.validateRepository(repository, nested),
        reason('OUTPUT_LIMIT'),
      );
      await assert.rejects(
        provider.validateRepository(repository, nested),
        reason('OUTPUT_LIMIT'),
      );
      assertionsComplete = true;
    });
    assert.equal(assertionsComplete, true);
    assert.equal(result.isError, true);
    assert.equal(formatted, false);
    assert.equal(await readFile(calls(), 'utf8'), 'run\nrun\n');
  });

  it('keeps standalone trusted validation and restricted pre-spawn rejection', async () => {
    const provider = new CliGitProvider();
    await provider.validateRepository(repository, context());
    await installGit('printf \'run\\n\' >> ../calls\nexec /usr/bin/git "$@"');
    config.git.executionProfile = 'restricted';
    await assert.rejects(
      provider.validateRepository(repository, context()),
      reason('POLICY_UNSUPPORTED'),
    );
    assert.equal(existsSync(calls()), false);
  });
});
