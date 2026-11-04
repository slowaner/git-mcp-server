/**
 * @fileoverview Actual SDK request isolation for terminal untracked framing errors.
 * @module tests/security/untracked-diff-format-sdk.test
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { z } from 'zod';
import { config } from '@/config/index.js';
import { createMcpToolHandler } from '@/mcp-server/tools/utils/toolHandlerFactory.js';
import type { SdkContext } from '@/mcp-server/tools/utils/toolDefinition.js';
import { CliGitProvider } from '@/services/git/providers/cli/CliGitProvider.js';
import { executeDiff } from '@/services/git/providers/cli/operations/commits/diff.js';
import {
  getGitExecutionContext,
  recordGitExecutionFailure,
} from '@/services/git/providers/cli/utils/execution-context.js';
import { GitExecutionError } from '@/services/git/providers/cli/utils/execution-errors.js';
import { executeGitCommand } from '@/services/git/providers/cli/utils/git-executor.js';
import { buildTrustedGitEnvironment } from '@/services/git/providers/cli/utils/execution-policy.js';
import { parseUntrackedDiffOutput } from '@/services/git/providers/cli/utils/untracked-diff-output.js';
import { JsonRpcErrorCode } from '@/types-global/errors.js';

describe(
  'terminal combined framing in actual SDK scope',
  { timeout: 15000 },
  () => {
    let temporary: string;
    let repository: string;
    let home: string;
    let log: string;
    let saved: typeof config.git;
    const context = () => ({
      workingDirectory: repository,
      repositoryRoots: [repository],
      requestContext: {
        requestId: 'framing-sdk',
        timestamp: new Date().toISOString(),
      },
    });
    const calls = () => (existsSync(log) ? readFileSync(log, 'utf8') : '');
    const runSdk = async (operation: () => Promise<void>) => {
      let formatted = false;
      const handler = createMcpToolHandler({
        toolName: 'untracked_framing_fixture',
        inputSchema: z.object({}),
        logic: async () => {
          assert.ok(getGitExecutionContext());
          await operation();
          return { completed: true };
        },
        responseFormatter: () => {
          formatted = true;
          return [];
        },
      });
      const result = await handler({}, {
        signal: new AbortController().signal,
        requestId: 'framing-sdk',
      } as unknown as SdkContext);
      return { result, formatted };
    };
    beforeEach(() => {
      saved = { ...config.git };
      temporary = realpathSync(
        mkdtempSync(join(tmpdir(), 'untracked-format-sdk-')),
      );
      repository = join(temporary, 'repository');
      home = join(temporary, 'home');
      log = join(temporary, 'calls');
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
      execFileSync('/usr/bin/git', ['init', '-q'], { cwd: repository, env });
      writeFileSync(join(repository, 'new.txt'), 'literal contents\n');
      const quote = (value: string) =>
        "'" + value.replaceAll("'", "'\\''") + "'";
      const binary = join(temporary, 'git-fixture');
      // A native executable fixture corrupts only the diff payload. Every
      // effective-config/metadata query still uses the production controlled path.
      writeFileSync(
        binary,
        `#!/bin/sh\nprintf 'call\\n' >> ${quote(log)}\nif [ "$1" = diff ] && [ "$2" = --no-index ]; then printf 'malformed-prefix\\n'; exit 1; fi\nexec /usr/bin/git "$@"\n`,
        { mode: 0o700 },
      );
      Object.assign(config.git, {
        executionProfile: 'trusted',
        binaryPath: binary,
        trustedHome: home,
        trustedPath: '/usr/bin:/bin',
        baseDirs: [repository],
      });
    });
    afterEach(() => {
      Object.assign(config.git, saved);
      rmSync(temporary, { recursive: true, force: true });
    });

    const assertFormat = (error: unknown) => {
      assert.ok(error instanceof GitExecutionError);
      assert.equal(error.reason, 'INVALID_OUTPUT_FORMAT');
      assert.equal(error.code, JsonRpcErrorCode.InvalidRequest);
      assert.equal(
        error.message,
        'Invalid combined untracked Git diff output.',
      );
      assert.deepEqual(error.data, { reason: 'INVALID_OUTPUT_FORMAT' });
      return true;
    };
    it('keeps caught malformed native output terminal, without another invocation or formatter', async () => {
      let complete = false;
      let first: unknown;
      const { result, formatted } = await runSdk(async () => {
        const malformed = await executeGitCommand(
          ['diff', '--no-index', '/dev/null', 'new.txt'],
          repository,
          { allowNonZeroExit: true, repositoryRoots: [repository] },
        );
        assert.equal(malformed.exitCode, 1);
        assert.equal(malformed.stdout, 'malformed-prefix\n');
        assert.match(calls(), /^(call\n)+$/);
        assert.throws(
          () => parseUntrackedDiffOutput(malformed.stdout, 'new.txt'),
          (error: unknown) => {
            first = error;
            return assertFormat(error);
          },
        );
        const before = calls();
        await assert.rejects(
          new CliGitProvider().validateRepository(repository, context()),
          (error: unknown) => error === first && assertFormat(error),
        );
        assert.equal(calls(), before);
        complete = true;
      });
      assert.equal(complete, true);
      assert.equal(result.isError, true);
      assert.equal(formatted, false);
      assertFormat(first);
      const before = calls();
      const separate = await runSdk(async () => {
        await new CliGitProvider().validateRepository(repository, context());
      });
      assert.notEqual(
        separate.result.isError,
        true,
        JSON.stringify(separate.result),
      );
      assert.equal(separate.formatted, true);
      assert.ok(
        calls().length > before.length,
        'independent request actually spawns Git',
      );
    });
    it('preserves an earlier failure identity and first reason', async () => {
      const earlier = new GitExecutionError(
        'OUTPUT_LIMIT',
        'Earlier raw output limit.',
      );
      let complete = false;
      const { result, formatted } = await runSdk(async () => {
        recordGitExecutionFailure(earlier);
        assert.throws(
          () => parseUntrackedDiffOutput('malformed', 'new.txt'),
          (error: unknown) => error === earlier,
        );
        await assert.rejects(
          new CliGitProvider().validateRepository(repository, context()),
          (error: unknown) => error === earlier,
        );
        assert.equal(calls(), '');
        complete = true;
      });
      assert.equal(complete, true);
      assert.equal(result.isError, true);
      assert.equal(formatted, false);
    });
    it('makes malformed combined output terminal through the actual diff provider', async () => {
      let complete = false;
      const { result, formatted } = await runSdk(async () => {
        let failure: unknown;
        await assert.rejects(
          new CliGitProvider().diff({ includeUntracked: true }, context()),
          (error: unknown) => {
            failure = error;
            return assertFormat(error);
          },
        );
        const before = calls();
        assert.ok(before.length > 0);
        await assert.rejects(
          new CliGitProvider().validateRepository(repository, context()),
          (error: unknown) => error === failure,
        );
        assert.equal(calls(), before);
        complete = true;
      });
      assert.equal(complete, true);
      assert.equal(result.isError, true);
      assert.equal(formatted, false);
    });
    for (const exitCode of [
      undefined,
      null,
      '0',
      '1',
      false,
      true,
      -1,
      0.5,
      NaN,
      Infinity,
      2,
      255,
    ]) {
      it(`rejects invalid ordinary exit ${String(exitCode)} before parsing and keeps SDK poison`, async () => {
        let complete = false;
        let inspected = 0;
        let callsToProducer = 0;
        const { result, formatted } = await runSdk(async () => {
          let failure: unknown;
          await assert.rejects(
            executeDiff({ includeUntracked: true }, context(), async (args) => {
              callsToProducer++;
              if (args[0] === 'ls-files')
                return { stdout: 'new.txt\n', stderr: '' };
              if (!args.includes('--no-index'))
                return { stdout: '', stderr: '' };
              // Invalid status must be rejected before touching even the payload.
              return {
                get stdout(): string {
                  inspected++;
                  throw new Error('payload inspected');
                },
                stderr: '',
                exitCode: exitCode as number,
              };
            }),
            (error: unknown) => {
              failure = error;
              return assertFormat(error);
            },
          );
          assert.equal(inspected, 0);
          assert.equal(callsToProducer, 3);
          assert.equal(calls(), '');
          await assert.rejects(
            new CliGitProvider().validateRepository(repository, context()),
            (error: unknown) => error === failure,
          );
          assert.equal(calls(), '');
          complete = true;
        });
        assert.equal(complete, true);
        assert.equal(result.isError, true);
        assert.equal(formatted, false);
      });
    }
    for (const exitCode of [0, 1]) {
      it(`accepts numeric exit ${exitCode} and consumes one combined record`, async () => {
        let combinedCalls = 0;
        const result = await executeDiff(
          { includeUntracked: true },
          context(),
          async (args, _cwd, _ctx, options) => {
            if (args[0] === 'ls-files')
              return { stdout: 'new.txt\n', stderr: '' };
            if (!args.includes('--no-index')) {
              assert.equal(options, undefined);
              return { stdout: '', stderr: '' };
            }
            combinedCalls++;
            assert.deepEqual(args, [
              'diff',
              '--no-index',
              '--numstat',
              '-z',
              '--patch',
              '--',
              '/dev/null',
              'new.txt',
            ]);
            assert.deepEqual(options, { allowNonZeroExit: true });
            return {
              stdout: '2\t0\t\0/dev/null\0new.txt\0\0opaque\0patch',
              stderr: '',
              exitCode,
            };
          },
        );
        assert.equal(combinedCalls, 1);
        assert.deepEqual(result, {
          diff: 'opaque\0patch',
          filesChanged: 1,
          insertions: 2,
          deletions: 0,
          binary: false,
        });
      });
    }
    it('throws a typed payload-free error outside an SDK scope without global poison', async () => {
      assert.equal(getGitExecutionContext(), undefined);
      assert.throws(
        () => parseUntrackedDiffOutput('malformed', 'new.txt'),
        assertFormat,
      );
      await new CliGitProvider().validateRepository(repository, context());
      assert.match(calls(), /^(call\n)+$/);
    });
  },
);
