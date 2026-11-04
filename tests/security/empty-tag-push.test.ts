/**
 * @fileoverview Closed empty-tag push authorization and actual native effects.
 * @module tests/security/empty-tag-push.test
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { AssertionError } from 'node:assert';
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
import { config } from '../../src/config/index.js';
import { createMcpToolHandler } from '../../src/mcp-server/tools/utils/toolHandlerFactory.js';
import type { SdkContext } from '../../src/mcp-server/tools/utils/toolDefinition.js';
import { withRepositoryRoots } from '../../src/services/git/core/configured-repository-policy.js';
import { CliGitProvider } from '../../src/services/git/providers/cli/CliGitProvider.js';
import {
  authorizeEmptyTagPushDestination,
  executeGitCommand,
} from '../../src/services/git/providers/cli/utils/git-executor.js';
import { buildTrustedGitEnvironment } from '../../src/services/git/providers/cli/utils/execution-policy.js';
import { GitExecutionError } from '../../src/services/git/providers/cli/utils/execution-errors.js';
import {
  getGitExecutionFailure,
  recordGitExecutionFailure,
} from '../../src/services/git/providers/cli/utils/execution-context.js';
import { McpError } from '../../src/types-global/errors.js';

describe('closed explicit empty-tag push', { timeout: 30000 }, () => {
  let root: string,
    repository: string,
    destination: string,
    home: string,
    log: string,
    hook: string;
  let saved: typeof config.git, env: Record<string, string>;
  const git = (...args: string[]) =>
    execFileSync('/usr/bin/git', args, {
      cwd: repository,
      env,
      encoding: 'utf8',
    });
  const calls = () => readFileSync(log, 'utf8');
  const context = () => ({
    workingDirectory: repository,
    repositoryRoots: [repository, destination],
    requestContext: {
      requestId: 'empty-tags',
      timestamp: new Date().toISOString(),
    },
  });
  const reason = (expected: string) => (error: unknown) => {
    assert.ok(error instanceof GitExecutionError);
    assert.equal(error.reason, expected);
    return true;
  };
  const sdk = async (operation: () => Promise<void>) => {
    let formatted = false;
    const handler = createMcpToolHandler({
      toolName: 'empty_tag_fixture',
      inputSchema: z.object({}),
      logic: async () => {
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
      requestId: 'empty-tags',
    } as unknown as SdkContext);
    return { result, formatted };
  };
  const terminal = async (
    operation: () => Promise<unknown>,
    expected: string,
  ) => {
    let complete = false;
    const knownReasons = new Set([
      'POLICY_UNSUPPORTED',
      'INVALID_EXECUTION_OPTIONS',
      'OUTPUT_LIMIT',
      'CANCELLED',
      'DEADLINE',
      'SIGNAL_EXIT',
      'CLEANUP_FAILED',
      'SPAWN_FAILED',
      'INVALID_OUTPUT_ENCODING',
      'INVALID_OUTPUT_FORMAT',
      'REPOSITORY_BOUNDARY',
    ]);
    const errorClass = (error: unknown) =>
      error instanceof GitExecutionError
        ? 'GitExecutionError'
        : error instanceof McpError
          ? 'McpError'
          : error instanceof AssertionError
            ? 'AssertionError'
            : error instanceof Error
              ? 'Error'
              : 'other';
    const diagnostic = {
      diagnostic: 'empty-tag-terminal',
      expected: knownReasons.has(expected) ? expected : 'other',
      bodyEntered: false,
      stage: 'before-sdk',
      firstClass: 'none',
      firstReason: 'none',
      firstCode: null as number | null,
      recordedPresent: false,
      recordedSameIdentity: false,
      innerClass: 'none',
      innerCode: 'none',
      callsAtEntry: 0,
      callsAtFirstRejection: 0,
      callsBeforeLaterGit: 0,
    };
    const callCount = () => calls().split('\n').filter(Boolean).length;
    const { result, formatted } = await sdk(async () => {
      diagnostic.bodyEntered = true;
      diagnostic.stage = 'reject-operation';
      diagnostic.callsAtEntry = callCount();
      try {
        let first: unknown;
        await assert.rejects(operation, (error: unknown) => {
          first = error;
          diagnostic.stage = 'first-rejection-predicate';
          diagnostic.firstClass = errorClass(error);
          const typedReason =
            error instanceof GitExecutionError
              ? error.reason
              : error instanceof McpError
                ? error.data?.reason
                : undefined;
          diagnostic.firstReason =
            typeof typedReason === 'string' && knownReasons.has(typedReason)
              ? typedReason
              : 'other';
          diagnostic.firstCode =
            error instanceof McpError && Number.isFinite(error.code)
              ? error.code
              : null;
          const recorded = getGitExecutionFailure();
          diagnostic.recordedPresent = recorded !== undefined;
          diagnostic.recordedSameIdentity =
            recorded !== undefined && recorded === first;
          diagnostic.callsAtFirstRejection = callCount();
          return reason(expected)(error);
        });
        const before = calls();
        diagnostic.stage = 'later-git-identity';
        diagnostic.callsBeforeLaterGit = callCount();
        await assert.rejects(
          executeGitCommand(['--version'], repository),
          (error: unknown) => error === first,
        );
        diagnostic.stage = 'unchanged-native-count';
        assert.equal(calls(), before);
        complete = true;
        diagnostic.stage = 'body-complete';
      } catch (error) {
        diagnostic.innerClass = errorClass(error);
        diagnostic.innerCode =
          error instanceof AssertionError ? 'ERR_ASSERTION' : 'other';
        throw error;
      }
    });
    if (!complete)
      console.info(
        JSON.stringify({
          ...diagnostic,
          sdkIsError: result.isError === true,
          formatted,
          callsAfterSdk: callCount(),
          pushCallsAfterSdk: calls()
            .split('\n')
            .filter((command) => command === 'push').length,
        }),
      );
    assert.equal(complete, true);
    assert.equal(result.isError, true);
    assert.equal(formatted, false);
    assert.ok(!calls().split('\n').includes('push'));
  };
  beforeEach(() => {
    saved = { ...config.git };
    root = realpathSync(mkdtempSync(join(tmpdir(), 'git-empty-tags-')));
    repository = join(root, 'repository');
    destination = join(root, 'remote.git');
    home = join(root, 'home');
    log = join(root, 'calls');
    hook = join(root, 'push-hook');
    mkdirSync(repository);
    mkdirSync(home);
    writeFileSync(log, '');
    writeFileSync(
      join(home, '.gitconfig'),
      '[user]\n name = Push Fixture\n email = fixture@example.invalid\n[commit]\n gpgsign = false\n',
    );
    env = buildTrustedGitEnvironment(
      {
        profile: 'trusted',
        binaryPath: '/usr/bin/git',
        homeDirectory: home,
        helperPath: '/usr/bin:/bin',
      },
      {},
    );
    git('init', '-q', '--initial-branch=feature');
    git('commit', '--allow-empty', '-m', 'ordinary');
    git('init', '-q', '--bare', destination);
    git('config', 'remote.origin.url', destination);
    const quote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
    const binary = join(root, 'git-observer');
    writeFileSync(
      binary,
      '#!/bin/sh\nprintf "%s\\n" "$1" >> ' +
        quote(log) +
        '\nexec /usr/bin/git "$@"\n',
      { mode: 0o700 },
    );
    writeFileSync(
      join(repository, '.git/hooks/pre-push'),
      '#!/bin/sh\nprintf hook >> ' + quote(hook) + '\n',
      { mode: 0o700 },
    );
    Object.assign(config.git, {
      executionProfile: 'trusted',
      binaryPath: binary,
      trustedHome: home,
      trustedPath: '/usr/bin:/bin',
      baseDirs: [repository, destination],
      signCommits: false,
      maxCommandTimeoutMs: 30000,
      maxOutputBytes: 4 * 1024 * 1024,
      maxStdoutBytes: 4 * 1024 * 1024,
      maxStderrBytes: 4 * 1024 * 1024,
    });
  });
  afterEach(() => {
    Object.assign(config.git, saved);
    rmSync(root, { recursive: true, force: true });
  });

  it('keeps an empty explicit tag selection inert under configured branch push defaults', async () => {
    git('config', 'push.default', 'matching');
    git('config', 'remote.origin.push', '+refs/heads/feature:refs/heads/main');
    const before = {
      config: git('config', '--local', '--list'),
      refs: git('--git-dir', destination, 'for-each-ref'),
      objects: git('--git-dir', destination, 'count-objects', '-v'),
    };
    for (const dryRun of [false, true]) {
      const result = await new CliGitProvider().push(
        { remote: 'origin', tags: true, dryRun, setUpstream: true },
        context(),
      );
      assert.deepEqual(result, {
        success: true,
        remote: 'origin',
        branch: '',
        upstreamSet: false,
        pushedRefs: [],
        rejectedRefs: [],
      });
    }
    assert.deepEqual(
      {
        config: git('config', '--local', '--list'),
        refs: git('--git-dir', destination, 'for-each-ref'),
        objects: git('--git-dir', destination, 'count-objects', '-v'),
      },
      before,
    );
    assert.ok(calls().includes('for-each-ref\n'));
    assert.ok(!calls().split('\n').includes('push'));
    assert.equal(existsSync(hook), false);
  });

  it('rejects blank and option-like closed-helper endpoints before native queries', async () => {
    for (const remote of ['', '--all', '-x', 'host\nname'])
      await assert.rejects(
        authorizeEmptyTagPushDestination(remote, repository, {
          repositoryRoots: context().repositoryRoots,
        }),
      );
    assert.equal(calls(), '');
  });

  it('rejects restricted before filesystem discovery or native execution', async () => {
    config.git.executionProfile = 'restricted';
    const missing = join(root, 'never-created');
    await assert.rejects(
      authorizeEmptyTagPushDestination('origin', missing),
      reason('POLICY_UNSUPPORTED'),
    );
    await assert.rejects(
      new CliGitProvider().push(
        { tags: true },
        { ...context(), workingDirectory: missing },
      ),
      reason('POLICY_UNSUPPORTED'),
    );
    assert.equal(existsSync(missing), false);
    assert.equal(calls(), '');
  });

  it('keeps an empty server root capability terminal even when the tag set is empty', async () => {
    await terminal(
      () =>
        new CliGitProvider().push(
          { tags: true },
          { ...context(), repositoryRoots: [] },
        ),
      'REPOSITORY_BOUNDARY',
    );
    assert.equal(calls(), '');
  });

  it('intersects ambient roots instead of widening them for the closed callback', async () => {
    await terminal(
      () =>
        withRepositoryRoots([repository], () =>
          new CliGitProvider().push({ tags: true }, context()),
        ),
      'REPOSITORY_BOUNDARY',
    );
  });

  it('keeps ordinary provider root denial terminal without poisoning a fresh request', async () => {
    await terminal(
      () =>
        new CliGitProvider().status({}, { ...context(), repositoryRoots: [] }),
      'REPOSITORY_BOUNDARY',
    );
    assert.equal(calls(), '');
    assert.equal(getGitExecutionFailure(), undefined);
    const fresh = await new CliGitProvider().status({}, context());
    assert.equal(fresh.isClean, true);
    assert.ok(calls().length > 0);
    assert.equal(getGitExecutionFailure(), undefined);
  });

  it('preserves an earlier recorded failure identity when root narrowing also rejects', async () => {
    const earlier = new GitExecutionError(
      'OUTPUT_LIMIT',
      'Earlier fixture output limit.',
    );
    await terminal(async () => {
      recordGitExecutionFailure(earlier);
      try {
        return await new CliGitProvider().status(
          {},
          { ...context(), repositoryRoots: [] },
        );
      } catch (error) {
        assert.equal(error, earlier);
        throw error;
      }
    }, 'OUTPUT_LIMIT');
    assert.equal(calls(), '');
  });

  it('does not relabel or poison an entered operation confirmation error', async () => {
    let complete = false;
    const { result, formatted } = await sdk(async () => {
      await assert.rejects(
        new CliGitProvider().push(
          { force: true, branch: 'feature' },
          context(),
        ),
        (error: unknown) => {
          assert.ok(error instanceof McpError);
          assert.ok(!(error instanceof GitExecutionError));
          return true;
        },
      );
      assert.equal(getGitExecutionFailure(), undefined);
      assert.match(
        (await executeGitCommand(['--version'], repository)).stdout,
        /^git version /,
      );
      complete = true;
    });
    assert.equal(complete, true);
    assert.notEqual(result.isError, true);
    assert.equal(formatted, true);
    assert.ok(!calls().split('\n').includes('push'));
  });

  it('validates a literal outside endpoint in the full closed push gate', async () => {
    const outside = join(root, 'outside.git');
    git('init', '-q', '--bare', outside);
    const before = git('--git-dir', outside, 'for-each-ref');
    await terminal(
      () =>
        new CliGitProvider().push({ remote: outside, tags: true }, context()),
      'REPOSITORY_BOUNDARY',
    );
    assert.equal(git('--git-dir', outside, 'for-each-ref'), before);
    assert.equal(existsSync(hook), false);
  });

  it('retains effective push URL rewrites before returning an empty result', async () => {
    const outside = join(root, 'outside.git');
    git('init', '-q', '--bare', outside);
    git('config', 'url.' + outside + '.pushInsteadOf', destination);
    await terminal(
      () => new CliGitProvider().push({ tags: true }, context()),
      'REPOSITORY_BOUNDARY',
    );
    assert.equal(git('--git-dir', outside, 'for-each-ref'), '');
    assert.equal(existsSync(hook), false);
  });

  it('retains an independent provider abort inside an actual SDK request', async () => {
    const controller = new AbortController();
    controller.abort();
    await terminal(
      () =>
        new CliGitProvider().push(
          { tags: true },
          { ...context(), signal: controller.signal },
        ),
      'CANCELLED',
    );
    assert.equal(calls(), '');
  });

  it('retains the shorter provider deadline inside an actual SDK request', async () => {
    await terminal(
      () =>
        new CliGitProvider().push(
          { tags: true },
          { ...context(), deadline: Date.now() - 1 },
        ),
      'DEADLINE',
    );
    assert.equal(calls(), '');
  });

  it('keeps direct closed-helper abort and deadline controls within the SDK scope', async () => {
    const controller = new AbortController();
    controller.abort();
    await terminal(
      () =>
        authorizeEmptyTagPushDestination('origin', repository, {
          signal: controller.signal,
          repositoryRoots: context().repositoryRoots,
        }),
      'CANCELLED',
    );
    await terminal(
      () =>
        authorizeEmptyTagPushDestination('origin', repository, {
          deadline: Date.now() - 1,
          repositoryRoots: context().repositoryRoots,
        }),
      'DEADLINE',
    );
    assert.equal(calls(), '');
  });

  it('shares the request raw budget and keeps caught overflow terminal before no-op completion', async () => {
    config.git.maxOutputBytes = Buffer.byteLength(git('--version'), 'utf8') + 1;
    await terminal(async () => {
      const first = await executeGitCommand(['--version'], repository);
      assert.match(first.stdout, /^git version /);
      return new CliGitProvider().push({ tags: true }, context());
    }, 'OUTPUT_LIMIT');
  });

  it('retains nonempty explicit tag and ordinary branch pushes with actual ref receipts', async () => {
    const oid = git('rev-parse', 'HEAD').trim();
    git('tag', 'v1');
    const provider = new CliGitProvider();
    await provider.push({ tags: true }, context());
    assert.equal(
      git('--git-dir', destination, 'rev-parse', 'refs/tags/v1').trim(),
      oid,
    );
    await provider.push({ branch: 'feature' }, context());
    assert.equal(
      git('--git-dir', destination, 'rev-parse', 'refs/heads/feature').trim(),
      oid,
    );
    assert.ok(calls().split('\n').includes('push'));
    assert.equal(existsSync(hook), true);
  });
});
