/**
 * @fileoverview Actual provider/executor root restrictions and pre-Git denial.
 * @module tests/security/repository-command-gate.test
 */
import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { config } from '@/config/index.js';
import { CliGitProvider } from '@/services/git/providers/cli/CliGitProvider.js';
import {
  getConfiguredRepositoryPolicy,
  withRepositoryRoots,
} from '@/services/git/core/configured-repository-policy.js';
import { executeGitCommand } from '@/services/git/providers/cli/utils/git-executor.js';
import { withConfiguredGitExecutionContext } from '@/services/git/providers/cli/utils/configured-execution-policy.js';
import { gatherRepoSnapshot } from '@/mcp-server/tools/utils/repo-snapshot.js';

describe('production repository command gate', () => {
  let temporary: string;
  let first: string;
  let second: string;
  let repo: string;
  let outside: string;
  let saved: typeof config.git;
  const provider = new CliGitProvider();
  const requestContext = {
    requestId: 'boundary-fixture',
    timestamp: '2026-11-03T00:00:00Z',
    tenantId: 'fixture',
  };
  beforeEach(() => {
    saved = { ...config.git };
    temporary = realpathSync(
      mkdtempSync(join(tmpdir(), 'git-command-boundary-')),
    );
    first = join(temporary, 'first');
    second = join(temporary, 'second');
    outside = join(temporary, 'outside');
    for (const directory of [first, second, outside])
      mkdirSync(directory, { mode: 0o700 });
    repo = join(second, 'repo');
    mkdirSync(repo);
    execFileSync('/usr/bin/git', ['init', '-q', '--initial-branch=main'], {
      cwd: repo,
      env: {
        HOME: temporary,
        PATH: '/usr/bin:/bin',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: '/dev/null',
      },
    });
    config.git.executionProfile = 'trusted';
    config.git.baseDirs = [first, second];
    config.git.trustedHome = temporary;
  });
  afterEach(() => {
    Object.assign(config.git, saved);
    rmSync(temporary, { recursive: true, force: true });
  });

  it('uses actual provider with narrow roots and rejects empty grants before mkdir', async () => {
    const context = {
      workingDirectory: repo,
      requestContext,
      repositoryRoots: [second],
    };
    expect((await provider.status({}, context)).currentBranch).toBe('main');
    await expect(
      provider.status({}, { ...context, repositoryRoots: [] }),
    ).rejects.toThrow('empty roots');
    const leaf = join(second, 'denied-init');
    await expect(
      provider.init({ path: leaf }, { ...context, repositoryRoots: [] }),
    ).rejects.toThrow('empty roots');
    expect(existsSync(leaf)).toBe(false);
  });

  it('keeps ALS restrictions on every nested primary/secondary path without widening', async () => {
    await withRepositoryRoots([second], async () => {
      expect(getConfiguredRepositoryPolicy().resolve(repo).path).toBe(repo);
      expect(() => getConfiguredRepositoryPolicy().resolve('repo')).toThrow(
        'escapes',
      );
      expect(() => withRepositoryRoots([first], () => undefined)).toThrow(
        'escapes',
      );
      await expect(
        executeGitCommand(['status', '--porcelain'], repo, {
          repositoryRoots: [first, second],
        }),
      ).rejects.toThrow('escapes');
      await expect(
        provider.clone(
          { remoteUrl: repo, localPath: join(first, 'clone') },
          { workingDirectory: second, requestContext },
        ),
      ).rejects.toThrow('escapes');
      expect(existsSync(join(first, 'clone'))).toBe(false);
    });
  });

  it('rejects stale cwd before invoking any snapshot provider', async () => {
    let calls = 0;
    const trap = new Proxy(provider, {
      get(target, key, receiver) {
        if (['status', 'log', 'tag', 'remote'].includes(String(key)))
          return () => {
            calls++;
            throw new Error('provider must not run');
          };
        return Reflect.get(target, key, receiver);
      },
    });
    await expect(
      gatherRepoSnapshot({
        provider: trap,
        appContext: { ...requestContext, repositoryRoots: [first] },
        workingDirectory: repo,
      }),
    ).rejects.toThrow('escapes');
    expect(calls).toBe(0);
  });

  it('rejects local source metadata escape before clone transfers objects', async () => {
    const externalObjects = join(outside, 'objects');
    mkdirSync(externalObjects);
    symlinkSync(externalObjects, join(repo, '.git/objects/outside'));
    const destination = join(first, 'clone');
    await expect(
      provider.clone(
        { remoteUrl: repo, localPath: destination },
        { workingDirectory: first, requestContext },
      ),
    ).rejects.toThrow('symbolic');
    expect(existsSync(destination)).toBe(false);
  });

  it('does not discover an outside ancestor while creating inside a narrow root', async () => {
    writeFileSync(join(first, 'sentinel'), 'unchanged');
    const leaf = join(first, 'new');
    await provider.init(
      { path: leaf },
      { workingDirectory: first, requestContext, repositoryRoots: [first] },
    );
    expect(existsSync(join(leaf, '.git'))).toBe(true);
  });

  it('rejects effective global worktree authority before init creates any leaf', async () => {
    for (const worktree of [outside, '~/outside', '%(prefix)/outside']) {
      writeFileSync(
        join(temporary, '.gitconfig'),
        `[core]\n worktree = ${worktree}\n`,
      );
      const leaf = join(first, 'not-created');
      await expect(
        provider.init(
          { path: leaf },
          { workingDirectory: first, requestContext },
        ),
      ).rejects.toThrow(worktree === outside ? 'escapes' : 'unsupported');
      expect(existsSync(leaf)).toBe(false);
    }
  });

  it('never aliases malformed Unicode inputs to literal replacement characters', () => {
    const policy = getConfiguredRepositoryPolicy();
    const literal = join(first, '\uFFFD');
    mkdirSync(literal);
    expect(policy.resolve(literal).path).toBe(literal);
    expect(() => policy.resolve(`${first}/\uD800`)).toThrow('encoding');
    expect(() => policy.resolve(`${first}/\uDC00`)).toThrow('encoding');
  });

  it('poisons caught boundary failures and rejects symlink diff without partial output', async () => {
    writeFileSync(join(outside, 'sentinel'), 'outside-sentinel');
    symlinkSync(join(outside, 'sentinel'), join(repo, 'outside-link'));
    await expect(
      provider.diff(
        { includeUntracked: true },
        { workingDirectory: repo, requestContext },
      ),
    ).rejects.toThrow('symbolic');
    await expect(
      withConfiguredGitExecutionContext(undefined, async () => {
        await expect(
          executeGitCommand(['status'], outside),
        ).rejects.toMatchObject({ reason: 'REPOSITORY_BOUNDARY' });
        await expect(
          executeGitCommand(['--version'], repo),
        ).rejects.toMatchObject({ reason: 'REPOSITORY_BOUNDARY' });
      }),
    ).rejects.toMatchObject({ reason: 'REPOSITORY_BOUNDARY' });
  });

  it('authorizes exactly one literal wrapper and rejects arbitrary pathspec magic', async () => {
    const name = ':(literal)exact-file';
    writeFileSync(join(repo, name), 'literal fixture');
    await executeGitCommand(['add', '--', `:(literal)${name}`], repo);
    expect((await executeGitCommand(['ls-files', '-z'], repo)).stdout).toBe(
      `${name}\0`,
    );
    await expect(
      executeGitCommand(['add', '--', ':(glob)**'], repo),
    ).rejects.toMatchObject({ reason: 'REPOSITORY_BOUNDARY' });
  });

  it('intersects direct operation roots with request roots before any provider call', async () => {
    const scopedContext = { ...requestContext, repositoryRoots: [first] };
    const context = {
      workingDirectory: repo,
      requestContext: scopedContext,
      repositoryRoots: [second],
    };
    await expect(provider.status({}, context)).rejects.toThrow('escapes');
    await expect(provider.healthCheck(context)).rejects.toThrow('escapes');
    let calls = 0;
    const trap = new Proxy(provider, {
      get(target, key, receiver) {
        if (['status', 'log', 'tag', 'remote'].includes(String(key)))
          return () => {
            calls++;
            throw new Error('provider must not run');
          };
        return Reflect.get(target, key, receiver);
      },
    });
    await expect(
      gatherRepoSnapshot({
        provider: trap,
        appContext: scopedContext,
        repositoryRoots: [second],
        workingDirectory: repo,
      }),
    ).rejects.toThrow('escapes');
    expect(calls).toBe(0);
  });

  it('preserves all default diff exclusions and literal-looking sentinels without glob authority', async () => {
    const excluded = [
      'package-lock.json',
      'yarn.lock',
      'pnpm-lock.yaml',
      'bun.lock',
      'bun.lockb',
      'poetry.lock',
      'Pipfile.lock',
      'uv.lock',
      'composer.lock',
      'Gemfile.lock',
      'go.sum',
      'Cargo.lock',
      'flake.lock',
      'pubspec.lock',
      'mix.lock',
      'Podfile.lock',
      'packages.lock.json',
    ];
    for (const name of excluded)
      writeFileSync(join(repo, name), 'excluded fixture');
    writeFileSync(join(repo, 'keep'), 'visible fixture');
    const literalName = ':(exclude)go.sum';
    writeFileSync(join(repo, literalName), 'literal fixture');
    await executeGitCommand(
      [
        'add',
        '--',
        ...[...excluded, 'keep', literalName].map(
          (name) => `:(literal)${name}`,
        ),
      ],
      repo,
    );
    expect(
      (
        await executeGitCommand(
          [
            'diff',
            '--cached',
            '--name-only',
            '--',
            ...excluded.map((name) => `:(exclude)${name}`),
          ],
          repo,
        )
      ).stdout
        .split('\n')
        .filter(Boolean)
        .sort(),
    ).toEqual([literalName, 'keep']);
    expect(
      (
        await executeGitCommand(
          ['diff', '--cached', '--name-only', '--', `:(literal)${literalName}`],
          repo,
        )
      ).stdout,
    ).toBe(`${literalName}\n`);
    for (const operand of [
      ':(exclude)../outside',
      ':(exclude)*.lock',
      ':(exclude)',
      ':(exclude).',
      ':(exclude)..',
      ':(exclude)has:colon',
      ':(exclude)line\nbreak',
      ':(glob)**',
      ':(top)keep',
    ]) {
      await expect(
        executeGitCommand(['diff', '--cached', '--', operand], repo),
      ).rejects.toMatchObject({ reason: 'REPOSITORY_BOUNDARY' });
    }
    await expect(
      executeGitCommand(['add', '--', ':(exclude)go.sum'], repo),
    ).rejects.toMatchObject({ reason: 'REPOSITORY_BOUNDARY' });
    writeFileSync(join(outside, 'sentinel'), 'outside fixture');
    symlinkSync(
      join(outside, 'sentinel'),
      join(repo, ':(exclude)outside-link'),
    );
    await expect(
      executeGitCommand(
        ['diff', '--no-index', '--', '/dev/null', './:(exclude)outside-link'],
        repo,
      ),
    ).rejects.toMatchObject({ reason: 'REPOSITORY_BOUNDARY' });
    await expect(
      executeGitCommand(
        ['diff', '--no-index', '--', '/dev/null', join(outside, 'sentinel')],
        repo,
      ),
    ).rejects.toMatchObject({ reason: 'REPOSITORY_BOUNDARY' });
  }, 20000);
});
