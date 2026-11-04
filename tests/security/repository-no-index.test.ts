/**
 * @fileoverview Real fixed-filesystem diff authority and mode-confusion oracles.
 * @module tests/security/repository-no-index.test
 */
import { execFileSync } from 'node:child_process';
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { config } from '@/config/index.js';
import { JsonRpcErrorCode } from '@/types-global/errors.js';
import { executeGitCommand } from '@/services/git/providers/cli/utils/git-executor.js';
import { withConfiguredGitExecutionContext } from '@/services/git/providers/cli/utils/configured-execution-policy.js';
import { parseUntrackedDiffOutput } from '@/services/git/providers/cli/utils/untracked-diff-output.js';
import { validateGitArgs } from '@/services/git/providers/cli/utils/command-builder.js';
import { CliGitProvider } from '@/services/git/providers/cli/CliGitProvider.js';
import { parseGitDiffStat } from '@/services/git/providers/cli/utils/output-parser.js';

describe('fixed no-index filesystem authority', () => {
  let temporary: string;
  let allowed: string;
  let outside: string;
  let repository: string;
  let home: string;
  let log: string;
  let saved: typeof config.git;
  const git = (cwd: string, ...args: string[]) =>
    execFileSync('/usr/bin/git', args, {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        HOME: home,
        PATH: '/usr/bin:/bin',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: '/dev/null',
        GIT_AUTHOR_NAME: 'Filesystem fixture',
        GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
        GIT_COMMITTER_NAME: 'Filesystem fixture',
        GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
      },
    }).trim();
  const commands = (): string[][] =>
    existsSync(log)
      ? readFileSync(log, 'utf8')
          .split('\n')
          .filter(Boolean)
          .map((line) => line.split('\0').filter(Boolean))
      : [];
  const noBody = () =>
    expect(commands().filter(([name]) => name === 'diff')).toEqual([]);
  const args = (file = 'new.txt', stat = false) => [
    'diff',
    '--no-index',
    ...(stat ? ['--stat'] : []),
    '/dev/null',
    file,
  ];
  const combined = (file = 'new.txt') => [
    'diff',
    '--no-index',
    '--numstat',
    '-z',
    '--patch',
    '--',
    '/dev/null',
    file,
  ];
  const run = (
    operands = args(),
    cwd = repository,
    repositoryRoots?: readonly string[],
  ) =>
    executeGitCommand(operands, cwd, {
      allowNonZeroExit: true,
      repositoryRoots,
    });
  const denied = async (operation: Promise<unknown>) => {
    await expect(operation).rejects.toMatchObject({
      code: JsonRpcErrorCode.Forbidden,
    });
    noBody();
    expect(readFileSync(join(outside, 'sentinel'), 'utf8')).toBe(
      'outside-only-sentinel\n',
    );
  };
  beforeEach(() => {
    saved = { ...config.git };
    temporary = realpathSync(
      mkdtempSync(join(tmpdir(), 'git-no-index-authority-')),
    );
    allowed = join(temporary, 'allowed');
    outside = join(temporary, 'outside');
    home = join(temporary, 'home');
    log = join(temporary, 'calls');
    for (const directory of [allowed, outside, home])
      mkdirSync(directory, { mode: 0o700 });
    repository = join(allowed, 'repository');
    mkdirSync(repository);
    git(repository, 'init', '-q', '--initial-branch=main');
    writeFileSync(join(repository, 'tracked.txt'), 'base\n');
    git(repository, 'add', '--', 'tracked.txt');
    git(repository, '-c', 'commit.gpgsign=false', 'commit', '-qm', 'base');
    writeFileSync(join(repository, 'new.txt'), 'line one\nline two\n');
    writeFileSync(join(outside, 'sentinel'), 'outside-only-sentinel\n');
    const quote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
    const binary = join(temporary, 'git-fixture');
    writeFileSync(
      binary,
      `#!/bin/sh\nprintf '%s\\0' "$@" >> ${quote(log)}\nprintf '\\n' >> ${quote(log)}\nexec /usr/bin/git "$@"\n`,
      { mode: 0o700 },
    );
    config.git.executionProfile = 'trusted';
    config.git.binaryPath = binary;
    config.git.baseDirs = [allowed];
    config.git.trustedHome = home;
    config.git.trustedPath = '/usr/bin:/bin';
  });
  afterEach(() => {
    Object.assign(config.git, saved);
    rmSync(temporary, { recursive: true, force: true });
  });

  it.each([false, true])(
    'compares actual file contents with only fresh config and filesystem diff (stat=%s)',
    async (stat) => {
      const result = await run(args('new.txt', stat));
      expect(result.exitCode).toBe(1);
      if (stat)
        expect(result.stdout).toContain('1 file changed, 2 insertions(+)');
      else {
        expect(result.stdout).toContain('+line one\n+line two\n');
        expect(result.stdout).toContain('@@ -0,0 +1,2 @@');
      }
      expect(commands()).toEqual([
        ['config', '--null', '--list', '--includes'],
        args('new.txt', stat),
      ]);
    },
  );

  it('retains both native namespace comparisons for ordinary repository diff', async () => {
    writeFileSync(join(repository, 'tracked.txt'), 'changed\n');
    const result = await run(['diff', '--stat']);
    expect(result.stdout).toContain('1 insertion(+)');
    expect(commands().map(([name]) => name)).toEqual([
      'config',
      'rev-parse',
      'rev-parse',
      'diff',
    ]);
    expect(commands()[1]).toContain('--absolute-git-dir');
    expect(commands()[1]).toContain('--git-common-dir');
    expect(commands()[2]).toEqual(['rev-parse', '--show-toplevel']);
  });

  it('admits only the exact qualified combined tuple and preserves its contents/counts', async () => {
    validateGitArgs(combined());
    const result = await run(combined());
    expect(result.exitCode).toBe(1);
    const parsed = parseUntrackedDiffOutput(result.stdout, 'new.txt');
    expect(parsed.insertions).toBe(2);
    expect(parsed.deletions).toBe(0);
    expect(parsed.patch).toContain('+line one\n+line two\n');
    expect(commands()).toEqual([
      ['config', '--null', '--list', '--includes'],
      combined(),
    ]);
  });

  it('preserves actual provider patch/statOnly output while full mode uses one combined call per file', async () => {
    const provider = new CliGitProvider();
    const context = {
      workingDirectory: repository,
      requestContext: {
        requestId: 'producer-parity',
        timestamp: new Date().toISOString(),
      },
      repositoryRoots: [allowed],
    };
    const expectedPatch = await run(args());
    const expectedStat = await run(args('new.txt', true));
    const expectedCounts = parseGitDiffStat(expectedStat.stdout);
    writeFileSync(log, '');
    const full = await provider.diff({ includeUntracked: true }, context);
    expect(full.diff).toBe(expectedPatch.stdout);
    expect(full.filesChanged).toBe(1);
    expect(full.insertions).toBe(expectedCounts.totalAdditions);
    expect(full.deletions).toBe(expectedCounts.totalDeletions);
    expect(commands().filter((args) => args.includes('--no-index'))).toEqual([
      combined(),
    ]);
    writeFileSync(log, '');
    const statOnly = await provider.diff(
      { includeUntracked: true, stat: true },
      context,
    );
    expect(statOnly.diff).toBe(expectedStat.stdout);
    expect(statOnly.filesChanged).toBe(1);
    expect(statOnly.insertions).toBe(expectedCounts.totalAdditions);
    expect(statOnly.deletions).toBe(expectedCounts.totalDeletions);
    expect(commands().filter((args) => args.includes('--no-index'))).toEqual([
      args('new.txt', true),
    ]);
  });

  it.each([
    ['diff', '--numstat'],
    ['diff', '--patch'],
    [
      'diff',
      '--no-index',
      '-z',
      '--numstat',
      '--patch',
      '--',
      '/dev/null',
      'new.txt',
    ],
    [...combined(), 'extra'],
    [...combined().slice(0, -1), '-p'],
    [...combined().slice(0, -1), 'new.txt', '--stat'],
    [
      'diff',
      '--no-index',
      '--numstat',
      '-z',
      '--patch',
      '/dev/null',
      'new.txt',
    ],
    [
      'diff',
      '--no-index',
      '--numstat',
      '-z',
      '--patch',
      '--',
      'tracked.txt',
      'new.txt',
    ],
  ])(
    'rejects unqualified combined argv %j before native invocation',
    async (...operands) => {
      await expect(run(operands)).rejects.toThrow('Unsafe git flag rejected:');
      expect(commands()).toEqual([]);
    },
  );

  it('preserves the existing rejection of unsupported numstat without widening flags', async () => {
    await expect(
      run(['diff', '--no-index', '--numstat', '/dev/null', 'new.txt']),
    ).rejects.toThrow('Unsafe git flag rejected: --numstat');
    expect(commands()).toEqual([]);
  });

  it.each([':(literal)file', ':(exclude)file', 'HEAD:file', './-p'])(
    'keeps %s a real literal filesystem filename',
    async (name) => {
      writeFileSync(join(repository, name), `literal-${name}\n`);
      const result = await run(args(name));
      expect(result.stdout).toContain(`+literal-${name}\n`);
      expect(commands().map(([command]) => command)).toEqual([
        'config',
        'diff',
      ]);
    },
  );

  it('supports a linked worktree with authorized common metadata', async () => {
    const linked = join(allowed, 'linked');
    git(repository, 'worktree', 'add', '-q', '-b', 'linked', linked);
    writeFileSync(join(linked, 'new.txt'), 'linked-only\n');
    expect((await run(args(), linked)).stdout).toContain('+linked-only\n');
    expect(commands().map(([command]) => command)).toEqual(['config', 'diff']);
  });

  it.each(['index', 'alternates', 'common', 'include', 'legacy'] as const)(
    'rejects %s metadata escape before the body helper',
    async (kind) => {
      if (kind === 'index') {
        rmSync(join(repository, '.git/index'));
        symlinkSync(join(outside, 'sentinel'), join(repository, '.git/index'));
      } else if (kind === 'alternates') {
        writeFileSync(
          join(repository, '.git/objects/info/alternates'),
          `${outside}\n`,
        );
      } else if (kind === 'common') {
        writeFileSync(join(repository, '.git/commondir'), `${outside}\n`);
      } else if (kind === 'include') {
        appendFileSync(
          join(repository, '.git/config'),
          `[include]\npath = ${join(outside, 'sentinel')}\n`,
        );
      } else {
        mkdirSync(join(repository, '.git/remotes'), { recursive: true });
        writeFileSync(
          join(repository, '.git/remotes/legacy'),
          `URL: ${outside}\n`,
        );
      }
      await denied(run());
      expect(commands()).toEqual([]);
      await denied(run(combined()));
      expect(commands()).toEqual([]);
    },
  );

  it.each(['worktree', 'url', 'rewrite'] as const)(
    'rejects effective outside %s configuration before the body helper',
    async (kind) => {
      const value =
        kind === 'worktree'
          ? `[core]\nworktree = ${outside}\n`
          : kind === 'url'
            ? `[remote "origin"]\nurl = ${outside}\n`
            : `[url "${outside}/"]\ninsteadOf = private:\n[remote "origin"]\nurl = private:repository\n`;
      writeFileSync(join(home, '.gitconfig'), value);
      await denied(run());
      expect(commands()).toEqual([
        ['config', '--null', '--list', '--includes'],
      ]);
      writeFileSync(log, '');
      await denied(run(combined()));
      expect(commands()).toEqual([
        ['config', '--null', '--list', '--includes'],
      ]);
    },
  );

  it('rejects outside/symlink/directory operands and empty caller grants', async () => {
    symlinkSync(join(outside, 'sentinel'), join(repository, 'outside-link'));
    mkdirSync(join(repository, 'directory'));
    for (const name of [
      join(outside, 'sentinel'),
      'outside-link',
      'directory',
    ]) {
      writeFileSync(log, '');
      await denied(run(args(name)));
      writeFileSync(log, '');
      await denied(run(combined(name)));
    }
    writeFileSync(log, '');
    await denied(run(args(), repository, []));
    expect(commands()).toEqual([]);
    await denied(run(combined(), repository, []));
    expect(commands()).toEqual([]);
  });

  it('rejects bare filesystem mode rather than inventing worktree authority', async () => {
    const bare = join(allowed, 'bare.git');
    mkdirSync(bare);
    git(bare, 'init', '--bare', '-q');
    writeFileSync(join(bare, 'new.txt'), 'bare-only\n');
    await denied(run(args(), bare));
  });

  it.each([
    ['diff', '--no-index', '--cached', '/dev/null', 'new.txt'],
    ['diff', '--no-index', '--stat', '--name-only', '/dev/null', 'new.txt'],
    ['diff', '--no-index', '--', '/dev/null', 'new.txt'],
    ['diff', '--no-index', '../outside/sentinel', '/dev/null', 'new.txt'],
    ['diff', '--no-index', 'HEAD', '/dev/null', 'new.txt'],
    ['diff', '--no-index', 'tracked.txt', 'new.txt'],
    ['diff', '--no-index', '/dev/null', 'new.txt', '../outside/sentinel'],
    ['diff', '--no-index', '/dev/null', '-p'],
    ['diff', '--no-index', '/dev/null', ':(top)../outside/sentinel'],
  ])(
    'does not turn ambiguous argv %j into filesystem authority',
    async (...operands) => {
      await denied(run(operands));
    },
  );

  it.each(['repository', 'operator'] as const)(
    'revalidates %s config on each call and preserves first failure poison',
    async (source) => {
      await expect(
        withConfiguredGitExecutionContext(undefined, async () => {
          await run();
          appendFileSync(
            source === 'repository'
              ? join(repository, '.git/config')
              : join(home, '.gitconfig'),
            `[remote "origin"]\nurl = ${outside}\n`,
          );
          await expect(run()).rejects.toMatchObject({
            code: JsonRpcErrorCode.Forbidden,
          });
          const beforeLaterCall = commands();
          await expect(run()).rejects.toMatchObject({
            reason: 'REPOSITORY_BOUNDARY',
          });
          expect(commands()).toEqual(beforeLaterCall);
        }),
      ).rejects.toMatchObject({ reason: 'REPOSITORY_BOUNDARY' });
      expect(commands().map(([command]) => command)).toEqual([
        'config',
        'diff',
        'config',
      ]);
    },
  );

  it('revalidates changed common metadata on each call without cached authority', async () => {
    await expect(
      withConfiguredGitExecutionContext(undefined, async () => {
        await run();
        writeFileSync(log, '');
        writeFileSync(join(repository, '.git/commondir'), `${outside}\n`);
        await denied(run());
      }),
    ).rejects.toMatchObject({ reason: 'REPOSITORY_BOUNDARY' });
    expect(commands()).toEqual([]);
  });

  it('keeps default restricted execution before native work', async () => {
    config.git.executionProfile = 'restricted';
    await expect(run()).rejects.toMatchObject({ reason: 'POLICY_UNSUPPORTED' });
    expect(commands()).toEqual([]);
  });
});
