/**
 * @fileoverview Real transfer regressions for implicit submodule and legacy URLs.
 * @module tests/security/repository-transfer-boundaries.test
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
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
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { config } from '@/config/index.js';
import { JsonRpcErrorCode } from '@/types-global/errors.js';
import { CliGitProvider } from '@/services/git/providers/cli/CliGitProvider.js';
import { executeGitCommand } from '@/services/git/providers/cli/utils/git-executor.js';
import { withConfiguredGitExecutionContext } from '@/services/git/providers/cli/utils/configured-execution-policy.js';

describe('implicit native transfer boundaries', () => {
  let temporary: string;
  let allowed: string;
  let outside: string;
  let saved: typeof config.git;
  const provider = new CliGitProvider();
  const requestContext = {
    requestId: 'implicit-transfer-boundary',
    timestamp: '2026-11-03T00:00:00Z',
    tenantId: 'fixture',
  };
  const context = (workingDirectory: string) => ({
    workingDirectory,
    requestContext,
  });
  const environment = () => ({
    HOME: temporary,
    PATH: '/usr/bin:/bin',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_AUTHOR_NAME: 'Boundary fixture',
    GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
    GIT_COMMITTER_NAME: 'Boundary fixture',
    GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
  });
  const git = (cwd: string, ...args: string[]) =>
    execFileSync('/usr/bin/git', args, {
      cwd,
      env: environment(),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
  const hasObject = (cwd: string, oid: string): boolean => {
    const answer = execFileSync('/usr/bin/git', ['cat-file', '--batch-check'], {
      cwd,
      env: environment(),
      input: `${oid}\n`,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    if (answer === `${oid} missing\n`) return false;
    expect(answer).toMatch(new RegExp(`^${oid} commit [0-9]+\\n$`));
    return true;
  };
  const text = (filename: string) =>
    existsSync(filename) ? readFileSync(filename, 'utf8') : null;
  const init = (directory: string) => {
    mkdirSync(directory, { recursive: true });
    git(directory, 'init', '-q', '--initial-branch=main');
    return directory;
  };
  const commit = (directory: string, value: string) => {
    writeFileSync(join(directory, 'sentinel.txt'), value);
    git(directory, 'add', '--', 'sentinel.txt');
    git(directory, '-c', 'commit.gpgsign=false', 'commit', '-qm', value);
    return git(directory, 'rev-parse', 'HEAD');
  };
  const clone = (source: string, destination: string, bare = false) => {
    git(
      temporary,
      'clone',
      '-q',
      '--no-local',
      ...(bare ? ['--bare'] : []),
      '--',
      source,
      destination,
    );
    return destination;
  };
  const snapshot = (directory: string): Record<string, string> => {
    const files: Record<string, string> = {};
    const walk = (current: string, prefix: string) => {
      for (const entry of readdirSync(current, { withFileTypes: true })) {
        const relative = `${prefix}${entry.name}`;
        if (entry.isDirectory())
          walk(join(current, entry.name), `${relative}/`);
        else
          files[relative] = createHash('sha256')
            .update(readFileSync(join(current, entry.name)))
            .digest('hex');
      }
    };
    walk(directory, '');
    return files;
  };
  beforeEach(() => {
    saved = { ...config.git };
    temporary = realpathSync(
      mkdtempSync(join(tmpdir(), 'git-implicit-transfer-')),
    );
    allowed = join(temporary, 'allowed');
    outside = join(temporary, 'outside');
    mkdirSync(allowed, { mode: 0o700 });
    mkdirSync(outside, { mode: 0o700 });
    config.git.executionProfile = 'trusted';
    config.git.baseDirs = [allowed];
    config.git.trustedHome = temporary;
  });
  afterEach(() => {
    Object.assign(config.git, saved);
    rmSync(temporary, { recursive: true, force: true });
  });

  const fetchFixture = () => {
    const subSource = init(join(allowed, 'sub-source'));
    commit(subSource, 'submodule-base');
    const superSource = init(join(allowed, 'super-source'));
    commit(superSource, 'super-base');
    git(
      superSource,
      '-c',
      'protocol.file.allow=always',
      'submodule',
      'add',
      '-q',
      '--',
      subSource,
      'nested',
    );
    git(
      superSource,
      '-c',
      'commit.gpgsign=false',
      'commit',
      '-qam',
      'add-submodule',
    );
    const foreign = clone(subSource, join(outside, 'sub-source'));
    const guarded = clone(superSource, join(allowed, 'guarded'));
    git(
      guarded,
      '-c',
      'protocol.file.allow=always',
      'submodule',
      'update',
      '--init',
      '-q',
    );
    const nested = join(guarded, 'nested');
    git(nested, 'remote', 'set-url', 'origin', foreign);
    git(guarded, 'config', 'fetch.recurseSubmodules', 'true');
    git(guarded, 'config', 'submodule.recurse', 'true');
    git(guarded, 'config', 'submodule.nested.fetchRecurseSubmodules', 'true');
    const secret = commit(foreign, 'outside-only-fetch-object');
    const permitted = commit(superSource, 'allowed-superproject-update');
    expect(hasObject(nested, secret)).toBe(false);
    return { guarded, nested, foreign, secret, permitted };
  };

  it('proves the native fetch fixture really imports the forbidden nested object', () => {
    const fixture = fetchFixture();
    git(fixture.guarded, 'fetch', 'origin');
    expect(hasObject(fixture.nested, fixture.secret)).toBe(true);
    expect(
      text(join(fixture.guarded, '.git/modules/nested/FETCH_HEAD')),
    ).toContain(fixture.secret);
  });

  it('keeps ordinary clone nonrecursive and rejects explicit recursive clone before mkdir', async () => {
    const fixture = fetchFixture();
    const before = snapshot(fixture.foreign);
    const destination = join(allowed, 'ordinary-clone');
    await provider.clone(
      { remoteUrl: fixture.guarded, localPath: destination },
      context(allowed),
    );
    expect(git(destination, 'rev-parse', 'HEAD')).toBe(
      git(fixture.guarded, 'rev-parse', 'HEAD'),
    );
    expect(existsSync(join(destination, 'nested/.git'))).toBe(false);
    expect(existsSync(join(destination, '.git/modules'))).toBe(false);
    expect(hasObject(destination, fixture.secret)).toBe(false);
    for (const flag of [
      '--recurse-submodules',
      '--recurse-submodules=nested',
    ]) {
      const denied = join(
        allowed,
        flag === '--recurse-submodules' ? 'recursive-clone' : 'pathspec-clone',
      );
      await expect(
        executeGitCommand(
          ['clone', flag, '--end-of-options', fixture.guarded, denied],
          allowed,
        ),
      ).rejects.toMatchObject({ code: JsonRpcErrorCode.Forbidden });
      expect(existsSync(denied)).toBe(false);
    }
    expect(snapshot(fixture.foreign)).toEqual(before);
  });

  it.each(['fetch', 'pull', 'fetch-explicit', 'fetch-global'] as const)(
    'disables configured nested %s while retaining superproject transfer',
    async (operation) => {
      const fixture = fetchFixture();
      const nestedFetchHead = text(
        join(fixture.guarded, '.git/modules/nested/FETCH_HEAD'),
      );
      const outsideBefore = snapshot(fixture.foreign);
      if (operation === 'fetch-global') {
        for (const key of [
          'fetch.recurseSubmodules',
          'submodule.recurse',
          'submodule.nested.fetchRecurseSubmodules',
        ])
          git(fixture.guarded, 'config', '--unset', key);
        writeFileSync(
          join(temporary, '.gitconfig'),
          '[fetch]\n\trecurseSubmodules = true\n[submodule]\n\trecurse = true\n',
        );
      }
      if (operation === 'fetch')
        await provider.fetch({ remote: 'origin' }, context(fixture.guarded));
      else if (operation === 'fetch-explicit')
        await executeGitCommand(
          ['fetch', 'origin', '--recurse-submodules=yes'],
          fixture.guarded,
        );
      else if (operation === 'fetch-global')
        await provider.fetch({ remote: 'origin' }, context(fixture.guarded));
      else
        await provider.pull(
          { remote: 'origin', branch: 'main', fastForwardOnly: true },
          context(fixture.guarded),
        );
      expect(hasObject(fixture.guarded, fixture.permitted)).toBe(true);
      expect(text(join(fixture.guarded, '.git/FETCH_HEAD'))).toContain(
        fixture.permitted,
      );
      expect(hasObject(fixture.nested, fixture.secret)).toBe(false);
      expect(hasObject(fixture.guarded, fixture.secret)).toBe(false);
      expect(
        text(join(fixture.guarded, '.git/modules/nested/FETCH_HEAD')),
      ).toBe(nestedFetchHead);
      expect(snapshot(fixture.foreign)).toEqual(outsideBefore);
    },
  );

  it.each(['configured', 'explicit'] as const)(
    'disables %s nested push without blocking the allowed superproject push',
    async (mode) => {
      const subSource = init(join(allowed, 'sub-source'));
      const base = commit(subSource, 'submodule-base');
      const superproject = init(join(allowed, 'superproject'));
      commit(superproject, 'super-base');
      git(
        superproject,
        '-c',
        'protocol.file.allow=always',
        'submodule',
        'add',
        '-q',
        '--',
        subSource,
        'nested',
      );
      git(
        superproject,
        '-c',
        'commit.gpgsign=false',
        'commit',
        '-qam',
        'add-submodule',
      );
      const initialSuper = git(superproject, 'rev-parse', 'HEAD');
      const target = clone(superproject, join(allowed, 'target.git'), true);
      const controlTarget = clone(
        superproject,
        join(allowed, 'control-target.git'),
        true,
      );
      const foreign = clone(subSource, join(outside, 'target.git'), true);
      const controlForeign = clone(
        subSource,
        join(outside, 'control-target.git'),
        true,
      );
      const nested = join(superproject, 'nested');
      const secret = commit(nested, 'inside-only-push-object');
      git(superproject, 'add', '--', 'nested');
      git(
        superproject,
        '-c',
        'commit.gpgsign=false',
        'commit',
        '-qm',
        'new-gitlink',
      );
      const permitted = git(superproject, 'rev-parse', 'HEAD');
      git(superproject, 'config', 'push.recurseSubmodules', 'on-demand');
      git(superproject, 'config', 'submodule.recurse', 'true');
      git(superproject, 'remote', 'add', 'origin', controlTarget);
      git(nested, 'remote', 'set-url', 'origin', controlForeign);
      // A separate outside target proves the native setup actually recurses.
      git(superproject, 'push', 'origin', 'main');
      expect(git(controlForeign, 'rev-parse', 'refs/heads/main')).toBe(secret);
      expect(hasObject(controlForeign, secret)).toBe(true);
      git(superproject, 'remote', 'set-url', 'origin', target);
      git(nested, 'remote', 'set-url', 'origin', foreign);
      git(nested, 'update-ref', 'refs/remotes/origin/main', base);
      git(superproject, 'update-ref', 'refs/remotes/origin/main', initialSuper);
      expect(hasObject(foreign, secret)).toBe(false);
      const before = snapshot(foreign);
      if (mode === 'configured')
        await provider.push(
          { remote: 'origin', branch: 'main' },
          context(superproject),
        );
      else
        await executeGitCommand(
          ['push', 'origin', 'main', '--recurse-submodules=only'],
          superproject,
        );
      expect(git(target, 'rev-parse', 'refs/heads/main')).toBe(permitted);
      expect(git(foreign, 'rev-parse', 'refs/heads/main')).toBe(base);
      expect(hasObject(foreign, secret)).toBe(false);
      expect(snapshot(foreign)).toEqual(before);
    },
  );

  const legacyFixture = (
    kind: 'remotes' | 'branches',
    mode: 'ordinary' | 'bare' | 'linked' = 'ordinary',
  ) => {
    const seed = init(join(allowed, 'seed'));
    commit(seed, 'shared-base');
    const repo = clone(seed, join(allowed, 'repository'), mode === 'bare');
    const foreign = clone(seed, join(outside, 'repository'));
    const secret = commit(foreign, 'outside-only-legacy-object');
    // A separate branch supplies an inside-only object for mutation detection.
    const insideOnly = commit(seed, 'inside-only-legacy-object');
    git(repo, 'fetch', '-q', 'origin', 'main:refs/heads/inside-only');
    let workingDirectory = repo;
    if (mode === 'linked') {
      workingDirectory = join(allowed, 'linked');
      git(repo, 'worktree', 'add', '-q', '-b', 'linked', workingDirectory);
    }
    const common = git(
      workingDirectory,
      'rev-parse',
      '--path-format=absolute',
      '--git-common-dir',
    );
    const filename = join(common, kind, 'legacy');
    mkdirSync(dirname(filename), { recursive: true });
    writeFileSync(
      filename,
      kind === 'remotes'
        ? `URL: ${foreign}\nPull: refs/heads/main:refs/remotes/legacy/main\nPush: refs/heads/inside-only:refs/heads/legacy-write\n`
        : `${foreign}#main\n`,
    );
    expect(existsSync(join(workingDirectory, 'legacy'))).toBe(false);
    expect(hasObject(workingDirectory, secret)).toBe(false);
    expect(hasObject(foreign, insideOnly)).toBe(false);
    return { workingDirectory, common, foreign, secret, insideOnly };
  };

  it.each(['remotes', 'branches'] as const)(
    'proves native legacy %s fetch/push fixture endpoints are active',
    (kind) => {
      const fixture = legacyFixture(kind);
      git(fixture.workingDirectory, 'fetch', 'legacy');
      expect(hasObject(fixture.workingDirectory, fixture.secret)).toBe(true);
      git(
        fixture.workingDirectory,
        'push',
        'legacy',
        'refs/heads/inside-only:refs/heads/legacy-write',
      );
      expect(git(fixture.foreign, 'rev-parse', 'refs/heads/legacy-write')).toBe(
        fixture.insideOnly,
      );
      expect(hasObject(fixture.foreign, fixture.insideOnly)).toBe(true);
    },
  );

  for (const mode of ['ordinary', 'bare', 'linked'] as const) {
    for (const kind of ['remotes', 'branches'] as const) {
      it.each(['fetch', 'push', 'pull'] as const)(
        `rejects ${mode} legacy ${kind} %s before any transfer`,
        async (operation) => {
          const fixture = legacyFixture(kind, mode);
          const outsideBefore = snapshot(fixture.foreign);
          const fetchHead = text(join(fixture.common, 'FETCH_HEAD'));
          const insideBefore = git(fixture.workingDirectory, 'show-ref');
          const action =
            operation === 'fetch'
              ? provider.fetch(
                  { remote: 'legacy' },
                  context(fixture.workingDirectory),
                )
              : operation === 'push'
                ? provider.push(
                    {
                      remote: 'legacy',
                      branch: 'inside-only',
                      remoteBranch: 'legacy-write',
                    },
                    context(fixture.workingDirectory),
                  )
                : provider.pull(
                    { remote: 'legacy', branch: 'main', fastForwardOnly: true },
                    context(fixture.workingDirectory),
                  );
          await expect(action).rejects.toMatchObject({
            code: JsonRpcErrorCode.Forbidden,
          });
          expect(hasObject(fixture.workingDirectory, fixture.secret)).toBe(
            false,
          );
          expect(git(fixture.workingDirectory, 'show-ref')).toBe(insideBefore);
          expect(text(join(fixture.common, 'FETCH_HEAD'))).toBe(fetchHead);
          expect(hasObject(fixture.foreign, fixture.insideOnly)).toBe(false);
          expect(snapshot(fixture.foreign)).toEqual(outsideBefore);
        },
      );
    }
  }

  it('poisons a caught legacy metadata denial before a subsequent transfer', async () => {
    const fixture = legacyFixture('remotes');
    const before = snapshot(fixture.foreign);
    await expect(
      withConfiguredGitExecutionContext(undefined, async () => {
        await executeGitCommand(
          ['fetch', 'legacy'],
          fixture.workingDirectory,
        ).catch(() => undefined);
        return executeGitCommand(['fetch', 'origin'], fixture.workingDirectory);
      }),
    ).rejects.toMatchObject({ reason: 'REPOSITORY_BOUNDARY' });
    expect(hasObject(fixture.workingDirectory, fixture.secret)).toBe(false);
    expect(snapshot(fixture.foreign)).toEqual(before);
  });

  it('preserves empty legacy scaffolding and ordinary configured transfers', async () => {
    const source = init(join(allowed, 'source'));
    commit(source, 'allowed-base');
    const repo = clone(source, join(allowed, 'repository'));
    for (const kind of ['remotes', 'branches'])
      mkdirSync(join(repo, '.git', kind), { recursive: true });
    const next = commit(source, 'allowed-update');
    await provider.fetch({ remote: 'origin' }, context(repo));
    expect(hasObject(repo, next)).toBe(true);
    await provider.pull(
      { remote: 'origin', branch: 'main', fastForwardOnly: true },
      context(repo),
    );
    expect(git(repo, 'rev-parse', 'HEAD')).toBe(next);
    const target = clone(repo, join(allowed, 'target.git'), true);
    git(repo, 'remote', 'set-url', 'origin', target);
    const pushed = commit(repo, 'allowed-push');
    await provider.push({ remote: 'origin', branch: 'main' }, context(repo));
    expect(git(target, 'rev-parse', 'refs/heads/main')).toBe(pushed);
  });
});
