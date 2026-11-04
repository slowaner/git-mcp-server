/**
 * @fileoverview Real Git metadata fixtures for repository capability discovery.
 * @module tests/security/repository-discovery.test
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { RepositoryPathPolicy } from '@/services/git/core/repository-capability.js';
import {
  discoverRepository,
  metadataConfig,
} from '@/services/git/core/repository-discovery.js';
import {
  authorizeRepositoryRemotes,
  rewriteRemoteUrl,
} from '@/services/git/core/repository-remotes.js';

describe('authorized Git metadata discovery', () => {
  let dir: string;
  let root1: string;
  let root2: string;
  let outside: string;
  let repo: string;
  let policy: RepositoryPathPolicy;
  const git = (cwd: string, ...args: string[]): void => {
    execFileSync('git', args, {
      cwd,
      env: {
        PATH: process.env.PATH!,
        HOME: dir,
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: '/dev/null',
        GIT_AUTHOR_NAME: 'Fixture',
        GIT_AUTHOR_EMAIL: 'fixture@example.test',
        GIT_COMMITTER_NAME: 'Fixture',
        GIT_COMMITTER_EMAIL: 'fixture@example.test',
      },
      stdio: 'pipe',
    });
  };
  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'git-metadata-boundary-'));
    root1 = path.join(dir, 'root1');
    root2 = path.join(dir, 'root2');
    outside = path.join(dir, 'outside');
    for (const root of [root1, root2, outside]) mkdirSync(root);
    repo = path.join(root1, 'repo');
    mkdirSync(repo);
    git(repo, 'init', '--initial-branch=main');
    git(
      repo,
      '-c',
      'commit.gpgsign=false',
      'commit',
      '--allow-empty',
      '-m',
      'fixture',
    );
    writeFileSync(path.join(outside, 'sentinel'), 'unchanged');
    policy = new RepositoryPathPolicy([root1, root2]);
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('preserves normal, bare and cross-root linked repositories', () => {
    expect(discoverRepository(policy, repo).worktree).toBe(
      policy.resolve(repo).path,
    );
    const bare = path.join(root2, 'bare');
    git(root2, 'init', '--bare', bare);
    expect(discoverRepository(policy, bare).worktree).toBeUndefined();
    const linked = path.join(root2, 'linked');
    git(repo, 'worktree', 'add', '--detach', linked);
    const result = discoverRepository(policy, linked);
    expect(result.commonDirectory).toBe(
      path.join(policy.resolve(repo).path, '.git'),
    );
    expect(result.worktree).toBe(policy.resolve(linked).path);
  });

  it('stops ancestor discovery at an allowed subdirectory', () => {
    const sub = path.join(repo, 'sub');
    mkdirSync(sub);
    expect(() =>
      discoverRepository(new RepositoryPathPolicy([sub]), sub),
    ).toThrow('root boundary');
    expect(readFileSync(path.join(outside, 'sentinel'), 'utf8')).toBe(
      'unchanged',
    );
  });

  it('rejects outside gitdir, commondir, worktree, index and alternates', () => {
    const marker = path.join(root2, 'pointer');
    mkdirSync(marker);
    writeFileSync(path.join(marker, '.git'), `gitdir: ${outside}\n`);
    expect(() => discoverRepository(policy, marker)).toThrow();
    const admin = path.join(repo, '.git');
    writeFileSync(path.join(admin, 'commondir'), `${outside}\n`);
    expect(() => discoverRepository(policy, repo)).toThrow();
    rmSync(path.join(admin, 'commondir'));
    git(repo, 'config', 'core.worktree', outside);
    expect(() => discoverRepository(policy, repo)).toThrow();
    git(repo, 'config', '--unset', 'core.worktree');
    rmSync(path.join(admin, 'index'));
    symlinkSync(path.join(outside, 'sentinel'), path.join(admin, 'index'));
    expect(() => discoverRepository(policy, repo)).toThrow();
    rmSync(path.join(admin, 'index'));
    writeFileSync(path.join(admin, 'objects/info/alternates'), `${outside}\n`);
    expect(() => discoverRepository(policy, repo)).toThrow();
    expect(readFileSync(path.join(outside, 'sentinel'), 'utf8')).toBe(
      'unchanged',
    );
  });

  it('rejects outside preexisting fetch/push/rewrite URLs before transfer', () => {
    git(repo, 'remote', 'add', 'origin', outside);
    expect(() =>
      authorizeRepositoryRemotes(
        policy,
        discoverRepository(policy, repo),
        'fetch',
      ),
    ).toThrow();
    git(repo, 'remote', 'set-url', 'origin', path.join(root2, 'new-bare'));
    expect(() =>
      authorizeRepositoryRemotes(
        policy,
        discoverRepository(policy, repo),
        'fetch',
      ),
    ).not.toThrow();
    git(repo, 'remote', 'set-url', '--push', 'origin', outside);
    expect(() =>
      authorizeRepositoryRemotes(
        policy,
        discoverRepository(policy, repo),
        'push',
      ),
    ).toThrow();
    git(repo, 'config', '--unset-all', 'remote.origin.pushurl');
    git(repo, 'remote', 'set-url', 'origin', 'https://alias.example/repo');
    git(repo, 'config', `url.${outside}/.insteadOf`, 'https://alias.example/');
    expect(() =>
      authorizeRepositoryRemotes(
        policy,
        discoverRepository(policy, repo),
        'fetch',
      ),
    ).toThrow();
    expect(readFileSync(path.join(outside, 'sentinel'), 'utf8')).toBe(
      'unchanged',
    );
  });

  it('matches native config syntax BOM without stripping BOM or U+FFFD from worktree values', () => {
    const filename = path.join(root1, 'metadata-config');
    for (const value of ['\ufeffrepo', 'repo\ufeff', 'repo\ufffd']) {
      writeFileSync(filename, `\ufeff[core]\r\n\tworktree = ${value}\r\n`);
      const parsed = metadataConfig(policy.readMetadata(filename)).get(
        'core.worktree',
      )![0]!;
      const native = execFileSync(
        '/usr/bin/git',
        ['config', '--null', '--file', filename, '--get', 'core.worktree'],
        {
          cwd: root1,
          env: {
            PATH: '/usr/bin:/bin',
            HOME: dir,
            GIT_CONFIG_NOSYSTEM: '1',
            GIT_CONFIG_GLOBAL: '/dev/null',
          },
          stdio: 'pipe',
        },
      );
      expect(native.at(-1)).toBe(0);
      expect(parsed).toBe(value);
      expect(Buffer.from(parsed)).toEqual(native.subarray(0, -1));
    }
  });

  it('uses longest rewrites and explicit pushurl semantics', () => {
    const config = metadataConfig(
      '[url "/first/"]\n insteadOf = https://host/\n[url "/specific/"]\n insteadOf = https://host/team/\n[url "/push/"]\n pushInsteadOf = https://host/\n',
    );
    expect(rewriteRemoteUrl('https://host/team/repo', config, false)).toBe(
      '/specific/repo',
    );
    expect(rewriteRemoteUrl('https://host/team/repo', config, true)).toBe(
      '/push/team/repo',
    );
    expect(rewriteRemoteUrl('https://host/team/repo', config, true, true)).toBe(
      '/specific/repo',
    );
    expect(() =>
      metadataConfig('[include]\n path = /outside/config'),
    ).toThrow();
    expect(() => metadataConfig('[core]\n worktree = "../outside"')).toThrow();
  });
});
