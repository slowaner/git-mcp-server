/**
 * @fileoverview Native effective-config fixtures and bounded parser failures.
 * @module tests/security/repository-effective-config.test
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { RepositoryPathPolicy } from '@/services/git/core/repository-capability.js';
import {
  parseEffectiveGitConfig,
  resolveEffectiveRepository,
} from '@/services/git/core/repository-effective-config.js';
import { rewriteRemoteUrl } from '@/services/git/core/repository-remotes.js';

describe('effective repository configuration', () => {
  let dir: string;
  let root: string;
  let repo: string;
  let home: string;
  let outside: string;
  let policy: RepositoryPathPolicy;
  let reads: number;
  const git = (cwd: string, ...args: string[]): string =>
    execFileSync('git', args, {
      cwd,
      env: { PATH: process.env.PATH!, HOME: home, GIT_CONFIG_NOSYSTEM: '1' },
      encoding: 'utf8',
      stdio: 'pipe',
    });
  const readConfig = async (
    cwd: string,
  ): Promise<{ stdout: string; exitCode: number }> => {
    reads++;
    return {
      stdout: git(cwd, 'config', '--null', '--list', '--includes'),
      exitCode: 0,
    };
  };
  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'effective-config-'));
    root = path.join(dir, 'root');
    home = path.join(dir, 'home');
    outside = path.join(dir, 'outside');
    for (const directory of [root, home, outside]) mkdirSync(directory);
    repo = path.join(root, 'repo');
    mkdirSync(repo);
    git(repo, 'init', '--initial-branch=main');
    writeFileSync(path.join(outside, 'sentinel'), 'unchanged');
    policy = new RepositoryPathPolicy([root]);
    reads = 0;
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('parses complete framing, duplicate precedence and case-sensitive subsections', () => {
    const config = parseEffectiveGitConfig(
      'Core.Worktree\nfirst\0core.worktree\nsecond\0remote.Origin.URL\n/repo\0user.name\nline1\nline2\0core.flag\0',
    );
    expect(config.get('core.worktree')).toEqual(['first', 'second']);
    expect(config.get('remote.Origin.url')).toEqual(['/repo']);
    expect(config.get('user.name')).toEqual(['line1\nline2']);
    expect(config.get('core.flag')).toEqual(['true']);
    for (const raw of [
      'core.worktree\n/partial',
      '\0',
      'invalid\nvalue\0',
      'remote.origin.url\n/path\n/other\0',
      'core.worktree\n' + 'x'.repeat(1024 * 1024) + '\0',
      'user.name\nx\0'.repeat(10001),
    ]) {
      expect(() => parseEffectiveGitConfig(raw)).toThrow();
    }
  });

  it('uses trusted includes and includeIf in the intended canonical cwd', async () => {
    const included = path.join(home, 'included');
    writeFileSync(
      included,
      '[user]\n name = Native Fixture\n[commit]\n gpgSign = true\n',
    );
    writeFileSync(
      path.join(home, '.gitconfig'),
      `[includeIf "gitdir:${policy.resolve(repo).path}/"]\n path = ${included}\n`,
    );
    const result = await resolveEffectiveRepository(policy, repo, readConfig);
    expect(result.config.get('user.name')).toEqual(['Native Fixture']);
    expect(result.config.get('commit.gpgsign')).toEqual(['true']);
    expect(reads).toBe(1);
  });

  it('rejects effective global worktree and rewrite paths before transfer', async () => {
    git(repo, 'remote', 'add', 'origin', 'https://alias.example/repo');
    writeFileSync(
      path.join(home, '.gitconfig'),
      `[url "${outside}/"]\n insteadOf = https://alias.example/\n`,
    );
    await expect(
      resolveEffectiveRepository(policy, repo, readConfig),
    ).rejects.toThrow();
    writeFileSync(
      path.join(home, '.gitconfig'),
      `[core]\n worktree = ${outside}\n`,
    );
    await expect(
      resolveEffectiveRepository(policy, repo, readConfig),
    ).rejects.toThrow();
    expect(readFileSync(path.join(outside, 'sentinel'), 'utf8')).toBe(
      'unchanged',
    );
  });

  it('rejects local includes and unsafe metadata before config Git is invoked', async () => {
    writeFileSync(
      path.join(repo, '.git/config'),
      `[include]\n path = ${outside}/sentinel\n`,
    );
    await expect(
      resolveEffectiveRepository(policy, repo, readConfig),
    ).rejects.toThrow();
    expect(reads).toBe(0);
    expect(readFileSync(path.join(outside, 'sentinel'), 'utf8')).toBe(
      'unchanged',
    );
  });

  it('rejects nonzero introspection and worktree interpolation', async () => {
    await expect(
      resolveEffectiveRepository(policy, repo, async () => ({
        stdout: '',
        exitCode: 1,
      })),
    ).rejects.toThrow();
    await expect(
      resolveEffectiveRepository(policy, repo, async () => ({
        stdout: 'core.worktree\n~/outside\0',
        exitCode: 0,
      })),
    ).rejects.toThrow();
  });

  it('matches native push rewrite composition and explicit push URL handling', () => {
    const source = 'https://source.example/repo';
    git(repo, 'remote', 'add', 'origin', source);
    git(
      repo,
      'config',
      'url.https://push.example/.pushInsteadOf',
      'https://source.example/',
    );
    git(repo, 'config', `url.${outside}/.insteadOf`, 'https://push.example/');
    const config = parseEffectiveGitConfig(
      git(repo, 'config', '--null', '--list', '--includes'),
    );
    expect(rewriteRemoteUrl(source, config, true)).toBe(
      git(repo, 'remote', 'get-url', '--push', '--all', 'origin').trim(),
    );
    git(
      repo,
      'remote',
      'set-url',
      '--push',
      'origin',
      'https://push.example/explicit',
    );
    expect(
      rewriteRemoteUrl('https://push.example/explicit', config, true, true),
    ).toBe(git(repo, 'remote', 'get-url', '--push', '--all', 'origin').trim());
  });
});
