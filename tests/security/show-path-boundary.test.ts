/**
 * @fileoverview Real immutable show filters under the canonical repository gate.
 * @module tests/security/show-path-boundary.test
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  mkdtempSync,
  mkdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
  readFileSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, afterEach, describe, it } from 'node:test';
import { config } from '../../src/config/index.js';
import { executeLog } from '../../src/services/git/providers/cli/operations/commits/log.js';
import { executeGitCommand } from '../../src/services/git/providers/cli/utils/git-executor.js';
import { withConfiguredGitExecutionContext } from '../../src/services/git/providers/cli/utils/configured-execution-policy.js';
import { buildTrustedGitEnvironment } from '../../src/services/git/providers/cli/utils/execution-policy.js';
import type { RequestContext } from '../../src/utils/internal/requestContext.js';

describe('immutable show path boundary', { timeout: 30000 }, () => {
  let root: string,
    repository: string,
    home: string,
    log: string,
    outside: string,
    oid: string;
  let saved: typeof config.git, env: Record<string, string>;
  const git = (...args: string[]) =>
    execFileSync('/usr/bin/git', args, {
      cwd: repository,
      env,
      encoding: 'utf8',
    });
  const scope = <T>(run: () => Promise<T>) =>
    withConfiguredGitExecutionContext(undefined, run);
  const execute = (args: string[], cwd: string, _ctx: RequestContext) =>
    executeGitCommand(args, cwd, { repositoryRoots: [repository] });
  beforeEach(() => {
    saved = { ...config.git };
    root = realpathSync(mkdtempSync(join(tmpdir(), 'git-show-boundary-')));
    repository = join(root, 'repo');
    home = join(root, 'home');
    log = join(root, 'calls');
    outside = join(root, 'outside-sentinel');
    mkdirSync(repository);
    mkdirSync(home);
    writeFileSync(log, '');
    writeFileSync(outside, 'OUTSIDE_SENTINEL_BYTES');
    writeFileSync(
      join(home, '.gitconfig'),
      '[user]\n name = Show Fixture\n email = fixture@example.invalid\n[commit]\n gpgsign = false\n',
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
    git('init', '-q', '--initial-branch=main');
    mkdirSync(join(repository, 'dir'));
    for (const name of ['selected', 'dir/file', '-chosen', ':(glob)*'])
      writeFileSync(join(repository, name), 'SELECTED_ONLY_CONTENT\n');
    writeFileSync(join(repository, 'sentinel'), 'OTHER_FILE_SENTINEL\n');
    git('add', '--all');
    git('commit', '-m', 'selected and sentinel');
    oid = git('rev-parse', 'HEAD').trim();
    const binary = join(root, 'git-observer');
    const quote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
    writeFileSync(
      binary,
      '#!/bin/sh\nprintf "%s\\n" "$1" >> ' +
        quote(log) +
        '\nexec /usr/bin/git "$@"\n',
      { mode: 0o700 },
    );
    Object.assign(config.git, {
      executionProfile: 'trusted',
      binaryPath: binary,
      trustedHome: home,
      trustedPath: '/usr/bin:/bin',
      baseDirs: [repository],
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

  for (const path of ['selected', 'dir/', '-chosen', ':(glob)*']) {
    it(
      'keeps selected stat/patch exact for literal filter ' +
        JSON.stringify(path),
      async () => {
        const result = await scope(() =>
          executeLog(
            { maxCount: 1, path, stat: true, patch: true },
            {
              workingDirectory: repository,
              requestContext: {
                requestId: 'show-path',
                timestamp: new Date().toISOString(),
              },
            },
            execute,
          ),
        );
        assert.equal(result.totalCount, 1);
        assert.equal(result.commits[0]!.hash, oid);
        const commit = result.commits[0]!;
        assert.ok(commit.patch!.includes('+SELECTED_ONLY_CONTENT'));
        assert.ok(!commit.patch!.includes('OTHER_FILE_SENTINEL'));
        assert.ok(!commit.stat!.includes('sentinel'));
        assert.match(commit.stat!, /1 file changed/);
        assert.equal(
          readFileSync(join(repository, 'sentinel'), 'utf8'),
          'OTHER_FILE_SENTINEL\n',
        );
      },
    );
  }
  for (const kind of ['outside', 'symlink', 'native-magic'] as const) {
    it(
      'denies ' + kind + ' before show and keeps caught failure terminal',
      async () => {
        const operand =
          kind === 'outside'
            ? outside
            : kind === 'symlink'
              ? 'escape'
              : ':(glob)*';
        if (kind === 'symlink')
          symlinkSync(outside, join(repository, 'escape'));
        await assert.rejects(
          scope(async () => {
            await assert.rejects(
              executeGitCommand(
                ['show', '--format=', '--stat', oid, '--', operand],
                repository,
                { repositoryRoots: [repository] },
              ),
              (error: unknown) => {
                assert.equal(
                  (error as { data?: { reason?: string } }).data?.reason,
                  'REPOSITORY_BOUNDARY',
                );
                return true;
              },
            );
            const before = readFileSync(log, 'utf8');
            await assert.rejects(
              executeGitCommand(['--version'], repository, {
                repositoryRoots: [repository],
              }),
            );
            assert.equal(readFileSync(log, 'utf8'), before);
            return 'partial success must not escape';
          }),
        );
        assert.ok(!readFileSync(log, 'utf8').split('\n').includes('show'));
        assert.equal(readFileSync(outside, 'utf8'), 'OUTSIDE_SENTINEL_BYTES');
      },
    );
  }
  it('preserves ordinary unfiltered show semantics', async () => {
    const output = await scope(() =>
      executeGitCommand(['show', '--format=', '-p', oid], repository, {
        repositoryRoots: [repository],
      }),
    );
    assert.ok(output.stdout.includes('+OTHER_FILE_SENTINEL'));
    assert.ok(output.stdout.includes('+SELECTED_ONLY_CONTENT'));
  });
});
