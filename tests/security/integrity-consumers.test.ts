/**
 * @fileoverview Real Git consumer oracles for records, paths, pushes and signing.
 * @module tests/security/integrity-consumers.test
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
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, afterEach, describe, it } from 'node:test';
import { config } from '../../src/config/index.js';
import { executeLog } from '../../src/services/git/providers/cli/operations/commits/log.js';
import { executeTag } from '../../src/services/git/providers/cli/operations/tags/tag.js';
import { executeCommit } from '../../src/services/git/providers/cli/operations/commits/commit.js';
import { executePush } from '../../src/services/git/providers/cli/operations/remotes/push.js';
import { executeAdd } from '../../src/services/git/providers/cli/operations/staging/add.js';
import { executeDiff } from '../../src/services/git/providers/cli/operations/commits/diff.js';
import { executeGitCommand } from '../../src/services/git/providers/cli/utils/git-executor.js';
import type { ExecuteGitOptions } from '../../src/services/git/providers/cli/utils/git-executor.js';
import { withConfiguredGitExecutionContext } from '../../src/services/git/providers/cli/utils/configured-execution-policy.js';
import { buildTrustedGitEnvironment } from '../../src/services/git/providers/cli/utils/execution-policy.js';
import type { RequestContext } from '../../src/utils/internal/requestContext.js';

describe('production integrity consumers', { timeout: 30000 }, () => {
  let temporary: string, repository: string, home: string;
  let env: Record<string, string>, saved: typeof config.git;
  const context = () => ({
    workingDirectory: repository,
    repositoryRoots: [temporary],
    requestContext: {
      requestId: 'integrity-consumer',
      timestamp: new Date().toISOString(),
    },
  });
  const git = (...args: string[]) =>
    execFileSync('/usr/bin/git', args, {
      cwd: repository,
      env,
      encoding: 'utf8',
    });
  const calls: string[][] = [];
  const execute = (
    args: string[],
    cwd: string,
    _ctx: RequestContext,
    options?: ExecuteGitOptions,
  ) => {
    calls.push(args);
    return executeGitCommand(args, cwd, {
      ...options,
      repositoryRoots: [temporary],
    });
  };
  const scoped = <T>(run: () => Promise<T>) =>
    withConfiguredGitExecutionContext(undefined, run);
  beforeEach(() => {
    saved = { ...config.git };
    calls.length = 0;
    temporary = realpathSync(
      mkdtempSync(join(tmpdir(), 'git-integrity-consumer-')),
    );
    repository = join(temporary, 'repository');
    home = join(temporary, 'home');
    mkdirSync(repository);
    mkdirSync(home);
    writeFileSync(
      join(home, '.gitconfig'),
      '[user]\n name = Integrity Fixture\n email = fixture@example.invalid\n[commit]\n gpgsign = false\n',
    );
    Object.assign(config.git, {
      executionProfile: 'trusted',
      binaryPath: '/usr/bin/git',
      trustedHome: home,
      trustedPath: '/usr/bin:/bin',
      baseDirs: [temporary],
      signCommits: false,
      maxCommandTimeoutMs: 30000,
      maxOutputBytes: 4 * 1024 * 1024,
      maxStdoutBytes: 4 * 1024 * 1024,
      maxStderrBytes: 4 * 1024 * 1024,
    });
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
  });
  afterEach(() => {
    Object.assign(config.git, saved);
    rmSync(temporary, { recursive: true, force: true });
  });

  it('cannot forge log or tag records with body markers and preserves exact bodies', async () => {
    const body =
      'body\n<<<COMMIT_START>>>fake\x1ffield\x1e\n<<<COMMIT_END>>>\n';
    const message = 'hostile subject\n\n' + body;
    const file = join(temporary, 'message');
    writeFileSync(file, message);
    git('commit', '--allow-empty', '--cleanup=verbatim', '-F', file);
    const oid = git('rev-parse', 'HEAD').trim();
    git('tag', '-a', '--cleanup=verbatim', '-F', file, 'v1');
    const logs = await scoped(() =>
      executeLog({ maxCount: 10 }, context(), execute),
    );
    assert.equal(logs.totalCount, 2);
    assert.equal(logs.commits[0]!.hash, oid);
    assert.equal(logs.commits[0]!.author, 'Integrity Fixture');
    assert.equal(logs.commits[0]!.body, body);
    const tags = await scoped(() =>
      executeTag({ mode: 'list' }, context(), execute),
    );
    assert.equal(tags.tags?.length, 1);
    assert.equal(tags.tags[0]!.commit, oid);
    assert.equal(tags.tags[0]!.annotationBody, body);
  });

  it('stages only literal requested paths and keeps the extra-file sentinel unchanged', async () => {
    const names = [
      '-',
      '--all',
      ':(glob)*',
      '*',
      '?',
      'line\nname',
      '\ufeffname',
      '\ufffdname',
    ];
    for (const name of [...names, 'sentinel'])
      writeFileSync(join(repository, name), name);
    await scoped(() => executeAdd({ paths: names }, context(), execute));
    const indexed = git('ls-files', '-z').split('\0').filter(Boolean).sort();
    assert.deepEqual(indexed, [...names].sort());
    assert.equal(
      readFileSync(join(repository, 'sentinel'), 'utf8'),
      'sentinel',
    );
  });

  it('counts newline and dash filenames from NUL enumeration through combined diff', async () => {
    writeFileSync(join(repository, '-'), 'dash\n');
    writeFileSync(join(repository, 'line\nname'), 'newline\n');
    const result = await scoped(() =>
      executeDiff({ includeUntracked: true }, context(), execute),
    );
    assert.equal(result.filesChanged, 2);
    assert.equal(result.insertions, 2);
    assert.equal(
      calls.filter((args) => args[0] === 'diff' && args.includes('--numstat'))
        .length,
      2,
    );
    assert.equal(
      calls.filter(
        (args) => args.includes('--no-index') && args.includes('--stat'),
      ).length,
      0,
    );
    assert.ok(result.diff.includes('+dash'));
    assert.ok(result.diff.includes('+newline'));
  });

  it('literal diff selection excludes an untracked extra-file sentinel', async () => {
    writeFileSync(join(repository, 'selected.txt'), 'selected content\n');
    writeFileSync(
      join(repository, 'extra-sentinel.txt'),
      'EXTRA_SENTINEL_CONTENT\n',
    );
    const result = await scoped(() =>
      executeDiff(
        { includeUntracked: true, paths: ['selected.txt'] },
        context(),
        execute,
      ),
    );
    assert.equal(result.filesChanged, 1);
    assert.equal(result.insertions, 1);
    assert.ok(result.diff.includes('+selected content'));
    assert.ok(!result.diff.includes('EXTRA_SENTINEL_CONTENT'));
    assert.equal(calls.filter((args) => args.includes('--no-index')).length, 1);
    assert.equal(
      readFileSync(join(repository, 'extra-sentinel.txt'), 'utf8'),
      'EXTRA_SENTINEL_CONTENT\n',
    );
  });

  it('denies force, lease, deletion and configured force before any native push', async () => {
    git('config', 'remote.origin.url', join(temporary, 'remote.git'));
    // Initialize the actual destination so canonical transfer discovery is valid.
    execFileSync(
      '/usr/bin/git',
      ['init', '--bare', join(temporary, 'remote.git')],
      { env, stdio: 'pipe' },
    );
    for (const options of [
      { branch: 'feature', remoteBranch: 'main', force: true },
      {
        branch: 'feature',
        remoteBranch: 'refs/heads/main',
        forceWithLease: true,
      },
      { remoteBranch: 'refs/heads/main', delete: true },
    ]) {
      await assert.rejects(
        scoped(() => executePush(options, context(), execute)),
        /confirmation/i,
      );
    }
    git('config', 'remote.origin.push', '+refs/heads/feature:refs/heads/main');
    await assert.rejects(
      scoped(() => executePush({}, context(), execute)),
      /confirmation/i,
    );
    assert.equal(calls.filter((args) => args[0] === 'push').length, 0);
  });

  it('ordinary explicit feature push succeeds with an exact destination', async () => {
    const destination = join(temporary, 'remote.git');
    execFileSync('/usr/bin/git', ['init', '--bare', destination], {
      env,
      stdio: 'pipe',
    });
    git('config', 'remote.origin.url', destination);
    const result = await scoped(() =>
      executePush({ branch: 'feature' }, context(), execute),
    );
    assert.equal(result.success, true);
    assert.ok(
      calls.some(
        (args) =>
          args[0] === 'push' &&
          args.includes('refs/heads/feature:refs/heads/feature'),
      ),
    );
    assert.equal(
      execFileSync(
        '/usr/bin/git',
        ['--git-dir', destination, 'rev-parse', 'refs/heads/feature'],
        { env, encoding: 'utf8' },
      ),
      git('rev-parse', 'HEAD'),
    );
  });

  it('strict signing failure never retries creation or repeats a hook', async () => {
    config.git.signCommits = true;
    const counter = join(temporary, 'hook-count');
    writeFileSync(
      join(repository, '.git', 'hooks', 'pre-commit'),
      '#!/bin/sh\nprintf call >> "' + counter + '"\n',
      { mode: 0o700 },
    );
    git('config', 'gpg.program', '/usr/bin/false');
    const before = git('rev-parse', 'HEAD');
    await assert.rejects(
      scoped(() =>
        executeCommit(
          { message: 'must sign', allowEmpty: true },
          context(),
          execute,
        ),
      ),
    );
    assert.equal(calls.filter((args) => args[0] === 'commit').length, 1);
    assert.equal(readFileSync(counter, 'utf8'), 'call');
    assert.equal(git('rev-parse', 'HEAD'), before);
  });

  it('native unsigned policy creates once and reports actual signature presence', async () => {
    const result = await scoped(() =>
      executeCommit(
        { message: 'native', allowEmpty: true },
        context(),
        execute,
      ),
    );
    assert.equal(result.signed, false);
    assert.equal(result.commitHash, git('rev-parse', 'HEAD').trim());
    assert.equal(calls.filter((args) => args[0] === 'commit').length, 1);
  });

  it('verifies real native SSH trust and never accepts recognized prose with exit1', async () => {
    const key = join(home, 'key');
    execFileSync(
      '/usr/bin/ssh-keygen',
      ['-q', '-t', 'ed25519', '-N', '', '-f', key],
      { env },
    );
    git('config', 'gpg.format', 'ssh');
    git('config', 'user.signingkey', key);
    const allowed = join(home, 'allowed');
    writeFileSync(
      allowed,
      'fixture@example.invalid ' + readFileSync(key + '.pub', 'utf8'),
    );
    git('config', 'gpg.ssh.allowedSignersFile', allowed);
    config.git.signCommits = true;
    const created = await scoped(() =>
      executeTag(
        { mode: 'create', tagName: 'signed', message: 'annotation' },
        context(),
        execute,
      ),
    );
    assert.equal(created.signed, true);
    const valid = await scoped(() =>
      executeTag({ mode: 'verify', tagName: 'signed' }, context(), execute),
    );
    assert.equal(valid.verified, true);
    assert.equal(valid.trust, 'trusted');
    const failed = await scoped(() =>
      executeTag(
        { mode: 'verify', tagName: 'signed' },
        context(),
        (args, cwd, ctx, options) =>
          args[0] === 'verify-tag'
            ? Promise.resolve({
                stdout: '',
                stderr: valid.rawOutput!,
                exitCode: 1,
              })
            : execute(args, cwd, ctx, options),
      ),
    );
    assert.equal(failed.verified, false);
    writeFileSync(allowed, '');
    const untrusted = await scoped(() =>
      executeTag({ mode: 'verify', tagName: 'signed' }, context(), execute),
    );
    assert.equal(untrusted.verified, false);
  });

  it('does not retry a failed strict tag creation unsigned', async () => {
    config.git.signCommits = true;
    git('config', 'gpg.program', '/usr/bin/false');
    await assert.rejects(
      scoped(() =>
        executeTag(
          { mode: 'create', tagName: 'must-sign', message: 'annotation' },
          context(),
          execute,
        ),
      ),
    );
    assert.equal(calls.filter((args) => args[0] === 'tag').length, 1);
    assert.equal(git('tag', '--list', 'must-sign'), '');
  });
});
