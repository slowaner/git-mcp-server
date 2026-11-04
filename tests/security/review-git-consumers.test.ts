/**
 * @fileoverview Native signed-history and triangular-push review regressions.
 * @module tests/security/review-git-consumers.test
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
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
import { config } from '../../src/config/index.js';
import { gatherRepoSnapshot } from '../../src/mcp-server/tools/utils/repo-snapshot.js';
import { CliGitProvider } from '../../src/services/git/providers/cli/CliGitProvider.js';
import { buildTrustedGitEnvironment } from '../../src/services/git/providers/cli/utils/execution-policy.js';

describe('native review consumer regressions', { timeout: 30000 }, () => {
  let root: string, repository: string, home: string;
  let saved: typeof config.git, env: Record<string, string>;
  const git = (...args: string[]) =>
    execFileSync('/usr/bin/git', args, {
      cwd: repository,
      env,
      encoding: 'utf8',
    });
  const context = () => ({
    workingDirectory: repository,
    repositoryRoots: [root],
    requestContext: {
      requestId: 'review-consumer',
      timestamp: new Date().toISOString(),
    },
  });
  const remoteState = (directory: string) => ({
    refs: git('--git-dir', directory, 'for-each-ref'),
    objects: git('--git-dir', directory, 'count-objects', '-v'),
  });
  beforeEach(() => {
    saved = { ...config.git };
    root = realpathSync(mkdtempSync(join(tmpdir(), 'git-review-consumer-')));
    repository = join(root, 'repository');
    home = join(root, 'home');
    mkdirSync(repository);
    mkdirSync(home);
    writeFileSync(
      join(home, '.gitconfig'),
      '[user]\n name = Review Fixture\n email = fixture@example.invalid\n[commit]\n gpgsign = false\n',
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
    Object.assign(config.git, {
      executionProfile: 'trusted',
      binaryPath: '/usr/bin/git',
      trustedHome: home,
      trustedPath: '/usr/bin:/bin',
      baseDirs: [root],
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

  it('keeps configured signature display out of identity history and repository snapshots', async () => {
    const key = join(home, 'signing-key');
    execFileSync(
      '/usr/bin/ssh-keygen',
      ['-q', '-t', 'ed25519', '-N', '', '-f', key],
      { env },
    );
    const signers = join(home, 'allowed-signers');
    writeFileSync(
      signers,
      'fixture@example.invalid ' + readFileSync(key + '.pub', 'utf8'),
    );
    git('config', 'gpg.format', 'ssh');
    git('config', 'user.signingkey', key);
    git('config', 'gpg.ssh.allowedSignersFile', signers);
    git('config', 'log.showSignature', 'true');
    const body = 'body\n<<<COMMIT_START>>>\x1f\x1e\nexact trailing line\n';
    const message = join(root, 'message');
    writeFileSync(message, 'signed subject\n\n' + body);
    git('commit', '--allow-empty', '-S', '--cleanup=verbatim', '-F', message);
    const oid = git('rev-parse', 'HEAD').trim();
    const nativeDisplay = git('log', '--format=%H', '-n1');
    assert.ok(nativeDisplay.includes(oid));
    assert.notEqual(
      nativeDisplay.trim(),
      oid,
      'native signature display actually adds output',
    );
    const provider = new CliGitProvider();
    const history = await provider.log({ maxCount: 1 }, context());
    assert.equal(history.totalCount, 1);
    assert.equal(history.commits[0]!.hash, oid);
    assert.equal(history.commits[0]!.subject, 'signed subject');
    assert.equal(history.commits[0]!.body, body);
    const snapshot = await gatherRepoSnapshot(
      {
        provider,
        workingDirectory: repository,
        repositoryRoots: [root],
        appContext: context().requestContext,
      },
      { commitLimit: 1, tagLimit: 1 },
    );
    assert.deepEqual(snapshot.warnings, []);
    assert.equal(snapshot.snapshot?.recentCommits.length, 1);
    assert.equal(snapshot.snapshot?.recentCommits[0]!.hash, oid.slice(0, 7));
    assert.equal(
      snapshot.snapshot?.recentCommits[0]!.subject,
      'signed subject',
    );
    assert.equal(git('config', '--get', 'log.showSignature').trim(), 'true');
  });

  it('pushes simple to the same-named branch on a separate push remote without touching tracking refs', async () => {
    const origin = join(root, 'origin.git'),
      upstream = join(root, 'upstream.git');
    git('init', '-q', '--bare', origin);
    git('init', '-q', '--bare', upstream);
    git('config', 'remote.origin.url', origin);
    git('config', 'remote.upstream.url', upstream);
    git('config', 'branch.feature.remote', 'upstream');
    git('config', 'branch.feature.merge', 'refs/heads/feature');
    git('config', 'branch.feature.pushRemote', 'origin');
    git('config', 'push.default', 'simple');
    const before = remoteState(upstream),
      oid = git('rev-parse', 'HEAD').trim();
    const result = await new CliGitProvider().push({}, context());
    assert.equal(result.success, true);
    assert.equal(result.remote, 'origin');
    assert.equal(
      git('--git-dir', origin, 'rev-parse', 'refs/heads/feature').trim(),
      oid,
    );
    assert.deepEqual(remoteState(upstream), before);
    assert.equal(
      git('--git-dir', origin, 'for-each-ref', '--format=%(refname)'),
      'refs/heads/feature\n',
    );
    assert.equal(
      git('config', '--get', 'branch.feature.remote').trim(),
      'upstream',
    );
    assert.equal(
      git('config', '--get', 'branch.feature.merge').trim(),
      'refs/heads/feature',
    );
  });

  it('preserves central simple pushes and rejects central upstream-name mismatch before transfer', async () => {
    const upstream = join(root, 'upstream.git');
    git('init', '-q', '--bare', upstream);
    git('config', 'remote.upstream.url', upstream);
    git('config', 'branch.feature.remote', 'upstream');
    git('config', 'branch.feature.pushRemote', 'upstream');
    git('config', 'push.default', 'simple');
    git('config', 'branch.feature.merge', 'refs/heads/main');
    const before = remoteState(upstream);
    await assert.rejects(
      new CliGitProvider().push({}, context()),
      /Simple push upstream differs/,
    );
    assert.deepEqual(remoteState(upstream), before);
    git('config', 'branch.feature.merge', 'refs/heads/feature');
    await new CliGitProvider().push({}, context());
    assert.equal(
      git('--git-dir', upstream, 'rev-parse', 'refs/heads/feature').trim(),
      git('rev-parse', 'HEAD').trim(),
    );
    assert.equal(
      git('--git-dir', upstream, 'for-each-ref', '--format=%(refname)'),
      'refs/heads/feature\n',
    );
  });
});
