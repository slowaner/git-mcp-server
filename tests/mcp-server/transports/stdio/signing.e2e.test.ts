/**
 * @fileoverview Native Git signing through real MCP tools, isolated SSH keys,
 * configuration files, repositories, and local bare remotes.
 * @module tests/mcp-server/transports/stdio/signing.e2e.test
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
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
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const TIMEOUT_MS = 30_000;

describe('stdio transport: native Git signing', () => {
  let client: Client;
  let root: string;
  let globalConfig: string;
  let env: Record<string, string>;
  let globalSettings: string;

  function run(command: string[], cwd: string): string {
    const proc = Bun.spawnSync(command, { cwd, env });
    if (proc.exitCode !== 0) {
      throw new Error(`${command.join(' ')} failed: ${proc.stderr.toString()}`);
    }
    return proc.stdout.toString().trim();
  }

  function git(args: string[], cwd: string): string {
    return run(['git', ...args], cwd);
  }

  function commitFile(repo: string, name: string, content: string): string {
    writeFileSync(join(repo, name), content);
    git(['add', '--', name], repo);
    git(['commit', '--message=fixture commit'], repo);
    return git(['rev-parse', 'HEAD'], repo);
  }

  function repository(name: string, signing?: boolean): string {
    const repo = join(root, name);
    mkdirSync(repo, { recursive: true });
    git(['init', '-q', '-b', 'main'], repo);
    if (signing !== undefined) {
      git(['config', 'commit.gpgSign', String(signing)], repo);
      git(['config', 'tag.gpgSign', String(signing)], repo);
    }
    commitFile(repo, 'base.txt', 'base\n');
    return repo;
  }

  function expectCommitSignature(repo: string, signed: boolean): void {
    const object = git(['cat-file', 'commit', 'HEAD'], repo);
    expect(/^gpgsig(?:-sha256)? /m.test(object.split('\n\n', 1)[0]!)).toBe(
      signed,
    );
  }

  function expectTagSignature(
    repo: string,
    tag: string,
    signed: boolean,
  ): void {
    const signature = git(
      ['for-each-ref', '--format=%(contents:signature)', `refs/tags/${tag}`],
      repo,
    );
    expect(signature.includes('-----BEGIN SSH SIGNATURE-----')).toBe(signed);
  }

  async function call(
    name: string,
    path: string,
    args: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    const result = await client.callTool({
      name,
      arguments: { path, ...args },
    });
    expect(result.isError, JSON.stringify(result)).toBeFalsy();
    return (result.structuredContent ?? {}) as Record<string, unknown>;
  }

  async function expectError(
    name: string,
    path: string,
    args: Record<string, unknown>,
  ): Promise<string> {
    const result = await client.callTool({
      name,
      arguments: { path, ...args },
    });
    expect(result.isError, JSON.stringify(result)).toBe(true);
    return JSON.stringify(result.content);
  }

  beforeAll(async () => {
    root = realpathSync(mkdtempSync(join(tmpdir(), 'git-mcp-signing-e2e-')));
    globalConfig = join(root, 'gitconfig');
    env = { ...(process.env as Record<string, string>) };
    // These are test fixtures, independent of the developer's config, identity,
    // signing keys, and any MCP deployment environment overrides.
    for (const key of Object.keys(env)) {
      if (key.startsWith('GIT_')) delete env[key];
    }
    Object.assign(env, {
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: globalConfig,
      GIT_PROVIDER: 'cli',
      GIT_SIGN_COMMITS: 'false',
      GIT_EDITOR: 'true',
      GIT_SEQUENCE_EDITOR: 'true',
    });
    // Remove server identity aliases too; identity comes from fixture Git config.
    delete env.GIT_USERNAME;
    delete env.GIT_EMAIL;
    const key = join(root, 'signing-key');
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key], root);
    globalSettings = [
      '[user]',
      '  name = Signing fixture',
      '  email = signing@example.com',
      `  signingKey = ${key}`,
      '[gpg]',
      '  format = ssh',
      '[commit]',
      '  gpgSign = true',
      '[tag]',
      '  gpgSign = true',
      '[pull]',
      '  rebase = false',
      '',
    ].join('\n');
    writeFileSync(globalConfig, globalSettings);
    client = new Client({ name: 'native-signing-e2e', version: '0.0.0' });
    await client.connect(
      new StdioClientTransport({
        command: 'bun',
        args: ['src/index.ts'],
        cwd: process.cwd(),
        env: { ...env, MCP_TRANSPORT_TYPE: 'stdio', MCP_LOG_LEVEL: 'error' },
        stderr: 'pipe',
      }),
    );
  }, TIMEOUT_MS);

  afterAll(async () => {
    await client?.close();
    if (root) rmSync(root, { recursive: true, force: true });
  });

  for (const signed of [true, false]) {
    it(
      `commit, tag, merge, cherry-pick, rebase, and pull follow native signing=${signed}`,
      async () => {
        // Enabled case inherits global config; disabled case overrides it locally.
        const repo = repository(
          `operations-${signed}`,
          signed ? undefined : false,
        );
        writeFileSync(join(repo, 'tool.txt'), 'tool commit\n');
        const commit = await call('git_commit', repo, {
          message: '-native commit',
          filesToStage: ['tool.txt'],
        });
        expect(commit.signed).toBe(signed);
        expectCommitSignature(repo, signed);
        const tag = await call('git_tag', repo, {
          mode: 'create',
          tagName: 'native',
        });
        expect(tag.signed).toBe(signed);
        expectTagSignature(repo, 'native', signed);
        expect(git(['cat-file', '-t', 'refs/tags/native'], repo)).toBe(
          signed ? 'tag' : 'commit',
        );
        if (signed)
          expect(
            git(
              ['for-each-ref', '--format=%(subject)', 'refs/tags/native'],
              repo,
            ),
          ).toBe('Tag native');

        git(['checkout', '-q', '-b', 'feature'], repo);
        commitFile(repo, 'feature.txt', 'feature\n');
        git(['checkout', '-q', 'main'], repo);
        await call('git_merge', repo, {
          branch: 'feature',
          noFastForward: true,
          message: 'native merge',
        });
        expectCommitSignature(repo, signed);

        git(['checkout', '-q', '-b', 'pick-source'], repo);
        const picked = commitFile(repo, 'pick.txt', 'pick\n');
        git(['checkout', '-q', 'main'], repo);
        commitFile(repo, 'before-pick.txt', 'advance\n');
        await call('git_cherry_pick', repo, { commits: [picked] });
        expectCommitSignature(repo, signed);

        git(['checkout', '-q', '-b', 'rebased'], repo);
        commitFile(repo, 'rebase.txt', 'rebase\n');
        git(['checkout', '-q', 'main'], repo);
        commitFile(repo, 'before-rebase.txt', 'advance\n');
        git(['checkout', '-q', 'rebased'], repo);
        await call('git_rebase', repo, { mode: 'start', upstream: 'main' });
        expectCommitSignature(repo, signed);

        const pullRepo = repository(
          `pull-${signed}`,
          signed ? undefined : false,
        );
        const remote = join(root, `remote-${signed}.git`);
        git(['init', '-q', '--bare', '-b', 'main', remote], root);
        git(['remote', 'add', 'origin', remote], pullRepo);
        git(['push', '-q', '-u', 'origin', 'main'], pullRepo);
        const producer = join(root, `producer-${signed}`);
        git(['clone', '-q', remote, producer], root);
        commitFile(producer, 'remote.txt', 'remote\n');
        git(['push', '-q'], producer);
        commitFile(pullRepo, 'local.txt', 'local\n');
        await call('git_pull', pullRepo, { remote: 'origin', branch: 'main' });
        expectCommitSignature(pullRepo, signed);

        commitFile(producer, 'remote-again.txt', 'remote again\n');
        git(['push', '-q'], producer);
        commitFile(pullRepo, 'local-again.txt', 'local again\n');
        await call('git_pull', pullRepo, {
          remote: 'origin',
          branch: 'main',
          rebase: true,
        });
        expectCommitSignature(pullRepo, signed);
      },
      TIMEOUT_MS,
    );
  }

  it(
    'honors tag.forceSignAnnotated while preserving lightweight tags',
    async () => {
      const repo = repository('force-annotated', false);
      git(['config', 'tag.forceSignAnnotated', 'true'], repo);
      const annotated = await call('git_tag', repo, {
        mode: 'create',
        tagName: 'annotated',
        annotated: true,
      });
      expect(annotated.signed).toBe(true);
      expectTagSignature(repo, 'annotated', true);
      const message = await call('git_tag', repo, {
        mode: 'create',
        tagName: 'message',
        message: '-message',
      });
      expect(message.signed).toBe(true);
      expectTagSignature(repo, 'message', true);
      const lightweight = await call('git_tag', repo, {
        mode: 'create',
        tagName: 'lightweight',
      });
      expect(lightweight.signed).toBe(false);
      expect(git(['cat-file', '-t', 'refs/tags/lightweight'], repo)).toBe(
        'commit',
      );
    },
    TIMEOUT_MS,
  );

  it(
    'honors conditional includes and repository overrides',
    async () => {
      const included = join(root, 'conditional.gitconfig');
      writeFileSync(
        included,
        '[commit]\n  gpgSign = true\n[tag]\n  gpgSign = true\n',
      );
      writeFileSync(
        globalConfig,
        globalSettings.replaceAll('gpgSign = true', 'gpgSign = false') +
          `[includeIf "gitdir:${root}/conditional/"]\n  path = ${included}\n`,
      );
      try {
        const repo = repository('conditional/repo');
        const commit = await call('git_commit', repo, {
          message: 'conditional',
          allowEmpty: true,
        });
        expect(commit.signed).toBe(true);
        expectCommitSignature(repo, true);
        expect(
          (
            await call('git_tag', repo, {
              mode: 'create',
              tagName: 'conditional',
            })
          ).signed,
        ).toBe(true);
        git(['config', 'commit.gpgSign', 'false'], repo);
        git(['config', 'tag.gpgSign', 'false'], repo);
        expect(
          (
            await call('git_commit', repo, {
              message: 'local override',
              allowEmpty: true,
            })
          ).signed,
        ).toBe(false);
        expect(
          (await call('git_tag', repo, { mode: 'create', tagName: 'local' }))
            .signed,
        ).toBe(false);
        const outside = repository('outside-conditional');
        expect(
          (
            await call('git_commit', outside, {
              message: 'outside',
              allowEmpty: true,
            })
          ).signed,
        ).toBe(false);
      } finally {
        writeFileSync(globalConfig, globalSettings);
      }
    },
    TIMEOUT_MS,
  );

  it(
    'propagates configured signing failures without creating unsigned objects',
    async () => {
      const repo = repository('signing-error');
      const head = git(['rev-parse', 'HEAD'], repo);
      git(['config', 'user.signingKey', join(root, 'missing-key')], repo);
      expect(
        await expectError('git_commit', repo, {
          message: 'must sign',
          allowEmpty: true,
        }),
      ).toMatch(/sign|key/i);
      expect(git(['rev-parse', 'HEAD'], repo)).toBe(head);
      expect(
        await expectError('git_tag', repo, {
          mode: 'create',
          tagName: 'must-sign',
        }),
      ).toMatch(/sign|key/i);
      expect(git(['tag', '--list', 'must-sign'], repo)).toBe('');
      git(['config', 'tag.gpgSign', 'not-a-boolean'], repo);
      expect(
        await expectError('git_tag', repo, {
          mode: 'create',
          tagName: 'bad-config',
        }),
      ).toMatch(/boolean|tag.gpgSign/i);
      expect(git(['show-ref', '--heads'], repo)).toContain(head);
    },
    TIMEOUT_MS,
  );

  for (const operation of ['cherry-pick', 'rebase']) {
    it(
      `${operation} continuation preserves native signing`,
      async () => {
        const repo = repository(`continue-${operation}`);
        git(['checkout', '-q', '-b', 'topic'], repo);
        const topic = commitFile(repo, 'base.txt', 'topic\n');
        git(['checkout', '-q', 'main'], repo);
        commitFile(repo, 'base.txt', 'main\n');
        let conflict: Record<string, unknown>;
        if (operation === 'cherry-pick') {
          conflict = await call('git_cherry_pick', repo, { commits: [topic] });
        } else {
          git(['checkout', '-q', 'topic'], repo);
          conflict = await call('git_rebase', repo, {
            mode: 'start',
            upstream: 'main',
          });
        }
        expect(conflict.conflicts).toBe(true);
        writeFileSync(join(repo, 'base.txt'), 'resolved\n');
        await call('git_add', repo, { paths: ['base.txt'] });
        if (operation === 'cherry-pick') {
          await call('git_cherry_pick', repo, {
            commits: [topic],
            continueOperation: true,
          });
        } else {
          await call('git_rebase', repo, { mode: 'continue' });
        }
        expectCommitSignature(repo, true);
        expect(readFileSync(join(repo, 'base.txt'), 'utf8')).toBe('resolved\n');
      },
      TIMEOUT_MS,
    );
  }
});
