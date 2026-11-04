/**
 * @fileoverview Production STDIO repository-boundary acceptance with real sentinels.
 * Build this checkout first; run with INTEGRATION=1 under Bun or Node/Vitest.
 * @module tests/security/repository-boundaries.e2e.test
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  rmSync,
  renameSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

describe('production STDIO repository confinement', () => {
  const bundle = join(process.cwd(), 'dist/index.js');
  let bundleHash: string;
  let temporary: string;
  let first: string;
  let second: string;
  let outside: string;
  let home: string;
  let repo: string;
  let outsideRepo: string;
  let env: Record<string, string>;

  function git(cwd: string, ...args: string[]): string {
    return execFileSync('/usr/bin/git', args, {
      cwd,
      encoding: 'utf8',
      stdio: 'pipe',
      env: {
        PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
        HOME: home,
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: join(home, '.gitconfig'),
      },
    }).trim();
  }

  function createRepo(directory: string, branch = 'main'): string {
    mkdirSync(directory, { recursive: true });
    git(directory, 'init', '-q', '--initial-branch', branch);
    writeFileSync(join(directory, 'payload.txt'), `${branch}-fixture\n`);
    git(directory, 'add', '--', 'payload.txt');
    git(directory, 'commit', '-q', '-m', `${branch} fixture`);
    return git(directory, 'rev-parse', 'HEAD');
  }

  /** Hash names and bytes, never follow fixture links or depend on timestamps. */
  function treeHash(directory: string): string {
    const hash = createHash('sha256');
    const walk = (current: string, prefix: string): void => {
      for (const entry of readdirSync(current, { withFileTypes: true }).sort(
        (a, b) => a.name.localeCompare(b.name),
      )) {
        const relative = `${prefix}/${entry.name}`;
        const absolute = join(current, entry.name);
        hash.update(relative).update('\0');
        if (entry.isDirectory()) walk(absolute, relative);
        else if (entry.isSymbolicLink()) hash.update(readlinkSync(absolute));
        else hash.update(readFileSync(absolute));
        hash.update('\0');
      }
    };
    walk(directory, '');
    return hash.digest('hex');
  }

  async function withClient(
    overrides: Record<string, string>,
    body: (client: Client) => Promise<void>,
    restricted = false,
  ): Promise<void> {
    const environment = { ...env, ...overrides };
    if (restricted) delete environment.GIT_EXECUTION_PROFILE;
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [bundle],
      cwd: temporary,
      env: environment,
      stderr: 'pipe',
    });
    const client = new Client({
      name: 'repository-confinement-fixture',
      version: '0.0.0',
    });
    // Drain while discarding logs; no secret/error dump is an assertion oracle.
    transport.stderr?.on('data', () => {});
    try {
      await client.connect(transport);
      await body(client);
    } finally {
      await client.close();
    }
  }

  async function request(
    client: Client,
    name: string,
    args: Record<string, unknown>,
  ): Promise<CallToolResult> {
    return (await client.callTool({ name, arguments: args })) as CallToolResult;
  }

  function accepted(result: CallToolResult): Record<string, unknown> {
    expect(Boolean(result.isError)).toBe(false);
    expect(result.structuredContent).toBeDefined();
    return result.structuredContent!;
  }

  function denied(result: CallToolResult): void {
    expect(Boolean(result.isError)).toBe(true);
    expect(JSON.stringify(result.content)).toMatch(
      /Repository (?:boundary|metadata) denied|Path traversal detected|Restricted Git execution unavailable|Effective Git configuration.*authority/i,
    );
  }

  beforeAll(() => {
    expect(
      existsSync(bundle),
      'Build current checkout with bun run build before this suite.',
    ).toBe(true);
    bundleHash = createHash('sha256')
      .update(readFileSync(bundle))
      .digest('hex');
    temporary = realpathSync(
      mkdtempSync(join(tmpdir(), 'git-entrypoint-boundary-')),
    );
    first = join(temporary, 'root1');
    second = join(temporary, 'root2');
    outside = join(temporary, 'outside');
    home = join(temporary, 'home');
    for (const directory of [first, second, outside, home])
      mkdirSync(directory, { mode: 0o700 });
    writeFileSync(
      join(home, '.gitconfig'),
      '[user]\n name = Boundary Fixture\n email = boundary@example.test\n[commit]\n gpgSign = false\n[tag]\n gpgSign = false\n',
    );
    repo = join(first, 'repo');
    outsideRepo = join(outside, 'private-repo');
    createRepo(repo);
    createRepo(outsideRepo, 'outside-fixture');
    writeFileSync(join(outside, 'sentinel'), 'outside-unchanged');
    env = {
      PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
      HOME: home,
      NODE_ENV: 'test',
      MCP_TRANSPORT_TYPE: 'stdio',
      MCP_AUTH_MODE: 'none',
      MCP_LOG_LEVEL: 'error',
      OTEL_ENABLED: 'false',
      STORAGE_PROVIDER_TYPE: 'in-memory',
      GIT_BASE_DIR: `${first},${second}`,
      GIT_SIGN_COMMITS: 'false',
      GIT_EXECUTION_PROFILE: 'trusted',
      GIT_BINARY_PATH: '/usr/bin/git',
      GIT_TRUSTED_HOME: home,
      GIT_TRUSTED_PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
      GIT_MAX_COMMAND_TIMEOUT_MS: '10000',
    };
  });
  afterAll(() => {
    try {
      if (bundleHash)
        expect(
          createHash('sha256').update(readFileSync(bundle)).digest('hex'),
        ).toBe(bundleHash);
    } finally {
      if (temporary) rmSync(temporary, { recursive: true, force: true });
    }
  });

  it('preserves both roots, relative anchor, bare, clone/init and linked worktrees', async () => {
    const bare = join(second, 'bare.git');
    git(second, 'clone', '-q', '--bare', '--no-hardlinks', repo, bare);
    await withClient({}, async (client) => {
      expect(
        accepted(await request(client, 'git_set_working_dir', { path: 'repo' }))
          .path,
      ).toBe(repo);
      expect(
        accepted(await request(client, 'git_status', { path: '.' }))
          .currentBranch,
      ).toBe('main');
      expect(
        accepted(await request(client, 'git_log', { path: bare, maxCount: 1 }))
          .commits as unknown[],
      ).toHaveLength(1);
      const clone = join(second, 'clone');
      accepted(
        await request(client, 'git_clone', {
          url: pathToFileURL(repo).href,
          path: clone,
        }),
      );
      expect(git(clone, 'rev-parse', 'HEAD')).toBe(
        git(repo, 'rev-parse', 'HEAD'),
      );
      const initialized = join(second, 'new/nested');
      accepted(await request(client, 'git_init', { path: initialized }));
      expect(existsSync(join(initialized, '.git'))).toBe(true);
      const worktree = join(second, '-literal-worktree');
      accepted(
        await request(client, 'git_worktree', {
          path: repo,
          mode: 'add',
          worktreePath: worktree,
          detach: true,
        }),
      );
      accepted(await request(client, 'git_status', { path: worktree }));
      expect(realpathSync(join(worktree, '.git'))).toBe(join(worktree, '.git'));
      expect(
        git(
          worktree,
          'rev-parse',
          '--path-format=absolute',
          '--git-common-dir',
        ),
      ).toBe(join(repo, '.git'));
      accepted(
        await request(client, 'git_worktree', {
          path: repo,
          mode: 'remove',
          worktreePath: worktree,
        }),
      );
    });
  }, 30000);

  it('rejects symlink repositories and new leaves through either root before outside writes', async () => {
    for (const [index, root] of [first, second].entries()) {
      symlinkSync(outsideRepo, join(root, 'repo-link'));
      symlinkSync(outside, join(root, 'parent-link'));
      const before = treeHash(outside);
      await withClient({}, async (client) => {
        denied(
          await request(client, 'git_status', {
            path: join(root, 'repo-link'),
          }),
        );
        denied(
          await request(client, 'git_init', {
            path: join(root, 'parent-link', `init-${index}`),
          }),
        );
        denied(
          await request(client, 'git_clone', {
            url: repo,
            path: join(root, 'parent-link', `clone-${index}`),
          }),
        );
        denied(
          await request(client, 'git_worktree', {
            path: repo,
            mode: 'add',
            worktreePath: join(root, 'parent-link', `wt-${index}`),
            detach: true,
          }),
        );
      });
      expect(treeHash(outside)).toBe(before);
    }
  }, 30000);

  it('rejects sibling prefixes, dangling links, loops and configured root aliases', async () => {
    const sibling = `${first}-sibling`;
    createRepo(sibling);
    symlinkSync(join(outside, 'missing'), join(second, 'dangling'));
    symlinkSync('loop', join(second, 'loop'));
    const alias = join(temporary, 'root-alias');
    symlinkSync(outside, alias);
    const before = treeHash(outside);
    await withClient({}, async (client) => {
      denied(await request(client, 'git_status', { path: sibling }));
      denied(
        await request(client, 'git_init', {
          path: join(second, 'dangling/new'),
        }),
      );
      denied(
        await request(client, 'git_init', { path: join(second, 'loop/new') }),
      );
    });
    let connected = false;
    try {
      await withClient(
        { GIT_BASE_DIR: `${first},${alias}` },
        async (client) => {
          connected = true;
          denied(
            await request(client, 'git_status', {
              path: join(alias, 'private-repo'),
            }),
          );
        },
      );
    } catch (error) {
      // Invalid roots may fail startup. Never convert a failed tool assertion
      // after a successful connection into a false-positive startup denial.
      if (connected) throw error;
      expect(error).toBeInstanceOf(Error);
    }
    expect(treeHash(outside)).toBe(before);
  }, 30000);

  it('stops ancestor discovery and hard reset at a configured subdirectory', async () => {
    const ancestor = join(temporary, 'ancestor');
    createRepo(ancestor, 'feature');
    const allowed = join(ancestor, 'allowed');
    mkdirSync(allowed);
    writeFileSync(join(ancestor, 'payload.txt'), 'outside-worktree-dirty');
    const before = treeHash(ancestor);
    await withClient({ GIT_BASE_DIR: allowed }, async (client) => {
      denied(
        await request(client, 'git_reset', {
          path: allowed,
          mode: 'hard',
          confirmed: true,
        }),
      );
    });
    expect(treeHash(ancestor)).toBe(before);
  }, 30000);

  it('rejects gitdir/common/worktree/index/alternates metadata escapes', async () => {
    const pointer = join(second, 'pointer');
    mkdirSync(pointer);
    writeFileSync(
      join(pointer, '.git'),
      `gitdir: ${join(outsideRepo, '.git')}\n`,
    );
    const before = treeHash(outside);
    await withClient({}, async (client) => {
      denied(await request(client, 'git_status', { path: pointer }));
      for (const kind of ['commondir', 'worktree', 'index', 'alternates']) {
        const target = join(first, `metadata-${kind}`);
        git(first, 'clone', '-q', '--no-hardlinks', repo, target);
        const admin = join(target, '.git');
        if (kind === 'commondir')
          writeFileSync(
            join(admin, 'commondir'),
            `${join(outsideRepo, '.git')}\n`,
          );
        if (kind === 'worktree')
          git(target, 'config', 'core.worktree', outsideRepo);
        if (kind === 'index') {
          rmSync(join(admin, 'index'));
          symlinkSync(join(outsideRepo, '.git/index'), join(admin, 'index'));
        }
        if (kind === 'alternates')
          writeFileSync(
            join(admin, 'objects/info/alternates'),
            `${join(outsideRepo, '.git/objects')}\n`,
          );
        denied(await request(client, 'git_log', { path: target, maxCount: 1 }));
      }
    });
    expect(treeHash(outside)).toBe(before);
  }, 30000);

  it('allows authorized cross-root local fetch and push with actual object/ref receipts', async () => {
    const receiver = join(first, 'allowed-receiver');
    mkdirSync(receiver);
    git(receiver, 'init', '-q', '--initial-branch=main');
    const target = join(second, 'allowed-push.git');
    git(second, 'init', '-q', '--bare', target);
    const before = treeHash(outside);
    await withClient({}, async (client) => {
      accepted(
        await request(client, 'git_remote', {
          path: receiver,
          mode: 'add',
          name: 'local',
          url: repo,
        }),
      );
      accepted(
        await request(client, 'git_fetch', { path: receiver, remote: 'local' }),
      );
      expect(git(receiver, 'rev-parse', 'refs/remotes/local/main')).toBe(
        git(repo, 'rev-parse', 'HEAD'),
      );
      accepted(
        await request(client, 'git_remote', {
          path: repo,
          mode: 'add',
          name: 'inside-push',
          url: target,
        }),
      );
      accepted(
        await request(client, 'git_push', {
          path: repo,
          remote: 'inside-push',
          branch: 'main',
          remoteBranch: 'feature',
        }),
      );
      expect(git(target, 'rev-parse', 'refs/heads/feature')).toBe(
        git(repo, 'rev-parse', 'HEAD'),
      );
    });
    expect(treeHash(outside)).toBe(before);
  }, 30000);

  it('rejects outside add/set-url and stored effective fetch rewrites before objects transfer', async () => {
    const receiver = join(first, 'denied-receiver');
    mkdirSync(receiver);
    git(receiver, 'init', '-q', '--initial-branch=main');
    await withClient({}, async (client) => {
      const initialConfig = readFileSync(join(receiver, '.git/config'), 'utf8');
      denied(
        await request(client, 'git_remote', {
          path: receiver,
          mode: 'add',
          name: 'outside',
          url: outsideRepo,
        }),
      );
      expect(readFileSync(join(receiver, '.git/config'), 'utf8')).toBe(
        initialConfig,
      );
      accepted(
        await request(client, 'git_remote', {
          path: receiver,
          mode: 'add',
          name: 'origin',
          url: repo,
        }),
      );
      const allowedConfig = readFileSync(join(receiver, '.git/config'), 'utf8');
      denied(
        await request(client, 'git_remote', {
          path: receiver,
          mode: 'set-url',
          name: 'origin',
          url: pathToFileURL(outsideRepo).href,
        }),
      );
      expect(readFileSync(join(receiver, '.git/config'), 'utf8')).toBe(
        allowedConfig,
      );
      for (const source of [
        outsideRepo,
        pathToFileURL(outsideRepo).href,
        pathToFileURL(outsideRepo).href.replace(/^file:/, 'FILE:'),
      ]) {
        git(receiver, 'remote', 'set-url', 'origin', source);
        const before = treeHash(join(receiver, '.git'));
        denied(
          await request(client, 'git_fetch', {
            path: receiver,
            remote: 'origin',
          }),
        );
        expect(treeHash(join(receiver, '.git'))).toBe(before);
      }
      const alias = join(first, 'local-alias');
      git(receiver, 'remote', 'set-url', 'origin', alias);
      git(receiver, 'config', `url.${outsideRepo}.insteadOf`, alias);
      const before = treeHash(join(receiver, '.git'));
      denied(
        await request(client, 'git_fetch', {
          path: receiver,
          remote: 'origin',
        }),
      );
      expect(treeHash(join(receiver, '.git'))).toBe(before);
    });
  }, 30000);

  it('checks trusted global/includeIf rewrites and effective worktree before native operations', async () => {
    const receiver = join(first, 'global-receiver');
    git(first, 'clone', '-q', '--no-hardlinks', repo, receiver);
    const alias = join(first, 'global-local-alias');
    git(receiver, 'remote', 'set-url', 'origin', alias);
    const globalConfig = join(home, '.gitconfig');
    const original = readFileSync(globalConfig, 'utf8');
    const rewrite = `[url "${outsideRepo}"]\n insteadOf = ${alias}\n`;
    const included = join(home, 'included-config');
    writeFileSync(included, rewrite);
    const before = treeHash(outside);
    try {
      for (const extra of [
        rewrite,
        `[includeIf "gitdir:${receiver}/.git/"]\n path = ${included}\n`,
      ]) {
        writeFileSync(globalConfig, original + extra);
        const objects = treeHash(join(receiver, '.git'));
        await withClient({}, async (client) => {
          denied(
            await request(client, 'git_fetch', {
              path: receiver,
              remote: 'origin',
            }),
          );
          expect(treeHash(join(receiver, '.git'))).toBe(objects);
        });
      }
      writeFileSync(globalConfig, original);
      git(receiver, 'remote', 'set-url', 'origin', repo);
      writeFileSync(
        globalConfig,
        original + `[core]\n worktree = ${outsideRepo}\n`,
      );
      await withClient({}, async (client) => {
        denied(await request(client, 'git_status', { path: receiver }));
      });
    } finally {
      writeFileSync(globalConfig, original);
    }
    expect(treeHash(outside)).toBe(before);
  }, 30000);

  it('rejects separate outside push URLs and multiple URLs without changing refs or objects', async () => {
    const sender = join(first, 'denied-sender');
    git(first, 'clone', '-q', '--no-hardlinks', repo, sender);
    const foreign = join(outside, 'push.git');
    git(outside, 'init', '-q', '--bare', foreign);
    git(sender, 'remote', 'set-url', '--push', 'origin', foreign);
    const before = treeHash(foreign);
    await withClient({}, async (client) => {
      denied(
        await request(client, 'git_push', {
          path: sender,
          remote: 'origin',
          branch: 'main',
          remoteBranch: 'feature',
        }),
      );
      expect(treeHash(foreign)).toBe(before);
      git(sender, 'config', '--unset-all', 'remote.origin.pushurl');
      git(sender, 'config', '--add', 'remote.origin.url', outsideRepo);
      const objects = treeHash(join(sender, '.git'));
      denied(
        await request(client, 'git_fetch', { path: sender, remote: 'origin' }),
      );
      expect(treeHash(join(sender, '.git'))).toBe(objects);
    });
  }, 30000);

  it('revalidates persisted cwd for status and wrapup after roots narrow on restart', async () => {
    const cached = join(second, 'cached');
    git(second, 'clone', '-q', '--no-hardlinks', repo, cached);
    const stored = {
      STORAGE_PROVIDER_TYPE: 'filesystem',
      STORAGE_FILESYSTEM_PATH: join(temporary, 'context-store'),
    };
    await withClient(stored, async (client) => {
      accepted(await request(client, 'git_set_working_dir', { path: cached }));
      expect(
        accepted(
          await request(client, 'git_wrapup_instructions', {
            acknowledgement: 'yes',
          }),
        ).repository,
      ).toBeDefined();
    });
    const before = treeHash(cached);
    await withClient({ ...stored, GIT_BASE_DIR: first }, async (client) => {
      denied(await request(client, 'git_status', { path: '.' }));
      const wrapup = await request(client, 'git_wrapup_instructions', {
        acknowledgement: 'yes',
      });
      denied(wrapup);
      expect(wrapup.structuredContent?.repository).toBeUndefined();
    });
    expect(treeHash(cached)).toBe(before);
  }, 30000);

  it('strips inherited Git routing instead of selecting the outside repository', async () => {
    const before = treeHash(outside);
    await withClient(
      {
        GIT_DIR: join(outsideRepo, '.git'),
        GIT_WORK_TREE: outsideRepo,
        GIT_COMMON_DIR: join(outsideRepo, '.git'),
        GIT_INDEX_FILE: join(outsideRepo, '.git/index'),
      },
      async (client) => {
        expect(
          accepted(await request(client, 'git_status', { path: repo }))
            .currentBranch,
        ).toBe('main');
      },
    );
    expect(treeHash(outside)).toBe(before);
  }, 30000);

  it('fails closed in default restricted profile before init or clone creates a leaf', async () => {
    const parent = join(second, 'raced-parent');
    const parked = join(second, 'raced-parent-parked');
    mkdirSync(parent);
    const initialized = join(parent, 'restricted-init');
    const cloned = join(parent, 'restricted-clone');
    const before = treeHash(outside);
    let linked = false;
    const swap = setInterval(() => {
      if (linked) {
        unlinkSync(parent);
        renameSync(parked, parent);
      } else {
        renameSync(parent, parked);
        symlinkSync(outside, parent);
      }
      linked = !linked;
    }, 2);
    try {
      await withClient(
        {},
        async (client) => {
          const init = await request(client, 'git_init', { path: initialized });
          expect(existsSync(initialized)).toBe(false);
          denied(init);
          denied(
            await request(client, 'git_clone', { url: repo, path: cloned }),
          );
          expect(existsSync(cloned)).toBe(false);
        },
        true,
      );
    } finally {
      clearInterval(swap);
      if (linked) {
        unlinkSync(parent);
        renameSync(parked, parent);
      }
    }
    expect(treeHash(outside)).toBe(before);
  }, 30000);
});
