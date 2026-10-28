/**
 * @fileoverview Multi-root checks through a separate stdio server and temp repos.
 * @module tests/mcp-server/transports/stdio/multi-root.e2e.test
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

describe('stdio multi-root paths', () => {
  let root: string;
  let first: string;
  let second: string;
  let repo: string;
  let client: Client;
  let env: Record<string, string>;

  function git(args: string[], cwd: string): void {
    const result = Bun.spawnSync(['git', ...args], { cwd, env });
    if (result.exitCode !== 0) throw new Error(result.stderr.toString());
  }
  async function call(
    name: string,
    args: Record<string, unknown>,
    fails = false,
  ) {
    const result = await client.callTool({ name, arguments: args });
    expect(Boolean(result.isError), JSON.stringify(result.content)).toBe(fails);
    if (fails)
      expect(JSON.stringify(result.content)).toContain('Path traversal');
    return result.structuredContent as Record<string, unknown>;
  }
  beforeAll(async () => {
    root = realpathSync(mkdtempSync(join(tmpdir(), 'git-mcp-roots-')));
    first = join(root, 'repos');
    second = join(root, 'worktrees');
    repo = join(first, 'repo');
    mkdirSync(repo, { recursive: true });
    mkdirSync(second);
    const globalConfig = join(root, 'gitconfig');
    writeFileSync(
      globalConfig,
      '[user]\n name = Fixture\n email = fixture@example.com\n[commit]\n gpgSign = false\n[tag]\n gpgSign = false\n',
    );
    env = {
      ...(process.env as Record<string, string>),
      NODE_ENV: 'test',
      GIT_CONFIG_GLOBAL: globalConfig,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_SIGN_COMMITS: 'false',
      GIT_BASE_DIR: ` ${first}, ${second} `,
      MCP_TRANSPORT_TYPE: 'stdio',
      STORAGE_PROVIDER_TYPE: 'in-memory',
      MCP_LOG_LEVEL: 'error',
      OTEL_ENABLED: 'false',
    };
    git(['init', '-q', '-b', 'main'], repo);
    writeFileSync(join(repo, 'base.txt'), 'fixture\n');
    git(['add', 'base.txt'], repo);
    git(['commit', '-q', '-m', 'fixture'], repo);
    client = new Client({ name: 'multi-root-fixture', version: '0.0.0' });
    await client.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [join(process.cwd(), 'dist/index.js')],
        cwd: root,
        env,
        stderr: 'pipe',
      }),
    );
  }, 30_000);
  afterAll(async () => {
    await client?.close();
    if (root) rmSync(root, { recursive: true, force: true });
  });

  it('sets a relative repository against the first root and reuses it', async () => {
    const result = await call('git_set_working_dir', { path: 'repo' });
    expect(result.path).toBe(repo);
    await call('git_status', { path: '.' });
  });
  it('rejects outside, traversal and prefix collisions', async () => {
    for (const path of [root, '../outside', `${first}-other/repo`])
      await call('git_status', { path }, true);
  });
  it('checks set-working-dir before initialization outside roots', async () => {
    const path = join(root, 'forbidden-init');
    await call(
      'git_set_working_dir',
      { path, initializeIfNotPresent: true },
      true,
    );
    expect(existsSync(path)).toBe(false);
    await call('git_status', { path: '.' });
  });
  it('allows a clone across roots, and rejects forbidden local sources/destinations', async () => {
    await call('git_clone', { url: repo, path: join(second, 'clone') });
    await call('git_status', { path: join(second, 'clone') });
    await call(
      'git_clone',
      { url: repo, path: join(root, 'forbidden-clone') },
      true,
    );
    await call(
      'git_clone',
      { url: root, path: join(second, 'forbidden-source') },
      true,
    );
    await call(
      'git_clone',
      {
        url: pathToFileURL(root).href,
        path: join(second, 'forbidden-file-source'),
      },
      true,
    );
    await call(
      'git_clone',
      {
        url: pathToFileURL(root).href.replace(/^file:/, 'FILE:'),
        path: join(second, 'forbidden-uppercase-source'),
      },
      true,
    );
    expect(existsSync(join(root, 'forbidden-clone'))).toBe(false);
    expect(existsSync(join(second, 'forbidden-source'))).toBe(false);
  });
  it('allows creation in the second root without requiring the path to exist', async () => {
    await call('git_init', { path: join(second, 'new-repo') });
    expect(existsSync(join(second, 'new-repo', '.git'))).toBe(true);
  });
  it('supports linked worktrees sharing metadata in another allowed root', async () => {
    const wt = join(second, 'linked');
    await call('git_worktree', {
      path: repo,
      mode: 'add',
      worktreePath: wt,
      detach: true,
    });
    await call('git_status', { path: wt });
    await call(
      'git_worktree',
      {
        path: repo,
        mode: 'move',
        worktreePath: wt,
        newPath: join(root, 'forbidden-move'),
      },
      true,
    );
    expect(existsSync(wt)).toBe(true);
    await call('git_worktree', {
      path: repo,
      mode: 'remove',
      worktreePath: wt,
    });
  });
  it('rejects additional worktree paths outside roots', async () => {
    const outside = join(root, 'forbidden-worktree');
    await call(
      'git_worktree',
      { path: repo, mode: 'add', worktreePath: outside, detach: true },
      true,
    );
    await call(
      'git_worktree',
      { path: repo, mode: 'remove', worktreePath: outside },
      true,
    );
    expect(existsSync(outside)).toBe(false);
  });
  it('preserves unrestricted relative clone and set-working-dir paths when unset', async () => {
    const legacyEnv = { ...env };
    delete legacyEnv.GIT_BASE_DIR;
    const legacy = new Client({
      name: 'unset-roots-fixture',
      version: '0.0.0',
    });
    try {
      await legacy.connect(
        new StdioClientTransport({
          command: process.execPath,
          args: [join(process.cwd(), 'dist/index.js')],
          cwd: second,
          env: legacyEnv,
          stderr: 'pipe',
        }),
      );
      const clone = await legacy.callTool({
        name: 'git_clone',
        arguments: { url: repo, path: '../legacy-clone' },
      });
      expect(Boolean(clone.isError), JSON.stringify(clone.content)).toBe(false);
      expect((clone.structuredContent as Record<string, unknown>).path).toBe(
        join(root, 'legacy-clone'),
      );
      const selected = await legacy.callTool({
        name: 'git_set_working_dir',
        arguments: { path: '../repos/repo' },
      });
      expect(Boolean(selected.isError), JSON.stringify(selected.content)).toBe(
        false,
      );
      expect((selected.structuredContent as Record<string, unknown>).path).toBe(
        repo,
      );
    } finally {
      await legacy.close();
    }
  }, 30_000);
  it('revalidates a persisted cwd after a root is removed', async () => {
    const storedEnv = {
      ...env,
      STORAGE_PROVIDER_TYPE: 'filesystem',
      STORAGE_FILESYSTEM_PATH: join(root, 'context-store'),
    };
    const writer = new Client({ name: 'cached-cwd-writer', version: '0.0.0' });
    const reader = new Client({ name: 'cached-cwd-reader', version: '0.0.0' });
    const transport = (environment: Record<string, string>) =>
      new StdioClientTransport({
        command: process.execPath,
        args: [join(process.cwd(), 'dist/index.js')],
        cwd: root,
        env: environment,
        stderr: 'pipe',
      });
    try {
      await writer.connect(transport(storedEnv));
      const selected = await writer.callTool({
        name: 'git_set_working_dir',
        arguments: { path: join(second, 'clone') },
      });
      expect(Boolean(selected.isError), JSON.stringify(selected.content)).toBe(
        false,
      );
    } finally {
      await writer.close();
    }
    try {
      await reader.connect(transport({ ...storedEnv, GIT_BASE_DIR: first }));
      const status = await reader.callTool({
        name: 'git_status',
        arguments: { path: '.' },
      });
      expect(Boolean(status.isError)).toBe(true);
      expect(JSON.stringify(status.content)).toContain('Path traversal');
    } finally {
      await reader.close();
    }
  }, 30_000);
});
