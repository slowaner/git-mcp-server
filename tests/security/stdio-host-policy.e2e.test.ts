/**
 * @fileoverview Built STDIO entrypoint preserves explicit host authority with HTTP auth enabled.
 * @module tests/security/stdio-host-policy.e2e
 */
import { expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

it('uses server-owned STDIO authority without an HTTP token or tenant fallback', async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'stdio-host-policy-')));
  const home = join(root, 'home');
  const repo = join(root, 'repo');
  mkdirSync(home);
  execFileSync('/usr/bin/git', [
    '-c',
    'core.hooksPath=/dev/null',
    'init',
    '-q',
    repo,
  ]);
  const client = new Client({ name: 'host-policy-fixture', version: '1' });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [join(process.cwd(), 'dist/index.js')],
    cwd: root,
    env: {
      PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
      HOME: home,
      NODE_ENV: 'test',
      MCP_TRANSPORT_TYPE: 'stdio',
      MCP_AUTH_MODE: 'jwt',
      MCP_AUTH_SECRET_KEY: 'synthetic-stdio-jwt-fixture-'.repeat(3),
      MCP_AUTH_ISSUER: 'https://issuer.example.test',
      MCP_AUTH_AUDIENCE: 'git-fixture',
      STORAGE_PROVIDER_TYPE: 'in-memory',
      GIT_BASE_DIR: root,
      GIT_EXECUTION_PROFILE: 'trusted',
      GIT_BINARY_PATH: '/usr/bin/git',
      GIT_TRUSTED_HOME: home,
      GIT_TRUSTED_PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
      OTEL_ENABLED: 'false',
      MCP_LOG_LEVEL: 'error',
    },
    stderr: 'pipe',
  });
  transport.stderr?.on('data', () => {});
  try {
    await client.connect(transport);
    const selected = await client.callTool({
      name: 'git_set_working_dir',
      arguments: { path: repo },
    });
    expect(selected.isError).not.toBe(true);
    const status = await client.callTool({
      name: 'git_status',
      arguments: { path: '.' },
    });
    expect(status.isError).not.toBe(true);
    const resource = await client.readResource({
      uri: 'git://working-directory',
    });
    expect(
      JSON.parse((resource.contents[0] as { text: string }).text)
        .workingDirectory,
    ).toBe(repo);
  } finally {
    await client.close();
    rmSync(root, { recursive: true, force: true });
  }
}, 30000);
