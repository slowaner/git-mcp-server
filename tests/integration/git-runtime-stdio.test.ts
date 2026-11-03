/**
 * @fileoverview Built-server STDIO Git execution-profile acceptance.
 * @module tests/integration/git-runtime-stdio.test
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

describe('source-built STDIO runtime policy', { timeout: 20000 }, () => {
  let directory: string;
  let home: string;
  const clients: Client[] = [];
  beforeEach(async () => {
    directory = await mkdtemp(path.join(tmpdir(), 'git-runtime-stdio-'));
    home = path.join(directory, 'home');
    await mkdir(home);
    await writeFile(
      path.join(home, '.gitconfig'),
      '[user]\n name = STDIO Fixture\n email = stdio@example.invalid\n[commit]\n gpgsign = false\n',
    );
    execFileSync('/usr/bin/git', ['init', '--quiet'], {
      cwd: directory,
      env: { HOME: home, PATH: '/usr/bin:/bin' },
    });
  });
  afterEach(async () => {
    await Promise.all(clients.splice(0).map((client) => client.close()));
    await rm(directory, { recursive: true, force: true });
  });
  const connect = async (
    extra: Record<string, string> = {},
    command = process.execPath,
  ) => {
    const transport = new StdioClientTransport({
      command,
      args: [path.resolve('dist/index.js')],
      cwd: directory,
      env: {
        PATH: '/usr/bin:/bin',
        HOME: home,
        NODE_ENV: 'test',
        MCP_TRANSPORT_TYPE: 'stdio',
        MCP_AUTH_MODE: 'none',
        MCP_LOG_LEVEL: 'error',
        OTEL_ENABLED: 'false',
        STORAGE_PROVIDER_TYPE: 'in-memory',
        GIT_BINARY_PATH: '/usr/bin/git',
        GIT_TRUSTED_HOME: home,
        GIT_TRUSTED_PATH: '/usr/bin:/bin',
        GIT_BASE_DIR: directory,
        GIT_SIGN_COMMITS: 'false',
        ...extra,
      },
      stderr: 'pipe',
    });
    // Continuously drain server diagnostics without retaining payloads.
    transport.stderr?.on('data', () => {});
    const client = new Client({ name: 'runtime-acceptance', version: '1.0.0' });
    clients.push(client);
    await client.connect(transport);
    return client;
  };
  it('default restricted rejects before init destination creation and repository hooks/config', async () => {
    const hook = path.join(directory, 'malicious-helper');
    await writeFile(
      hook,
      '#!/bin/sh\nprintf executed > "' +
        path.join(directory, 'executed') +
        '"\n',
    );
    await chmod(hook, 0o700);
    execFileSync('/usr/bin/git', ['config', 'core.fsmonitor', hook], {
      cwd: directory,
      env: { HOME: home, PATH: '/usr/bin:/bin' },
    });
    const client = await connect();
    const destination = path.join(directory, 'must-not-exist');
    const result = await client.callTool({
      name: 'git_init',
      arguments: { path: destination },
    });
    assert.equal(result.isError, true);
    assert.match(
      JSON.stringify(result.content),
      /sandbox|restricted|unsupported/i,
    );
    await assert.rejects(stat(destination), { code: 'ENOENT' });
    const status = await client.callTool({
      name: 'git_status',
      arguments: { path: directory },
    });
    assert.equal(status.isError, true);
    await assert.rejects(readFile(path.join(directory, 'executed')));
  });
  it('explicit trusted opt-in permits ordinary status with controlled Git', async () => {
    const client = await connect({ GIT_EXECUTION_PROFILE: 'trusted' });
    const result = await client.callTool({
      name: 'git_status',
      arguments: { path: directory },
    });
    assert.notEqual(result.isError, true, JSON.stringify(result.content));
    assert.ok(result.structuredContent);
  });
  it('canonical Node entrypoint ignores repository .env authority before filesystem operations', async () => {
    await writeFile(
      path.join(directory, '.env'),
      'GIT_EXECUTION_PROFILE=trusted\nGIT_BINARY_PATH=/bin/echo\nGIT_BASE_DIR=/\n',
    );
    const nodeExecutable = execFileSync('node', ['-p', 'process.execPath'], {
      encoding: 'utf8',
    }).trim();
    const client = await connect({}, nodeExecutable);
    const destination = path.join(directory, 'dotenv-must-not-create');
    const result = await client.callTool({
      name: 'git_init',
      arguments: { path: destination },
    });
    assert.equal(result.isError, true);
    assert.match(
      JSON.stringify(result.content),
      /sandbox|restricted|unsupported/i,
    );
    await assert.rejects(stat(destination), { code: 'ENOENT' });
  });
  it('built server rejects invalid blob output without formatting a success', async () => {
    const file = path.join(directory, 'invalid-blob');
    await writeFile(file, Buffer.from([0xff]));
    const hash = execFileSync('/usr/bin/git', ['hash-object', '-w', file], {
      cwd: directory,
      env: { HOME: home, PATH: '/usr/bin:/bin' },
      encoding: 'utf8',
    }).trim();
    const client = await connect({ GIT_EXECUTION_PROFILE: 'trusted' });
    const result = await client.callTool({
      name: 'git_show',
      arguments: { path: directory, object: hash },
    });
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent, undefined);
    assert.match(JSON.stringify(result.content), /UTF-8/);
  });
});
