/**
 * @fileoverview Real HTTP/SDK identity, repository and session isolation regressions.
 * @module tests/security/auth-sessions.integration
 */
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SignJWT } from 'jose';
import { container } from 'tsyringe';
import {
  mkdirSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { config } from '@/config/index.js';
import {
  AppConfig,
  Logger,
  StorageService as StorageToken,
  GitProviderFactory as FactoryToken,
} from '@/container/tokens.js';
import { logger, requestContextService } from '@/utils/index.js';
import {
  createHttpApp,
  closeHttpApp,
} from '@/mcp-server/transports/http/httpTransport.js';
import { SessionManager } from '@/mcp-server/transports/http/sessionManager.js';
import { createMcpToolHandler } from '@/mcp-server/tools/utils/toolHandlerFactory.js';
import { allToolDefinitions } from '@/mcp-server/tools/definitions/index.js';
import type { ToolDefinition } from '@/mcp-server/tools/utils/toolDefinition.js';
import { z } from 'zod';
import { CliGitProvider } from '@/services/git/providers/cli/CliGitProvider.js';
import { StorageService } from '@/storage/core/StorageService.js';
import { InMemoryProvider } from '@/storage/providers/inMemory/inMemoryProvider.js';
import {
  currentPrincipal,
  currentServerSessionId,
} from '@/mcp-server/transports/auth/lib/requestIdentity.js';
import { gitWorkingDirectoryResource } from '@/mcp-server/resources/definitions/git-working-directory.resource.js';

const suite = process.env.INTEGRATION === '1' ? describe : describe.skip;
suite('authenticated actual HTTP session and repository isolation', () => {
  const original = { ...config, git: { ...config.git } };
  const secret = 'synthetic-http-fixture-material-'.repeat(3);
  const issuer = 'https://issuer.example.test';
  const audience = 'git-http-fixture';
  const provider = new CliGitProvider();
  const storage = new StorageService(new InMemoryProvider());
  const remotes = vi.spyOn(provider, 'remote');
  let dir: string;
  let first: string;
  let second: string;
  let other: string;
  let app: ReturnType<typeof createHttpApp>;
  let makeServer: () => Promise<McpServer>;
  let ActualMcpServer = McpServer;
  let factories = 0;
  let dispatches = 0;
  const headers = {
    host: 'localhost:3015',
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
  };
  const init = {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'fixture', version: '1' },
    },
  };
  const claims = (
    subject = 'alice',
    tenant = 'tenant-a',
    client = 'client-a',
  ) => ({
    iss: issuer,
    aud: audience,
    sub: subject,
    tid: tenant,
    cid: client,
    scope: 'tool:git:read tool:git:write resource:git:read',
  });
  async function token(overrides: Record<string, unknown> = {}) {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ ...claims(), iat: now, exp: now + 120, ...overrides })
      .setProtectedHeader({ alg: 'HS256' })
      .sign(new TextEncoder().encode(secret));
  }
  async function request(
    auth: string,
    sid?: string,
    method = 'POST',
    body: unknown = { jsonrpc: '2.0', id: 7, method: 'ping' },
  ) {
    return app.request('http://localhost:3015/mcp', {
      method,
      headers: {
        ...headers,
        authorization: `Bearer ${auth}`,
        ...(sid ? { 'mcp-session-id': sid } : {}),
        ...(method === 'GET' && sid ? { accept: 'text/event-stream' } : {}),
      },
      ...(method === 'POST' ? { body: JSON.stringify(body) } : {}),
    });
  }
  async function initialize(auth: string) {
    const response = await request(auth, undefined, 'POST', init);
    const payload = await response.json();
    expect(response.status, JSON.stringify(payload)).toBe(200);
    const sid = response.headers.get('mcp-session-id')!;
    expect(sid).toMatch(/^[a-f0-9-]{36}$/);
    const ready = await request(auth, sid, 'POST', {
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    });
    expect(ready.status).toBe(202);
    await ready.text();
    return sid;
  }
  async function call(
    auth: string,
    sid: string,
    name: string,
    args: Record<string, unknown>,
  ) {
    const response = await request(auth, sid, 'POST', {
      jsonrpc: '2.0',
      id: 7,
      method: 'tools/call',
      params: { name, arguments: args },
    });
    expect(response.status).toBe(200);
    return (
      (await response.json()) as {
        result: {
          isError?: boolean;
          structuredContent?: Record<string, unknown>;
          content: unknown;
        };
      }
    ).result;
  }
  function accepted(result: Awaited<ReturnType<typeof call>>) {
    expect(result.isError, JSON.stringify(result.content)).not.toBe(true);
    return result.structuredContent!;
  }
  beforeAll(async () => {
    // Vitest hoists the baseline setup mock even inside its INTEGRATION guard.
    // Qualify the actual SDK only for this fixture, without changing global setup.
    if (!process.versions.bun)
      ActualMcpServer = (
        await vi.importActual<
          typeof import('@modelcontextprotocol/sdk/server/mcp.js')
        >('@modelcontextprotocol/sdk/server/mcp.js')
      ).McpServer;
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'auth-session-http-')));
    first = join(dir, 'alice');
    second = join(dir, 'bob');
    other = join(first, 'other');
    for (const root of [first, second, other]) {
      mkdirSync(root, { recursive: true });
      execFileSync('/usr/bin/git', [
        '-c',
        'core.hooksPath=/dev/null',
        'init',
        '-q',
        root,
      ]);
      writeFileSync(join(root, 'sentinel'), 'unchanged');
    }
    Object.assign(config, {
      mcpTransportType: 'http',
      mcpAuthMode: 'jwt',
      mcpAuthSecretKey: secret,
      mcpAuthIssuer: issuer,
      mcpAuthAudience: audience,
      mcpAuthMaxTokenLifetimeSeconds: 3600,
      mcpAuthClockToleranceSeconds: 0,
      mcpRepositoryGrants: JSON.stringify([
        {
          issuer,
          tenantId: 'tenant-a',
          clientId: 'client-a',
          subject: 'alice',
          roots: [first],
        },
        {
          issuer,
          tenantId: 'tenant-a',
          clientId: 'client-a',
          subject: 'bob',
          roots: [second],
        },
        {
          issuer,
          tenantId: 'tenant-b',
          clientId: 'client-a',
          subject: 'alice',
          roots: [second],
        },
        {
          issuer,
          tenantId: 'tenant-a',
          clientId: 'client-b',
          subject: 'alice',
          roots: [second],
        },
      ]),
      httpSecurity: {
        ...config.httpSecurity,
        maxSessions: 20,
        maxSessionsPerPrincipal: 8,
        maxStreamsPerPrincipal: 2,
      },
      git: {
        ...config.git,
        executionProfile: 'trusted',
        baseDirs: [first, second],
      },
    });
    container.registerInstance(AppConfig, config);
    container.registerInstance(Logger, logger);
    container.registerInstance(StorageToken, storage);
    container.registerInstance(FactoryToken, {
      getProvider: async () => provider,
    });
    makeServer = async () => {
      factories++;
      const server = new ActualMcpServer({
        name: 'actual-auth-fixture',
        version: '1',
      });
      for (const definition of allToolDefinitions as ToolDefinition<
        z.ZodObject,
        z.ZodObject
      >[])
        server.registerTool(
          definition.name,
          { inputSchema: definition.inputSchema },
          createMcpToolHandler({
            toolName: definition.name,
            inputSchema: definition.inputSchema,
            logic: definition.logic,
            ...(definition.responseFormatter
              ? { responseFormatter: definition.responseFormatter }
              : {}),
          }),
        );
      server.registerResource(
        'cwd',
        'git://working-directory',
        {},
        async (uri) => {
          const result = await gitWorkingDirectoryResource.logic(
            uri,
            {},
            requestContextService.createRequestContext(),
          );
          return {
            contents: [
              {
                uri: uri.href,
                mimeType: 'application/json',
                text: JSON.stringify(result),
              },
            ],
          };
        },
      );
      server.registerTool('identity_probe', {}, async () => {
        dispatches++;
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                principal: currentPrincipal(),
                sessionId: currentServerSessionId(),
              }),
            },
          ],
        };
      });
      return server;
    };
    app = createHttpApp(
      makeServer,
      requestContextService.createRequestContext({
        operation: 'auth-http-fixture',
      }),
    );
  });
  afterAll(async () => {
    if (app) await closeHttpApp(app);
    remotes.mockRestore();
    Object.assign(config, original);
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('rejects wrong authority, lifetime, missing tenant/subject/client and unknown grant before factory', async () => {
    const before = factories;
    for (const overrides of [
      { tid: undefined },
      { sub: undefined },
      { cid: undefined },
      { exp: undefined },
      { iat: undefined },
      { aud: 'wrong' },
      { iss: 'https://wrong.example.test' },
      { exp: Math.floor(Date.now() / 1000) - 10 },
      { sub: 'ungranted' },
    ]) {
      const response = await request(
        await token(overrides),
        undefined,
        'POST',
        init,
      );
      expect([401, 403]).toContain(response.status);
      await response.text();
    }
    expect(factories).toBe(before);
  });

  it('checks complete owner tuple before touch, expiry cleanup, lease and dispatch on all methods', async () => {
    const alice = await token();
    const sid = await initialize(alice);
    const touch = vi.spyOn(SessionManager.prototype, 'touchSession');
    const valid = vi.spyOn(SessionManager.prototype, 'isSessionValid');
    const terminate = vi.spyOn(SessionManager.prototype, 'terminateSession');
    try {
      for (const foreign of [
        await token({ sub: 'bob' }),
        await token({ tid: 'tenant-b' }),
        await token({ cid: 'client-b' }),
      ]) {
        for (const method of ['GET', 'POST', 'DELETE']) {
          const response = await request(foreign, sid, method, {
            jsonrpc: '2.0',
            id: 7,
            method: 'tools/call',
            params: { name: 'identity_probe' },
          });
          expect(response.status).toBe(404);
          await response.text();
        }
      }
      expect(touch).not.toHaveBeenCalled();
      expect(valid).not.toHaveBeenCalled();
      expect(terminate).not.toHaveBeenCalled();
      expect(dispatches).toBe(0);
    } finally {
      touch.mockRestore();
      valid.mockRestore();
      terminate.mockRestore();
    }
    const refreshed = await token({ jti: 'new-token' });
    const ping = await request(refreshed, sid);
    expect(ping.status).toBe(200);
    await ping.text();
    const stream = await request(refreshed, sid, 'GET');
    expect(stream.status).toBe(200);
    await stream.body!.cancel();
    const streamAgain = await request(refreshed, sid, 'GET');
    expect(streamAgain.status).toBe(200);
    await streamAgain.body!.cancel();
    const deleted = await request(refreshed, sid, 'DELETE');
    expect(deleted.status).toBe(200);
    await deleted.text();
    const gone = await request(alice, sid);
    expect(gone.status).toBe(404);
    await gone.text();
  });

  it('equal RPC ids on concurrent sessions keep distinct owners and correlations', async () => {
    const alice = await token();
    const bob = await token({ sub: 'bob' });
    const a = await initialize(alice);
    const b = await initialize(bob);
    const [one, two] = await Promise.all([
      call(alice, a, 'identity_probe', {}),
      call(bob, b, 'identity_probe', {}),
    ]);
    const identity = (result: typeof one) =>
      JSON.parse((result.content as { text: string }[])[0]!.text);
    expect(identity(one).principal.subject).toBe('alice');
    expect(identity(one).sessionId).toBe(a);
    expect(identity(two).principal.subject).toBe('bob');
    expect(identity(two).sessionId).toBe(b);
  });

  it('read scope cannot mutate any remote mode; repository config and provider remain untouched', async () => {
    const read = await token({ scope: 'tool:git:read' });
    const sid = await initialize(read);
    const before = readFileSync(join(first, '.git/config'), 'utf8');
    remotes.mockClear();
    for (const mode of ['add', 'remove', 'rename', 'set-url']) {
      const result = await call(read, sid, 'git_remote', {
        path: first,
        mode,
        name: 'origin',
        url: 'https://example.test/repo.git',
        newName: 'renamed',
      });
      expect(result.isError).toBe(true);
    }
    expect(remotes).not.toHaveBeenCalled();
    expect(readFileSync(join(first, '.git/config'), 'utf8')).toBe(before);
    accepted(
      await call(read, sid, 'git_remote', { path: first, mode: 'list' }),
    );
    expect(remotes).toHaveBeenCalledTimes(1);
    const write = await token();
    const writeSid = await initialize(write);
    accepted(
      await call(write, writeSid, 'git_remote', {
        path: first,
        mode: 'add',
        name: 'allowed',
        url: 'https://example.test/repo.git',
      }),
    );
    expect(
      accepted(
        await call(read, sid, 'git_remote', {
          path: first,
          mode: 'get-url',
          name: 'allowed',
        }),
      ).url,
    ).toBe('https://example.test/repo.git');
  });

  it('same-tenant sessions interleave real cwd tools independently and never inherit legacy state', async () => {
    const alice = await token();
    const a = await initialize(alice);
    const b = await initialize(alice);
    accepted(await call(alice, a, 'git_set_working_dir', { path: first }));
    expect((await call(alice, b, 'git_status', { path: '.' })).isError).toBe(
      true,
    );
    accepted(await call(alice, b, 'git_set_working_dir', { path: other }));
    for (const [sid, expected] of [
      [a, first],
      [b, other],
    ]) {
      const response = await request(alice, sid, 'POST', {
        jsonrpc: '2.0',
        id: 7,
        method: 'resources/read',
        params: { uri: 'git://working-directory' },
      });
      const result = (await response.json()) as {
        result: { contents: { text: string }[] };
      };
      expect(JSON.parse(result.result.contents[0]!.text).workingDirectory).toBe(
        expected,
      );
    }
    expect(
      accepted(
        await call(alice, a, 'git_wrapup_instructions', {
          acknowledgement: 'yes',
        }),
      ),
    ).toBeDefined();
    accepted(await call(alice, b, 'git_clear_working_dir', { confirm: 'yes' }));
    accepted(await call(alice, a, 'git_status', { path: '.' }));
    expect((await call(alice, b, 'git_status', { path: '.' })).isError).toBe(
      true,
    );
    const deleted = await request(alice, a, 'DELETE');
    await deleted.text();
    const c = await initialize(alice);
    expect((await call(alice, c, 'git_status', { path: '.' })).isError).toBe(
      true,
    );
  }, 30000);

  it('equal-scope principals cannot use absolute, clone, remote, worktree or metadata paths outside their grant', async () => {
    const alice = await token();
    const sid = await initialize(alice);
    const metadataAlias = join(first, 'metadata-alias');
    mkdirSync(metadataAlias);
    writeFileSync(
      join(metadataAlias, '.git'),
      `gitdir: ${join(second, '.git')}\n`,
    );
    const baseline = readFileSync(join(second, '.git/config'), 'utf8');
    const ownConfig = readFileSync(join(first, '.git/config'), 'utf8');
    for (const [name, args] of [
      ['git_status', { path: second }],
      ['git_status', { path: metadataAlias }],
      [
        'git_status',
        { path: second, tenantId: 'tenant-b', repositoryRoots: [second] },
      ],
      ['git_set_working_dir', { path: second }],
      [
        'git_clone',
        { url: pathToFileURL(second).href, path: join(first, 'clone') },
      ],
      [
        'git_clone',
        { url: pathToFileURL(first).href, path: join(second, 'clone') },
      ],
      [
        'git_remote',
        {
          path: first,
          mode: 'add',
          name: 'foreign',
          url: pathToFileURL(second).href,
        },
      ],
      [
        'git_worktree',
        {
          path: first,
          mode: 'add',
          worktreePath: join(second, 'worktree'),
          detach: true,
        },
      ],
    ] as const)
      expect((await call(alice, sid, name, args)).isError).toBe(true);
    expect(readFileSync(join(second, '.git/config'), 'utf8')).toBe(baseline);
    expect(readFileSync(join(first, '.git/config'), 'utf8')).toBe(ownConfig);
    expect(existsSync(join(second, 'clone'))).toBe(false);
    expect(existsSync(join(second, 'worktree'))).toBe(false);
    expect(existsSync(join(first, 'clone'))).toBe(false);
    const bob = await token({ sub: 'bob' });
    const bobSid = await initialize(bob);
    accepted(await call(bob, bobSid, 'git_status', { path: second }));
    expect(
      (await call(bob, bobSid, 'git_status', { path: first })).isError,
    ).toBe(true);
  });
  it('explicit anonymous mode retains separate server-session cwd and aggregate admission', async () => {
    const authenticated = app;
    const mode = config.mcpAuthMode;
    config.mcpAuthMode = 'none';
    app = createHttpApp(
      makeServer,
      requestContextService.createRequestContext(),
    );
    try {
      const a = await initialize('anonymous');
      const b = await initialize('anonymous');
      accepted(
        await call('anonymous', a, 'git_set_working_dir', { path: first }),
      );
      expect(
        (await call('anonymous', b, 'git_status', { path: '.' })).isError,
      ).toBe(true);
      accepted(
        await call('anonymous', b, 'git_set_working_dir', { path: second }),
      );
      accepted(
        await call('anonymous', a, 'git_clear_working_dir', { confirm: 'yes' }),
      );
      accepted(await call('anonymous', b, 'git_status', { path: '.' }));
    } finally {
      await closeHttpApp(app);
      app = authenticated;
      config.mcpAuthMode = mode;
    }
  }, 30000);
});
