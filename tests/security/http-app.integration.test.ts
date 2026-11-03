/**
 * @fileoverview Exercise production HTTP app and actual SDK transport under hostile inputs.
 * @module tests/security/http-app.integration
 */
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { config } from '../../src/config/index.js';
import {
  createHttpApp,
  closeHttpApp,
} from '../../src/mcp-server/transports/http/httpTransport.js';
import { logger, requestContextService } from '../../src/utils/index.js';
import { httpErrorHandler } from '../../src/mcp-server/transports/http/httpErrorHandler.js';
import { Hono } from 'hono';
import { container } from 'tsyringe';
import { AppConfig, Logger } from '../../src/container/tokens.js';
import type { HonoNodeBindings } from '../../src/mcp-server/transports/http/httpTypes.js';
import { McpError, JsonRpcErrorCode } from '../../src/types-global/errors.js';

const original = { ...config };
// tests/setup.ts intentionally mocks McpServer outside the explicit real-SDK profile.
const describeHttp = process.env.INTEGRATION === '1' ? describe : describe.skip;
const apps: ReturnType<typeof createHttpApp>[] = [];
let created = 0;
let executed = 0;
let failFactory = false;
const init = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'security-test', version: '1' },
  },
};
const baseHeaders = {
  host: 'localhost:3015',
  'content-type': 'application/json',
  accept: 'application/json, text/event-stream',
};

function app() {
  const value = createHttpApp(
    async () => {
      created++;
      if (failFactory) throw new Error('Synthetic factory failure');
      const server = new McpServer(
        { name: 'test', version: '1' },
        { maxToolInputElements: config.toolInputLimits.maxElements },
      );
      server.registerTool(
        'probe',
        { inputSchema: z.object({ paths: z.array(z.string()) }) },
        async () => {
          executed++;
          return { content: [{ type: 'text', text: 'ok' }] };
        },
      );
      return server;
    },
    requestContextService.createRequestContext({
      operation: 'http-security-test',
    }),
  );
  apps.push(value);
  return value;
}

async function post(
  value: ReturnType<typeof app>,
  body: unknown,
  headers: Record<string, string> = {},
) {
  return value.request('http://localhost:3015/mcp', {
    method: 'POST',
    headers: { ...baseHeaders, ...headers },
    body: JSON.stringify(body),
  });
}

async function initialize(value: ReturnType<typeof app>) {
  const response = await post(value, init);
  expect(response.status).toBe(200);
  const sid = response.headers.get('mcp-session-id');
  expect(sid).toBeTruthy();
  await response.json();
  const ready = await post(
    value,
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { 'mcp-session-id': sid! },
  );
  expect(ready.status).toBe(202);
  return sid!;
}

beforeEach(() => {
  Object.assign(config, {
    mcpAllowedOrigins: ['https://client.example'],
    mcpAuthMode: 'none',
    mcpStatefulSessionStaleTimeoutMs: 10000,
  });
  config.httpSecurity = {
    ...original.httpSecurity,
    maxSessions: 4,
    maxSessionsPerPrincipal: 2,
  };
  config.toolInputLimits = { ...original.toolInputLimits };
  created = 0;
  executed = 0;
  failFactory = false;
});
afterEach(async () => {
  await Promise.all(apps.splice(0).map(closeHttpApp));
  Object.assign(config, original);
});

describeHttp('actual production HTTP parser and admission', () => {
  test('real auth denial does not pull chunked body or allocate server', async () => {
    config.mcpAuthMode = 'jwt';
    config.mcpAuthSecretKey = 'synthetic-unit-test-secret-material-only';
    config.mcpAuthIssuer = 'https://issuer.example.test';
    config.mcpAuthAudience = 'http-fixture';
    config.mcpRepositoryGrants = JSON.stringify([
      {
        issuer: config.mcpAuthIssuer,
        tenantId: 'fixture',
        clientId: 'fixture',
        subject: 'fixture',
        roots: [process.cwd()],
      },
    ]);
    config.git = {
      ...config.git,
      executionProfile: 'trusted',
      baseDirs: [process.cwd()],
    };
    container.registerInstance(AppConfig, config);
    container.registerInstance(Logger, logger);
    const value = app();
    let pulls = 0;
    const stream = new ReadableStream(
      {
        pull() {
          pulls++;
        },
      },
      { highWaterMark: 0 },
    );
    const response = await value.request(
      new Request('http://localhost:3015/mcp', {
        method: 'POST',
        headers: baseHeaders,
        body: stream,
        duplex: 'half',
      } as RequestInit),
    );
    expect(response.status).toBe(401);
    await response.text();
    expect(pulls).toBe(0);
    expect(created).toBe(0);
    await stream.cancel();
  });

  test('pending factories have bounded concurrent allocation through late cleanup', async () => {
    config.httpSecurity.requestTimeoutMs = 15;
    let complete: (() => void) | undefined;
    let factories = 0;
    const value = createHttpApp(
      async () => {
        factories++;
        if (factories === 1)
          await new Promise<void>((resolve) => {
            complete = resolve;
          });
        return new McpServer({ name: 'factory-test', version: '1' });
      },
      requestContextService.createRequestContext({
        operation: 'factory-quota',
      }),
    );
    apps.push(value);
    const first = post(value, init);
    await new Promise((resolve) => setTimeout(resolve, 0));
    const limited = await post(value, init);
    expect(limited.status).toBe(429);
    await limited.text();
    const timeout = await first;
    expect(timeout.status).toBe(408);
    await timeout.text();
    const retained = await post(value, init);
    expect(retained.status).toBe(429);
    await retained.text();
    expect(factories).toBe(1);
    complete!();
    await new Promise((resolve) => setTimeout(resolve, 0));
    const recovered = await post(value, init);
    expect(recovered.status).toBe(200);
    await recovered.json();
    expect(factories).toBe(2);
  });
  test('approved browser/native initialize and tool work; Host/Origin rejection before factory', async () => {
    const value = app();
    for (const headers of [
      { origin: 'null' },
      { origin: 'https://foreign.example' },
      { host: 'evil.example', 'x-forwarded-host': 'localhost:3015' },
      { host: 'localhost:9999' },
    ]) {
      const response = await post(value, init, headers);
      expect(response.status).toBe(403);
      await response.text();
    }
    expect(created).toBe(0);
    const browser = await post(value, init, {
      origin: 'https://client.example',
    });
    expect(browser.status).toBe(200);
    expect(browser.headers.get('access-control-allow-origin')).toBe(
      'https://client.example',
    );
    await browser.json();
    const sid = await initialize(value);
    const call = await post(
      value,
      {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'probe', arguments: { paths: ['a'] } },
      },
      { 'mcp-session-id': sid },
    );
    expect(call.status).toBe(200);
    expect(
      ((await call.json()) as { result: { isError?: boolean } }).result.isError,
    ).not.toBe(true);
    expect(executed).toBe(1);
  });

  test('bytes, invalid collections and batches rejected before factory and provider', async () => {
    config.httpSecurity.maxBodyBytes = new TextEncoder().encode(
      JSON.stringify(init),
    ).length;
    const value = app();
    const accepted = await post(value, init);
    expect(accepted.status).toBe(200);
    const sid = accepted.headers.get('mcp-session-id')!;
    await accepted.json();
    const tooBig = await value.request('http://localhost:3015/mcp', {
      method: 'POST',
      headers: baseHeaders,
      body: JSON.stringify(init) + ' ',
    });
    expect(tooBig.status).toBe(413);
    await tooBig.text();
    const batch = await post(value, [
      { jsonrpc: '2.0', id: 1, method: 'ping' },
    ]);
    expect(batch.status).toBe(400);
    await batch.text();
    const huge = await post(
      value,
      {
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: { name: 'probe', arguments: { paths: Array(1001).fill({}) } },
      },
      { 'mcp-session-id': sid },
    );
    expect(huge.status).toBe(413);
    await huge.text();
    expect(created).toBe(1);
    expect(executed).toBe(0);
  });

  test('invalid sessionless messages allocate nothing; failed factories release quota', async () => {
    const value = app();
    for (let n = 0; n < 8; n++) {
      const bad = await post(value, { jsonrpc: '2.0', id: n, method: 'ping' });
      expect(bad.status).toBe(400);
      await bad.text();
    }
    expect(created).toBe(0);
    failFactory = true;
    for (let n = 0; n < 4; n++) {
      const failed = await post(value, init);
      expect(failed.status).toBe(500);
      await failed.text();
    }
    failFactory = false;
    await initialize(value);
    expect(created).toBe(5);
  });

  test('session cap, DELETE cleanup and independent app/session lifetimes', async () => {
    const first = app();
    const sid = await initialize(first);
    await initialize(first);
    const limited = await post(first, init);
    expect(limited.status).toBe(429);
    await limited.text();
    expect(created).toBe(2);
    const second = app();
    await initialize(second);
    const deleted = await first.request('http://localhost:3015/mcp', {
      method: 'DELETE',
      headers: { ...baseHeaders, 'mcp-session-id': sid },
    });
    expect(deleted.status).toBe(200);
    await deleted.text();
    await initialize(first);
  });

  test('SSE share bounded and cancellation reclaims stream slots', async () => {
    config.httpSecurity.maxSessionsPerPrincipal = 3;
    const value = app();
    const sid = await initialize(value);
    const secondId = await initialize(value);
    const thirdId = await initialize(value);
    const get = (session = sid) =>
      value.request('http://localhost:3015/mcp', {
        headers: {
          ...baseHeaders,
          'mcp-session-id': session,
          accept: 'text/event-stream',
        },
      });
    const stream = await get();
    expect(stream.status).toBe(200);
    // SDK supports one standalone stream per session; repeated GET cannot allocate another.
    const duplicate = await get();
    expect(duplicate.status).toBe(409);
    await duplicate.text();
    const second = await get(secondId);
    expect(second.status).toBe(200);
    const limited = await get(thirdId);
    expect(limited.status).toBe(429);
    await limited.text();
    await stream.body!.cancel();
    const resumed = await get(thirdId);
    expect(resumed.status).toBe(200);
    await second.body!.cancel();
    await resumed.body!.cancel();
  });

  test('expired session closes allocations before replacement', async () => {
    config.mcpStatefulSessionStaleTimeoutMs = 15;
    const value = app();
    const sid = await initialize(value);
    await new Promise((resolve) => setTimeout(resolve, 35));
    const expired = await post(
      value,
      { jsonrpc: '2.0', id: 3, method: 'ping' },
      { 'mcp-session-id': sid },
    );
    expect(expired.status).toBe(404);
    await expired.text();
    await initialize(value);
  });

  test('error handler never reads rejected-auth streaming body', async () => {
    let pulled = 0;
    const body = new ReadableStream(
      {
        pull() {
          pulled++;
        },
      },
      { highWaterMark: 0 },
    );
    const value = new Hono<{ Bindings: HonoNodeBindings }>();
    value.onError(httpErrorHandler);
    value.post('/mcp', () => {
      throw new McpError(
        JsonRpcErrorCode.Unauthorized,
        'Synthetic denied auth',
      );
    });
    const response = await value.request(
      new Request('http://localhost/mcp', {
        method: 'POST',
        body,
        duplex: 'half',
      } as RequestInit),
    );
    expect(response.status).toBe(401);
    expect(((await response.json()) as { id: unknown }).id).toBeNull();
    expect(pulled).toBe(0);
    await body.cancel();
  });
});
