/**
 * @fileoverview HTTP lifecycle cancellation, retained allocation and actual SDK element cap.
 * @module tests/security/http-lifetime
 */
import { describe, expect, test } from 'bun:test';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { z } from 'zod';
import { SignJWT } from 'jose';
import { config } from '../../src/config/index.js';
import { logger } from '../../src/utils/index.js';
import type { AuthStore } from '../../src/mcp-server/transports/auth/lib/authContext.js';
import { JwtStrategy } from '../../src/mcp-server/transports/auth/strategies/jwtStrategy.js';
import { ToolRegistry } from '../../src/mcp-server/tools/tool-registration.js';
import { authContext } from '../../src/mcp-server/transports/auth/index.js';
import {
  boundResponseLifetime,
  createServerWithinDeadline,
  dispatchWithDeadline,
} from '../../src/mcp-server/transports/http/httpLifetime.js';
// Run this profile explicitly; the default suite replaces McpServer in setup.ts.
const describeSdk = process.env.INTEGRATION === '1' ? describe : describe.skip;
const testSdk = process.env.INTEGRATION === '1' ? test : test.skip;

describeSdk('allocation lifetime', () => {
  test('timed-out factory keeps reserved capacity until late server closes', async () => {
    let resolve: (server: McpServer) => void = () => {};
    const pending = new Promise<McpServer>((value) => {
      resolve = value;
    });
    let abandoned = false;
    let released = false;
    const result = createServerWithinDeadline(
      () => pending,
      new Request('http://localhost'),
      10,
      () => {
        abandoned = true;
      },
      () => {
        released = true;
      },
    );
    await expect(result).rejects.toThrow('Initialization deadline');
    expect(abandoned).toBe(true);
    expect(released).toBe(false);
    resolve(new McpServer({ name: 'late', version: '1' }));
    await new Promise((done) => setTimeout(done, 0));
    expect(released).toBe(true);
  });
  test('response deadline and disconnect cancel source and reclaim exactly once', async () => {
    let cancelled = 0;
    let releases = 0;
    const response = boundResponseLifetime(
      new Response(
        new ReadableStream({
          cancel() {
            cancelled++;
          },
        }),
      ),
      () => {
        releases++;
      },
      10,
      new AbortController().signal,
    );
    const reader = response.body!.getReader();
    await expect(reader.read()).rejects.toThrow('lifetime');
    expect(cancelled).toBe(1);
    expect(releases).toBe(1);
    const controller = new AbortController();
    const disconnected = boundResponseLifetime(
      new Response(
        new ReadableStream({
          cancel() {
            cancelled++;
          },
        }),
      ),
      () => {
        releases++;
      },
      1000,
      controller.signal,
    );
    const second = disconnected.body!.getReader();
    controller.abort();
    await expect(second.read()).rejects.toThrow('lifetime');
    expect(cancelled).toBe(2);
    expect(releases).toBe(2);
  });
});

testSdk(
  'real SDK rejects excessive input before Zod issues and cancels running tools',
  async () => {
    const server = new McpServer(
      { name: 'budget', version: '1' },
      { maxToolInputElements: 3 },
    );
    let schemaRuns = 0;
    let executions = 0;
    let aborted = false;
    server.registerTool(
      'probe',
      {
        inputSchema: z.object({
          paths: z.array(
            z.string().refine(() => {
              schemaRuns++;
              return true;
            }),
          ),
        }),
      },
      async () => {
        executions++;
        return { content: [] };
      },
    );
    server.registerTool(
      'wait',
      { inputSchema: z.object({}) },
      async (_, extra) => {
        await new Promise<void>((resolve) =>
          extra.signal.addEventListener(
            'abort',
            () => {
              aborted = true;
              resolve();
            },
            { once: true },
          ),
        );
        return { content: [] };
      },
    );
    const transport = new WebStandardStreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => 'test-session',
    });
    await server.connect(transport);
    const req = () =>
      new Request('http://localhost/mcp', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          'mcp-session-id': 'test-session',
        },
      });
    try {
      const initRequest = new Request('http://localhost/mcp', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
        },
      });
      const initialized = await transport.handleRequest(initRequest, {
        parsedBody: {
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'test', version: '1' },
          },
        },
      });
      await initialized.json();
      const notify = await transport.handleRequest(req(), {
        parsedBody: { jsonrpc: '2.0', method: 'notifications/initialized' },
      });
      expect(notify.status).toBe(202);
      const call = (paths: unknown[]) =>
        transport.handleRequest(req(), {
          parsedBody: {
            jsonrpc: '2.0',
            id: 2,
            method: 'tools/call',
            params: { name: 'probe', arguments: { paths } },
          },
        });
      const atLimit = await call(['a', 'b']);
      expect(
        ((await atLimit.json()) as { result: { isError?: boolean } }).result
          .isError,
      ).not.toBe(true);
      expect(schemaRuns).toBe(2);
      expect(executions).toBe(1);
      const overLimit = await call([{}, {}, {}]);
      expect(
        ((await overLimit.json()) as { result: { isError: boolean } }).result
          .isError,
      ).toBe(true);
      expect(schemaRuns).toBe(2);
      expect(executions).toBe(1);
      await expect(
        dispatchWithDeadline(
          transport,
          req(),
          {
            jsonrpc: '2.0',
            id: 3,
            method: 'tools/call',
            params: { name: 'wait', arguments: {} },
          },
          10,
        ),
      ).rejects.toThrow('deadline');
      expect(aborted).toBe(true);
    } finally {
      await server.close();
    }
  },
);

/** Exercise the production registry and SDK without replacing their admission state. */
async function createWorkQuotaFixture() {
  const server = new McpServer(
    { name: 'work-quota', version: '1' },
    { maxToolInputElements: 4096 },
  );
  const releases: (() => void)[] = [];
  const state = { active: 0, probes: 0 };
  const registry = new ToolRegistry([
    {
      name: 'hold',
      description: 'Hold synthetic work.',
      inputSchema: z.object({}),
      outputSchema: z.object({ success: z.boolean().describe('Outcome.') }),
      logic: async () => {
        state.active++;
        await new Promise<void>((resolve) => releases.push(resolve));
        state.active--;
        return { success: true };
      },
    },
    {
      name: 'probe',
      description: 'Count synthetic work.',
      inputSchema: z.object({}),
      outputSchema: z.object({ success: z.boolean().describe('Outcome.') }),
      logic: () => {
        state.probes++;
        return Promise.resolve({ success: true });
      },
    },
  ]);
  await registry.registerAll(server);
  const transport = new WebStandardStreamableHTTPServerTransport({
    enableJsonResponse: true,
    sessionIdGenerator: () => 'quota-session',
  });
  const request = () =>
    new Request('http://localhost/mcp', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-session-id': 'quota-session',
      },
    });
  const call = (store: AuthStore, id: number, name: string) =>
    authContext.run(store, () =>
      transport.handleRequest(request(), {
        parsedBody: {
          jsonrpc: '2.0',
          id,
          method: 'tools/call',
          params: { name, arguments: {} },
        },
      }),
    );
  const releaseAll = () => releases.forEach((release) => release());
  const close = async () => {
    releaseAll();
    await server.close();
  };
  try {
    await server.connect(transport);
    const initialized = await transport.handleRequest(
      new Request('http://localhost/mcp', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
        },
      }),
      {
        parsedBody: {
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'test', version: '1' },
          },
        },
      },
    );
    expect(initialized.status).toBe(200);
    await initialized.json();
    const ready = await transport.handleRequest(request(), {
      parsedBody: { jsonrpc: '2.0', method: 'notifications/initialized' },
    });
    expect(ready.status).toBe(202);
    return { call, releaseAll, close, state };
  } catch (error) {
    await close();
    throw error;
  }
}

testSdk(
  'production tool registry bounds active work and preserves independent principal share',
  async () => {
    const savedMode = config.mcpAuthMode;
    let fixture: Awaited<ReturnType<typeof createWorkQuotaFixture>> | undefined;
    config.mcpAuthMode = 'jwt';
    try {
      const secret = 'synthetic-quota-signing-material-'.repeat(3);
      const issuer = 'https://quota-fixture.example.test';
      const audience = 'quota-fixture';
      const strategy = new JwtStrategy(
        {
          ...config,
          mcpTransportType: 'http',
          mcpAuthSecretKey: secret,
          mcpAuthIssuer: issuer,
          mcpAuthAudience: audience,
          mcpRepositoryGrants: JSON.stringify(
            ['user-a', 'user-b'].map((subject) => ({
              issuer,
              tenantId: 'test-tenant',
              clientId: 'shared-client',
              subject,
              roots: [process.cwd()],
            })),
          ),
        },
        logger,
      );
      const signed = async (subject: string) => {
        const now = Math.floor(Date.now() / 1000);
        return new SignJWT({
          iss: issuer,
          aud: audience,
          sub: subject,
          tid: 'test-tenant',
          cid: 'shared-client',
          scope: 'tool:git:read',
          iat: now,
          exp: now + 60,
        })
          .setProtectedHeader({ alg: 'HS256' })
          .sign(new TextEncoder().encode(secret));
      };
      const alice = await strategy.verify(await signed('user-a'));
      const bob = await strategy.verify(await signed('user-b'));
      if (!alice.principal || !bob.principal)
        throw new Error('Real verifier must return principal identity.');
      expect(alice.clientId).toBe(bob.clientId);
      expect(alice.tenantId).toBe(bob.tenantId);
      expect(alice.scopes).toEqual(bob.scopes);
      expect(alice.principal.subject).not.toBe(bob.principal.subject);
      // Only actual verified strategy output enters the server-owned principal seam.
      const owners: Record<'alice' | 'bob', AuthStore> = {
        alice: {
          authInfo: alice,
          principal: alice.principal,
          transport: 'http',
        },
        bob: { authInfo: bob, principal: bob.principal, transport: 'http' },
      };
      fixture = await createWorkQuotaFixture();
      const { call, releaseAll, state } = fixture;
      const pending = [2, 3, 4, 5].map((id) => call(owners.alice, id, 'hold'));
      await new Promise((done) => setTimeout(done, 0));
      expect(state.active).toBe(4);
      const denied = await call(owners.alice, 6, 'probe');
      expect(
        ((await denied.json()) as { result: { isError: boolean } }).result
          .isError,
      ).toBe(true);
      expect(state.probes).toBe(0);
      const peer = await call(owners.bob, 7, 'probe');
      expect(
        ((await peer.json()) as { result: { isError?: boolean } }).result
          .isError,
      ).not.toBe(true);
      expect(state.probes).toBe(1);
      releaseAll();
      for (const response of await Promise.all(pending)) await response.json();
      expect(state.active).toBe(0);
      const resumed = await call(owners.alice, 8, 'probe');
      expect(
        ((await resumed.json()) as { result: { isError?: boolean } }).result
          .isError,
      ).not.toBe(true);
      expect(state.probes).toBe(2);
    } finally {
      try {
        await fixture?.close();
      } finally {
        config.mcpAuthMode = savedMode;
      }
    }
  },
);

testSdk(
  'anonymous tool work stays aggregated despite forged legacy client and tenant fields',
  async () => {
    const savedMode = config.mcpAuthMode;
    let fixture: Awaited<ReturnType<typeof createWorkQuotaFixture>> | undefined;
    config.mcpAuthMode = 'none';
    try {
      fixture = await createWorkQuotaFixture();
      const { call, releaseAll, state } = fixture;
      const unverified = (clientId: string, tenantId: string): AuthStore => ({
        authInfo: {
          token: 'synthetic-test-only',
          clientId,
          tenantId,
          subject: clientId,
          scopes: [],
        },
        transport: 'http',
      });
      const pending = [2, 3, 4, 5].map((id) =>
        call(
          unverified(
            id % 2 ? 'client-a' : 'client-b',
            id % 2 ? 'tenant-a' : 'tenant-b',
          ),
          id,
          'hold',
        ),
      );
      await new Promise((done) => setTimeout(done, 0));
      expect(state.active).toBe(4);
      const denied = await call(unverified('client-a', 'tenant-a'), 6, 'probe');
      expect(
        ((await denied.json()) as { result: { isError: boolean } }).result
          .isError,
      ).toBe(true);
      const forgedPeer = await call(
        unverified('new-client', 'new-tenant'),
        7,
        'probe',
      );
      expect(
        ((await forgedPeer.json()) as { result: { isError: boolean } }).result
          .isError,
      ).toBe(true);
      expect(state.probes).toBe(0);
      releaseAll();
      for (const response of await Promise.all(pending)) await response.json();
      expect(state.active).toBe(0);
      const resumed = await call(
        unverified('another-client', 'another-tenant'),
        8,
        'probe',
      );
      expect(
        ((await resumed.json()) as { result: { isError?: boolean } }).result
          .isError,
      ).not.toBe(true);
      expect(state.probes).toBe(1);
    } finally {
      try {
        await fixture?.close();
      } finally {
        config.mcpAuthMode = savedMode;
      }
    }
  },
);
