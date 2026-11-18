/**
 * @fileoverview HTTP lifecycle cancellation, retained allocation and actual SDK element cap.
 * @module tests/security/http-lifetime
 */
import { describe, expect, test } from 'bun:test';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { z } from 'zod';
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

testSdk(
  'production tool registry bounds active work and preserves independent principal share',
  async () => {
    const server = new McpServer(
      { name: 'work-quota', version: '1' },
      { maxToolInputElements: 4096 },
    );
    const releases: (() => void)[] = [];
    let active = 0;
    let probes = 0;
    const registry = new ToolRegistry([
      {
        name: 'hold',
        description: 'Hold synthetic work.',
        inputSchema: z.object({}),
        outputSchema: z.object({ success: z.boolean().describe('Outcome.') }),
        logic: async () => {
          active++;
          await new Promise<void>((resolve) => releases.push(resolve));
          active--;
          return { success: true };
        },
      },
      {
        name: 'probe',
        description: 'Count synthetic work.',
        inputSchema: z.object({}),
        outputSchema: z.object({ success: z.boolean().describe('Outcome.') }),
        logic: () => {
          probes++;
          return Promise.resolve({ success: true });
        },
      },
    ]);
    await registry.registerAll(server);
    const transport = new WebStandardStreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => 'quota-session',
    });
    await server.connect(transport);
    const request = () =>
      new Request('http://localhost/mcp', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          'mcp-session-id': 'quota-session',
        },
      });
    const call = (clientId: string, id: number, name: string) =>
      authContext.run(
        {
          authInfo: {
            token: 'synthetic-test-only',
            clientId,
            tenantId: 'test-tenant',
            subject: clientId,
            scopes: [],
          },
        },
        () =>
          transport.handleRequest(request(), {
            parsedBody: {
              jsonrpc: '2.0',
              id,
              method: 'tools/call',
              params: { name, arguments: {} },
            },
          }),
      );
    try {
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
      await initialized.json();
      await transport.handleRequest(request(), {
        parsedBody: { jsonrpc: '2.0', method: 'notifications/initialized' },
      });
      const pending = [2, 3, 4, 5].map((id) => call('client-a', id, 'hold'));
      await new Promise((done) => setTimeout(done, 0));
      expect(active).toBe(4);
      const denied = await call('client-a', 6, 'probe');
      expect(
        ((await denied.json()) as { result: { isError: boolean } }).result
          .isError,
      ).toBe(true);
      expect(probes).toBe(0);
      const peer = await call('client-b', 7, 'probe');
      expect(
        ((await peer.json()) as { result: { isError?: boolean } }).result
          .isError,
      ).not.toBe(true);
      expect(probes).toBe(1);
      releases.forEach((release) => release());
      for (const response of await Promise.all(pending)) await response.json();
      expect(active).toBe(0);
      const resumed = await call('client-a', 8, 'probe');
      expect(
        ((await resumed.json()) as { result: { isError?: boolean } }).result
          .isError,
      ).not.toBe(true);
    } finally {
      releases.forEach((release) => release());
      await server.close();
    }
  },
);
