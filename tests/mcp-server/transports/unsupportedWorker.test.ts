/**
 * @fileoverview Unsupported Worker cold/warm binding and route rejection tests.
 * @module tests/mcp-server/transports/unsupportedWorker.test
 */
import { describe, expect, it } from 'vitest';

import { unsupportedWorker } from '@/mcp-server/transports/unsupportedWorker.js';

describe('unsupported Worker deployment', () => {
  it('rejects startup requests without evaluating auth or storage bindings', async () => {
    const bindings = new Proxy(
      {},
      {
        get() {
          throw new Error(
            'Bindings must not be read for an unsupported deployment',
          );
        },
        ownKeys() {
          throw new Error(
            'Bindings must not be enumerated for an unsupported deployment',
          );
        },
      },
    );
    const response = unsupportedWorker.fetch(
      new Request('https://worker.example.test/mcp'),
      bindings,
    );
    expect(response.status).toBe(503);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await response.json()).toMatchObject({
      error: 'Unsupported deployment profile',
    });
  });

  it.each(['/', '/healthz', '/mcp', '/.well-known/oauth-protected-resource'])(
    'never reports readiness or discovery success at %s',
    (route) => {
      expect(
        unsupportedWorker.fetch(
          new Request(`https://worker.example.test${route}`),
          {},
        ).status,
      ).toBe(503);
    },
  );

  it('does not reuse permissive cold-start bindings in later warm requests', async () => {
    const first = unsupportedWorker.fetch(
      new Request('https://worker.example.test/mcp', {
        method: 'POST',
        body: 'invalid-json',
      }),
      { MCP_AUTH_MODE: 'none' },
    );
    const next = unsupportedWorker.fetch(
      new Request('https://worker.example.test/mcp', { method: 'DELETE' }),
      {
        MCP_AUTH_MODE: 'jwt',
        MCP_AUTH_SECRET_KEY: undefined,
        STORAGE_PROVIDER_TYPE: 'cloudflare-kv',
      },
    );
    expect(first.status).toBe(503);
    expect(next.status).toBe(503);
    expect(await next.json()).toEqual(await first.json());
  });
});
