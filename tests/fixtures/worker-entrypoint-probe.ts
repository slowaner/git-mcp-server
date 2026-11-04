/**
 * @fileoverview Isolated Bun import oracle for the actual unsupported Worker entrypoint.
 * @module tests/fixtures/worker-entrypoint-probe
 */
import assert from 'node:assert/strict';
import { mock } from 'bun:test';

// This probe runs in its own process so module mocks never contaminate suites.
// Any attempted application/config/service import fails before its factory runs.
for (const module of [
  '@/config/index.js',
  '@/container/index.js',
  '@/mcp-server/server.js',
  '@/mcp-server/transports/http/httpTransport.js',
  '@/utils/index.js',
]) {
  mock.module(module, () => {
    throw new Error(
      `Unsupported Worker imported application module: ${module}`,
    );
  });
}

const bindings = new Proxy(
  {},
  {
    get() {
      throw new Error('Worker read runtime bindings');
    },
    ownKeys() {
      throw new Error('Worker enumerated runtime bindings');
    },
  },
);
const { default: worker } = await import('@/worker.js');
for (const method of [
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS',
  'HEAD',
]) {
  for (const route of [
    '/',
    '/healthz',
    '/mcp',
    '/.well-known/oauth-protected-resource',
  ]) {
    const request = new Request(`https://worker.example.test${route}`, {
      method,
    });
    assert.equal(worker.fetch(request, bindings).status, 503);
  }
}
assert.equal(
  worker.fetch(new Request('https://worker.example.test/mcp'), {
    MCP_AUTH_MODE: 'none',
  }).status,
  503,
);
assert.equal(
  worker.fetch(new Request('https://worker.example.test/mcp'), {
    MCP_AUTH_MODE: 'jwt',
  }).status,
  503,
);
process.stdout.write('entrypoint-policy-ok\n');
