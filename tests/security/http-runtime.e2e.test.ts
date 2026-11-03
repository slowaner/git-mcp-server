/**
 * @fileoverview Production bundle HTTP compatibility and security under Node and Bun.
 * @module tests/security/http-runtime.e2e
 */
import { expect, test } from 'bun:test';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { resolve } from 'node:path';

const runtimeTest = process.env.INTEGRATION === '1' ? test : test.skip;

for (const runtime of ['node', process.execPath]) {
  runtimeTest(
    `production HTTP bundle: ${runtime}`,
    async () => {
      const reservation = createServer();
      reservation.listen(0, '127.0.0.1');
      await once(reservation, 'listening');
      const address = reservation.address();
      if (!address || typeof address === 'string')
        throw new Error('Missing test listener address.');
      const port = address.port;
      await new Promise<void>((resolve, reject) =>
        reservation.close((error) => (error ? reject(error) : resolve())),
      );
      const child = spawn(runtime, [resolve('dist/index.js')], {
        stdio: 'ignore',
        env: {
          ...process.env,
          NODE_ENV: 'testing',
          MCP_TRANSPORT_TYPE: 'http',
          MCP_HTTP_HOST: '127.0.0.1',
          MCP_HTTP_PORT: String(port),
          MCP_HTTP_MAX_PORT_RETRIES: '0',
          MCP_HTTP_ALLOWED_HOSTS: `127.0.0.1:${port}`,
          MCP_ALLOWED_ORIGINS: 'https://client.example',
          MCP_AUTH_MODE: 'none',
          MCP_HTTP_MAX_BODY_BYTES: '1024',
          MCP_LOG_LEVEL: 'error',
          OTEL_ENABLED: 'false',
        },
      });
      const closed = once(child, 'close');
      const endpoint = `http://127.0.0.1:${port}/mcp`;
      const headers = {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
      };
      try {
        let ready = false;
        for (let attempt = 0; attempt < 100; attempt++) {
          if (child.exitCode !== null)
            throw new Error(
              `Server exited before readiness: ${child.exitCode}`,
            );
          try {
            const health = await fetch(`http://127.0.0.1:${port}/healthz`);
            await health.text();
            if (health.ok) {
              ready = true;
              break;
            }
          } catch {
            /* startup has not bound yet */
          }
          await new Promise((done) => setTimeout(done, 25));
        }
        expect(ready).toBe(true);
        const init = JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'runtime-test', version: '1' },
          },
        });
        const accepted = await fetch(endpoint, {
          method: 'POST',
          headers,
          body: init,
        });
        expect(accepted.status).toBe(200);
        const sid = accepted.headers.get('mcp-session-id');
        expect(sid).toBeTruthy();
        await accepted.json();
        for (const peer of [
          { origin: 'null' },
          { origin: 'https://foreign.example' },
          { host: 'evil.example' },
        ]) {
          const denied = await fetch(endpoint, {
            method: 'POST',
            headers: { ...headers, ...peer },
            body: init,
          });
          expect(denied.status).toBe(403);
          await denied.text();
        }
        const batch = await fetch(endpoint, {
          method: 'POST',
          headers,
          body: '[{"jsonrpc":"2.0","id":2,"method":"ping"}]',
        });
        expect(batch.status).toBe(400);
        await batch.text();
        let sent = false;
        const body = new ReadableStream<Uint8Array>({
          pull(controller) {
            if (!sent) {
              sent = true;
              controller.enqueue(new TextEncoder().encode(' '.repeat(1025)));
            } else controller.close();
          },
        });
        const oversized = await fetch(endpoint, {
          method: 'POST',
          headers,
          body,
          duplex: 'half',
        } as RequestInit);
        expect(oversized.status).toBe(413);
        await oversized.text();
        const deleted = await fetch(endpoint, {
          method: 'DELETE',
          headers: { ...headers, 'mcp-session-id': sid! },
        });
        expect(deleted.status).toBe(200);
        await deleted.text();
      } finally {
        child.kill('SIGTERM');
        const timeout = setTimeout(() => child.kill('SIGKILL'), 2000);
        try {
          await closed;
        } finally {
          clearTimeout(timeout);
        }
      }
    },
    15000,
  );
}
