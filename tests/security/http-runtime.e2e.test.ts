/**
 * @fileoverview Production bundle HTTP compatibility and security under Node and Bun.
 * @module tests/security/http-runtime.e2e
 */
import { expect, test } from 'bun:test';
import { SignJWT } from 'jose';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const runtimeTest = process.env.INTEGRATION === '1' ? test : test.skip;

const profiles = ['node', process.execPath].flatMap((runtime) =>
  (['none', 'jwt'] as const).map((authMode) => ({ runtime, authMode })),
);

for (const { runtime, authMode } of profiles) {
  runtimeTest(
    `production HTTP bundle: ${runtime} with ${authMode} auth`,
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
      const repository = await mkdtemp(join(tmpdir(), 'git-http-runtime-'));
      const secret = 'synthetic-runtime-test-secret-material-only';
      const issuer = 'https://issuer.example.test';
      const audience = 'git-http-runtime';
      const token =
        authMode === 'jwt'
          ? await new SignJWT({
              cid: 'runtime-test',
              sub: 'runtime-test',
              tid: 'test-tenant',
              scp: ['tool:git:read'],
            })
              .setProtectedHeader({ alg: 'HS256' })
              .setIssuer(issuer)
              .setAudience(audience)
              .setIssuedAt()
              .setExpirationTime('5m')
              .sign(new TextEncoder().encode(secret))
          : undefined;
      const child = spawn(runtime, [resolve('dist/index.js')], {
        stdio: 'ignore',
        env: {
          ...process.env,
          NODE_ENV: 'testing',
          MCP_TRANSPORT_TYPE: 'http',
          MCP_RESPONSE_FORMAT: 'json',
          MCP_HTTP_HOST: '127.0.0.1',
          MCP_HTTP_PORT: String(port),
          MCP_HTTP_MAX_PORT_RETRIES: '0',
          MCP_HTTP_ALLOWED_HOSTS: `127.0.0.1:${port},LOCALHOST:${port}`,
          MCP_ALLOWED_ORIGINS: 'https://client.example',
          MCP_AUTH_MODE: authMode,
          MCP_AUTH_SECRET_KEY: secret,
          MCP_AUTH_ISSUER: issuer,
          MCP_AUTH_AUDIENCE: audience,
          MCP_REPOSITORY_GRANTS: JSON.stringify([
            {
              issuer,
              clientId: 'runtime-test',
              subject: 'runtime-test',
              tenantId: 'test-tenant',
              roots: [repository],
            },
          ]),
          MCP_HTTP_MAX_BODY_BYTES: '1024',
          MCP_LOG_LEVEL: 'error',
          OTEL_ENABLED: 'false',
          GIT_BASE_DIR: repository,
          GIT_BINARY_PATH: '/usr/bin/git',
          GIT_TRUSTED_HOME: repository,
        },
      });
      const closed = once(child, 'close');
      const endpoint = `http://127.0.0.1:${port}/mcp`;
      const headers = {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        ...(token && { authorization: `Bearer ${token}` }),
      };
      try {
        execFileSync('/usr/bin/git', ['init', '--quiet'], {
          cwd: repository,
          env: { HOME: repository, PATH: '/usr/bin:/bin' },
        });
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
        const canonicalHost = await fetch(`http://127.0.0.1:${port}/healthz`, {
          headers: { host: `LoCaLhOsT:${port}` },
        });
        expect(canonicalHost.status).toBe(200);
        await canonicalHost.text();
        const initialization = {
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'runtime-test', version: '1' },
          },
        };
        if (authMode === 'jwt') {
          const unauthorized = await fetch(endpoint, {
            method: 'POST',
            headers: { ...headers, authorization: 'Bearer invalid' },
            body: JSON.stringify(initialization),
          });
          expect(unauthorized.status).toBe(401);
          await unauthorized.text();
        }
        const { id: _id, ...withoutId } = initialization;
        const { jsonrpc: _jsonrpc, ...withoutVersion } = initialization;
        for (const invalid of [
          withoutId,
          { ...initialization, id: null },
          withoutVersion,
          { ...initialization, jsonrpc: '1.0' },
        ]) {
          const rejected = await fetch(endpoint, {
            method: 'POST',
            headers,
            body: JSON.stringify(invalid),
          });
          expect(rejected.status).toBe(400);
          expect(rejected.headers.get('mcp-session-id')).toBeNull();
          await rejected.text();
        }
        for (const id of [0, 'runtime-initialize']) {
          const response = await fetch(endpoint, {
            method: 'POST',
            headers,
            body: JSON.stringify({ ...initialization, id }),
          });
          expect(response.status).toBe(200);
          expect(((await response.json()) as { id: unknown }).id).toBe(id);
          const deleted = await fetch(endpoint, {
            method: 'DELETE',
            headers: {
              ...headers,
              'mcp-session-id': response.headers.get('mcp-session-id')!,
            },
          });
          expect(deleted.status).toBe(200);
          await deleted.text();
        }
        const init = JSON.stringify(initialization);
        const accepted = await fetch(endpoint, {
          method: 'POST',
          headers,
          body: init,
        });
        expect(accepted.status).toBe(200);
        const sid = accepted.headers.get('mcp-session-id');
        expect(sid).toBeTruthy();
        await accepted.json();

        const sessionHeaders = { ...headers, 'mcp-session-id': sid! };
        const initialized = await fetch(endpoint, {
          method: 'POST',
          headers: sessionHeaders,
          body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'notifications/initialized',
          }),
        });
        expect(initialized.status).toBe(202);
        await initialized.text();
        const listed = await fetch(endpoint, {
          method: 'POST',
          headers: sessionHeaders,
          body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
        });
        expect(listed.status).toBe(200);
        expect(await listed.json()).toMatchObject({
          id: 2,
          result: {
            tools: expect.arrayContaining([
              expect.objectContaining({ name: 'git_status' }),
            ]),
          },
        });

        const status = await fetch(endpoint, {
          method: 'POST',
          headers: sessionHeaders,
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 3,
            method: 'tools/call',
            params: { name: 'git_status', arguments: { path: repository } },
          }),
        });
        expect(status.status).toBe(200);
        expect(await status.json()).toMatchObject({
          id: 3,
          result: { structuredContent: { success: true, isClean: true } },
        });

        if (authMode === 'jwt') {
          const denied = await fetch(endpoint, {
            method: 'POST',
            headers: sessionHeaders,
            body: JSON.stringify({
              jsonrpc: '2.0',
              id: 4,
              method: 'tools/call',
              params: {
                name: 'git_set_working_dir',
                arguments: { path: repository },
              },
            }),
          });
          expect(denied.status).toBe(200);
          expect(await denied.json()).toMatchObject({
            id: 4,
            result: { isError: true },
          });
        }

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
          await rm(repository, { recursive: true, force: true });
        }
      }
    },
    15000,
  );
}
