/**
 * @fileoverview Actual Worker entrypoint import, route and initialization-denial tests.
 * @module tests/mcp-server/transports/worker.entrypoint.test
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import worker from '@/worker.js';

describe('Worker production entrypoint', () => {
  it('imports and rejects every route before application factories or binding reads', () => {
    const executable = process.versions.bun ? process.execPath : 'bun';
    const probe = fileURLToPath(
      new URL('../../fixtures/worker-entrypoint-probe.ts', import.meta.url),
    );
    const result = spawnSync(executable, ['run', probe], {
      cwd: fileURLToPath(new URL('../../../', import.meta.url)),
      encoding: 'utf8',
      timeout: 10000,
      maxBuffer: 1024 * 1024,
    });
    expect(result.error).toBeUndefined();
    expect(result.signal).toBeNull();
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('entrypoint-policy-ok\n');
  });

  it('keeps the actual entrypoint unavailable across warm binding changes', async () => {
    const request = new Request('https://worker.example.test/healthz');
    const cold = worker.fetch(request, { MCP_AUTH_MODE: 'none' });
    const warm = worker.fetch(
      request,
      new Proxy(
        {},
        {
          get() {
            throw new Error('warm binding read');
          },
        },
      ),
    );
    expect(cold.status).toBe(503);
    expect(warm.status).toBe(503);
    expect(await warm.json()).toEqual(await cold.json());
  });
});
