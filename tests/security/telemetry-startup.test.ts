/**
 * @fileoverview Actual production telemetry startup on Node and Bun without implicit metric sinks.
 * @module tests/security/telemetry-startup.test
 */
import { afterAll, beforeAll, describe, expect, it } from 'bun:test';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

describe('actual telemetry startup exporter boundary', () => {
  let temporary: string, artifact: string;
  beforeAll(() => {
    temporary = mkdtempSync(join(tmpdir(), 'telemetry-startup-'));
    artifact = join(temporary, 'startup.mjs');
    execFileSync(
      process.execPath,
      [
        'build',
        fileURLToPath(
          new URL('./helpers/telemetry-startup.fixture.ts', import.meta.url),
        ),
        '--target=node',
        '--outfile=' + artifact,
      ],
      { cwd: process.cwd(), stdio: 'pipe', timeout: 15000 },
    );
  });
  afterAll(() => rmSync(temporary, { recursive: true, force: true }));
  for (const runtime of ['node', process.execPath]) {
    for (const selection of [
      'default',
      'console',
      'prometheus',
      'configured',
    ]) {
      it(`${runtime}: ${selection} uses only explicit safe metric readers`, () => {
        const child = spawnSync(runtime, [artifact, selection], {
          cwd: process.cwd(),
          env: { ...process.env },
          encoding: 'utf8',
          timeout: 10000,
          maxBuffer: 1024 * 1024,
        });
        expect(child.error).toBeUndefined();
        expect(child.signal).toBeNull();
        expect(child.status, child.stderr).toBe(0);
        expect(child.stderr).not.toContain(
          'SYNTHETIC_STARTUP_PRIVATE_SENTINEL',
        );
        const result = JSON.parse(child.stdout) as {
          completed: boolean;
          configured: boolean;
          metricRequests: number;
          traceRequests: number;
          extraListeners: number;
        };
        expect(result.completed).toBe(true);
        expect(result.configured).toBe(selection === 'configured');
        expect(result.traceRequests).toBeGreaterThan(0);
        expect(result.extraListeners).toBe(0);
        if (selection === 'configured')
          expect(result.metricRequests).toBeGreaterThan(0);
        else expect(result.metricRequests).toBe(0);
      }, 15000);
    }
  }
});
