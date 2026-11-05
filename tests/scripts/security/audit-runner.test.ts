/**
 * @fileoverview Audit process evidence tested against real temporary manifest bytes.
 * @module tests/scripts/security/audit-runner
 */
import { afterEach, describe, expect, it } from 'bun:test';
import '../../../scripts/security-audit.js';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  auditAllowsProgress,
  executeAudit,
  runSecurityAudit,
} from '../../../scripts/security/audit-runner.js';

const roots: string[] = [];
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'g6-audit-'));
  roots.push(root);
  await writeFile(
    join(root, 'package.json'),
    JSON.stringify({ packageManager: `bun@${Bun.version}` }),
  );
  await writeFile(join(root, 'bun.lock'), 'synthetic locked inventory');
  return root;
}
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe('audit runner', () => {
  it('uses the exact Bun executable and no filters or shell', async () => {
    const root = await fixture();
    const report = await runSecurityAudit(root, 'high', async (args, cwd) => {
      expect(args).toEqual([process.execPath, 'audit', '--json']);
      expect(cwd).toBe(root);
      return { exitCode: 0, stdout: '{}', stderr: '' };
    });
    expect(auditAllowsProgress(report)).toBe(true);
    expect(report.lockSha256).toHaveLength(64);
  });

  it('blocks changed lock bytes despite valid clean output', async () => {
    const root = await fixture();
    const report = await runSecurityAudit(root, 'high', async () => {
      await writeFile(join(root, 'bun.lock'), 'different inventory');
      return { exitCode: 0, stdout: '{}', stderr: '' };
    });
    expect(auditAllowsProgress(report)).toBe(false);
    expect(report.outcome.status).toBe('error');
  });

  it('blocks mismatched runtime before executing audit', async () => {
    const root = await fixture();
    await writeFile(
      join(root, 'package.json'),
      '{"packageManager":"bun@0.0.0"}',
    );
    const report = await runSecurityAudit(root, 'high', async () => {
      throw new Error('must not execute');
    });
    expect(auditAllowsProgress(report)).toBe(false);
  });

  it('classifies unavailable tool as execution failure', async () => {
    const result = await executeAudit(
      ['/definitely-missing-g6-audit'],
      await fixture(),
    );
    expect(result.exitCode).toBeNull();
    expect(result.stderr).not.toBe('');
  });

  it('captures a real process exit and JSON output without a shell', async () => {
    const result = await executeAudit(
      [process.execPath, '--print', 'JSON.stringify({})'],
      await fixture(),
    );
    expect(result).toEqual({ exitCode: 0, stdout: '{}\n', stderr: '' });
  });

  it('does not turn successful exit with stderr into clean evidence', async () => {
    const report = await runSecurityAudit(
      await fixture(),
      'high',
      async () => ({
        exitCode: 0,
        stdout: '{}',
        stderr: 'skipped registry',
      }),
    );
    expect(auditAllowsProgress(report)).toBe(false);
  });
});
