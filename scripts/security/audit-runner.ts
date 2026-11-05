/**
 * @fileoverview Bounded audit process and exact-input evidence collection.
 * @module scripts/security/audit-runner
 */
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  classifyAuditResult,
  type AuditExecution,
  type AuditOutcome,
  type AuditPolicy,
} from './audit-result.js';
import { sha256 } from './release-evidence.js';

/** Execution adapter supports offline regression tests, never a shell string. */
export type AuditExecutor = (
  command: string[],
  cwd: string,
) => Promise<AuditExecution>;

/** Evidence binds completion and policy to manifests, lock and exact runtime. */
export interface AuditReport {
  schemaVersion: 1;
  checkedAt: string;
  bunVersion: string;
  packageSha256: string;
  lockSha256: string;
  policy: AuditPolicy;
  outcome: AuditOutcome;
}

/** Default process has a deadline and combined output limit; signal/error is failure. */
export const executeAudit: AuditExecutor = async (command, cwd) => {
  const [binary, ...args] = command;
  if (!binary) throw new Error('Missing audit executable.');
  const result = spawnSync(binary, args, {
    cwd,
    encoding: 'utf8',
    timeout: 60_000,
    killSignal: 'SIGKILL',
    maxBuffer: 16 * 1024 * 1024,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error || result.signal) {
    return {
      exitCode: null,
      stdout: '',
      stderr: 'Audit execution failed, timed out, or exceeded output budget.',
    };
  }
  return {
    exitCode: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
};

/**
 * Audit all locked dependencies with unfiltered JSON, without caches or skips.
 * A manifest/lock change during the operation invalidates the complete result.
 * Use the running Bun binary after checking its packageManager pin, not PATH.
 * Pinned Bun reports unaudited registries on stderr unless CLI --silent is set;
 * keep this fixed argv unfiltered and non-silent so incomplete coverage blocks.
 */
export async function runSecurityAudit(
  root: string,
  policy: AuditPolicy = 'high',
  execute: AuditExecutor = executeAudit,
): Promise<AuditReport> {
  const inputs = async () =>
    Promise.all([
      readFile(join(root, 'package.json'), 'utf8'),
      readFile(join(root, 'bun.lock'), 'utf8'),
    ]);
  const [pkg, lock] = await inputs();
  const report: AuditReport = {
    schemaVersion: 1,
    checkedAt: new Date().toISOString(),
    bunVersion: Bun.version,
    packageSha256: sha256(pkg),
    lockSha256: sha256(lock),
    policy,
    outcome: { status: 'error', reason: 'Audit has not completed.' },
  };
  if (JSON.parse(pkg).packageManager !== `bun@${Bun.version}` || !lock.trim()) {
    report.outcome = {
      status: 'error',
      reason: 'Bun version or lockfile does not match pinned inputs.',
    };
    return report;
  }
  report.outcome = classifyAuditResult(
    await execute([process.execPath, 'audit', '--json'], root),
    policy,
  );
  const [afterPkg, afterLock] = await inputs();
  if (afterPkg !== pkg || afterLock !== lock) {
    report.outcome = {
      status: 'error',
      reason: 'Audit inputs changed during execution.',
    };
  }
  return report;
}

/** Only structured clean or explicitly policy-permitted findings allow progress. */
export function auditAllowsProgress(report: AuditReport): boolean {
  return (
    report.outcome.status === 'clean' ||
    (report.outcome.status === 'findings' && !report.outcome.blocking)
  );
}
