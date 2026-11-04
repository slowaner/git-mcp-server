#!/usr/bin/env bun
/**
 * @fileoverview CLI security gate with explicit findings and execution failure states.
 * @module scripts/security-audit
 */
import { fileURLToPath } from 'node:url';
import {
  auditAllowsProgress,
  runSecurityAudit,
} from './security/audit-runner.js';

if (import.meta.main) {
  const args = process.argv.slice(2);
  if (args.some((arg) => arg !== '--strict')) {
    console.error('Usage: bun scripts/security-audit.ts [--strict]');
    process.exitCode = 2;
  } else {
    try {
      const report = await runSecurityAudit(
        fileURLToPath(new URL('..', import.meta.url)),
        args.includes('--strict') ? 'all' : 'high',
      );
      // Structured report contains validated identities, never raw stderr/tokens.
      console.log(JSON.stringify(report, null, 2));
      process.exitCode = auditAllowsProgress(report) ? 0 : 1;
    } catch {
      console.error(
        'Audit infrastructure/input failure; no completed audit evidence.',
      );
      process.exitCode = 2;
    }
  }
}
