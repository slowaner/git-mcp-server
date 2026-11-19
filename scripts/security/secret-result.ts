/**
 * @fileoverview Current artifacts require structured zero findings, never history exceptions.
 * @module scripts/security/secret-result
 */

/** Execution, diagnostics and parsed report must all establish a complete clean scan. */
export function assertZeroSecretScan(result: {
  exitCode: number | null;
  stderr: string;
  executionError: boolean;
  report: unknown;
}): void {
  if (
    result.executionError ||
    result.exitCode !== 0 ||
    result.stderr.trim() ||
    !Array.isArray(result.report) ||
    result.report.length !== 0
  )
    throw new Error('Secret scan failed, incomplete, or contains findings.');
}
