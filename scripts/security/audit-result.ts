/**
 * @fileoverview Fail-closed classification of Bun's npm bulk-advisory JSON.
 * @module scripts/security/audit-result
 */

/** Captured process evidence; neither stdout nor exit status alone proves success. */
export interface AuditExecution {
  exitCode: number | null;
  stdout: string;
  stderr: string;
}

/** Recognized severities; the selected policy determines which findings block. */
export const AUDIT_SEVERITIES = [
  'info',
  'low',
  'moderate',
  'high',
  'critical',
] as const;

/** Validated advisory identity; raw registry text is not echoed by the gate. */
export interface AuditFinding {
  packageName: string;
  id: number;
  severity: (typeof AUDIT_SEVERITIES)[number];
  url: string;
}

/** Preserve High/Critical acceptance by default; `all` is an explicit strict mode. */
export type AuditPolicy = 'high' | 'all';

/** Exit filtering must be declared; it never changes the unfiltered JSON findings. */
export type AuditExitProfile = 'unfiltered' | 'high-filtered';

/** A completed clean audit differs from policy findings and incomplete execution. */
export type AuditOutcome =
  | { status: 'clean'; findings: [] }
  | { status: 'findings'; findings: AuditFinding[]; blocking: boolean }
  | { status: 'error'; reason: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Classify the unfiltered `bun audit --json` bulk response. The caller must use
 * no severity/ignore filters. Bun uses exit 1 for both findings and failures;
 * stderr, unsupported statuses, incomplete records and format drift fail closed.
 * A valid empty bulk response is `{}`, never an empty stream or summary phrase.
 */
export function classifyAuditResult(
  result: AuditExecution,
  policy: AuditPolicy = 'high',
  exitProfile: AuditExitProfile = 'unfiltered',
): AuditOutcome {
  if (result.stderr.trim()) {
    return { status: 'error', reason: 'Audit emitted stderr diagnostics.' };
  }
  if (result.exitCode !== 0 && result.exitCode !== 1) {
    return {
      status: 'error',
      reason: 'Audit execution did not complete normally.',
    };
  }
  if (!result.stdout.trim()) {
    return {
      status: 'error',
      reason: 'Audit returned no structured response.',
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    return {
      status: 'error',
      reason: 'Audit response is not one JSON document.',
    };
  }
  if (!isRecord(parsed)) {
    return { status: 'error', reason: 'Unsupported audit response schema.' };
  }

  const findings: AuditFinding[] = [];
  for (const [packageName, advisories] of Object.entries(parsed)) {
    if (
      !/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(packageName) ||
      !Array.isArray(advisories) ||
      advisories.length === 0
    ) {
      return { status: 'error', reason: 'Incomplete bulk-advisory response.' };
    }
    for (const advisory of advisories) {
      if (
        !isRecord(advisory) ||
        !Number.isSafeInteger(advisory.id) ||
        (advisory.id as number) <= 0 ||
        typeof advisory.title !== 'string' ||
        !advisory.title.trim() ||
        typeof advisory.vulnerable_versions !== 'string' ||
        !advisory.vulnerable_versions.trim() ||
        typeof advisory.severity !== 'string' ||
        !AUDIT_SEVERITIES.some((severity) => severity === advisory.severity) ||
        typeof advisory.url !== 'string' ||
        !URL.canParse(advisory.url) ||
        new URL(advisory.url).protocol !== 'https:' ||
        (advisory.name !== undefined && advisory.name !== packageName)
      ) {
        return {
          status: 'error',
          reason: 'Incomplete or unknown advisory schema.',
        };
      }
      findings.push({
        packageName,
        id: advisory.id as number,
        severity: advisory.severity as AuditFinding['severity'],
        url: advisory.url,
      });
    }
  }

  if (findings.length === 0 && result.exitCode === 0) {
    return { status: 'clean', findings: [] };
  }
  const hasHigh = findings.some(
    (finding) => finding.severity === 'high' || finding.severity === 'critical',
  );
  const expectedFindingsExit =
    exitProfile === 'high-filtered' && !hasHigh ? 0 : 1;
  if (findings.length > 0 && result.exitCode === expectedFindingsExit) {
    return {
      status: 'findings',
      findings,
      blocking: policy === 'all' || hasHigh,
    };
  }
  return {
    status: 'error',
    reason: 'Audit exit status contradicts its response.',
  };
}
