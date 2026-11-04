/**
 * @fileoverview Exact approved historical fixture disposition; no current-tree exception.
 * @module scripts/security/history-result
 */
import { TOOLCHAIN_PINS } from './toolchain-pins.js';

/** Independently assessed immutable occurrences; each must occur exactly once. */
export const ASSESSED_HISTORY_FIXTURES = [
  {
    Commit: 'd5a8b134e0fe0d7da04a2dca9c382098c2539cff',
    File: 'tests/utils/security/sanitization.test.ts',
    RuleID: 'generic-api-key',
    StartLine: 157,
    EndLine: 157,
    Fingerprint:
      'd5a8b134e0fe0d7da04a2dca9c382098c2539cff:tests/utils/security/sanitization.test.ts:generic-api-key:157',
  },
  {
    Commit: '24ae3e7f753f71b613053483a4bc9d0baac118c8',
    File: 'tests/utils/security/sanitization.test.ts',
    RuleID: 'generic-api-key',
    StartLine: 157,
    EndLine: 157,
    Fingerprint:
      '24ae3e7f753f71b613053483a4bc9d0baac118c8:tests/utils/security/sanitization.test.ts:generic-api-key:157',
  },
] as const;

/** Exact ancestry containing both assessed occurrences; no unrelated-ref waiver. */
export const HISTORY_POLICY_ANCHOR = '79c371bdaa37463199deb029d23fb8ba7d0baa47';

/** Full traversal; first-parent applies only to merge diff presentation. */
export function historyLogOptions(ref: string): string {
  if (!/^[0-9a-f]{40}$/.test(ref))
    throw new Error('Exact history commit required.');
  return `--full-history --diff-merges=first-parent ${ref} --`;
}

/** Safe fields only; suspected values and match text never leave this module. */
export interface HistoryFinding {
  Commit: string;
  File: string;
  RuleID: string;
  StartLine: number;
  EndLine: number;
  Fingerprint: string;
}

/** Verified process, ref coverage and embedded scanner rule provenance. */
export interface HistoryEvidence {
  ref: string;
  before: string;
  after: string;
  scannerVersion: string;
  scannerArchiveSha256: string;
  rulesSha256: string;
  rulesBytes: number;
  rulesGitBlob: string;
  ignoreSha256: string;
  logOptions: string;
  shallow: boolean;
  anchor: string;
  anchorReachable: boolean;
  reachableCommits: number;
  alteredHistory: boolean;
  exitCode: number | null;
  stderr: string;
  executionError: boolean;
  report: unknown;
}

/** Accepted fixture is visible and distinct from zero findings. */
export interface HistoryOutcome {
  status: 'accepted-history-fixtures' | 'blocked-findings' | 'error';
  findings: HistoryFinding[];
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Only both exact approved historical occurrences can satisfy this history gate.
 * Never use this classifier for current/staged-tree scans. Unknown findings,
 * duplicates, incomplete metadata and any process/provenance error block.
 */
export function classifyHistoryScan(
  evidence: HistoryEvidence,
  expectedRef: string,
  profile: 'linuxX64' | 'darwinArm64',
): HistoryOutcome {
  const error: HistoryOutcome = { status: 'error', findings: [] };
  if (
    !/^[0-9a-f]{40}$/.test(expectedRef) ||
    evidence.ref !== expectedRef ||
    evidence.before !== expectedRef ||
    evidence.after !== expectedRef ||
    evidence.scannerVersion !== TOOLCHAIN_PINS.gitleaks.version ||
    evidence.scannerArchiveSha256 !== TOOLCHAIN_PINS.gitleaks[profile].sha256 ||
    evidence.rulesSha256 !== TOOLCHAIN_PINS.gitleaks.rulesSha256 ||
    evidence.rulesBytes !== TOOLCHAIN_PINS.gitleaks.rulesBytes ||
    evidence.rulesGitBlob !== TOOLCHAIN_PINS.gitleaks.rulesGitBlob ||
    evidence.ignoreSha256 !== TOOLCHAIN_PINS.gitleaks.emptyIgnoreSha256 ||
    evidence.logOptions !== historyLogOptions(expectedRef) ||
    evidence.shallow !== false ||
    evidence.anchor !== HISTORY_POLICY_ANCHOR ||
    evidence.anchorReachable !== true ||
    !Number.isSafeInteger(evidence.reachableCommits) ||
    evidence.reachableCommits < 422 ||
    evidence.alteredHistory !== false ||
    evidence.executionError ||
    evidence.stderr.trim() ||
    ![0, 1].includes(evidence.exitCode as number) ||
    !Array.isArray(evidence.report)
  )
    return error;
  const findings: HistoryFinding[] = [];
  const seen = new Set<string>();
  for (const row of evidence.report) {
    if (
      !object(row) ||
      typeof row.Commit !== 'string' ||
      !/^[0-9a-f]{40}$/.test(row.Commit) ||
      typeof row.File !== 'string' ||
      !row.File ||
      row.File.startsWith('/') ||
      /[\x00-\x1f\x7f]/.test(row.File) ||
      row.File.split('/').includes('..') ||
      typeof row.RuleID !== 'string' ||
      !/^[a-z0-9-]+$/.test(row.RuleID) ||
      !Number.isSafeInteger(row.StartLine) ||
      (row.StartLine as number) < 1 ||
      !Number.isSafeInteger(row.EndLine) ||
      (row.EndLine as number) < (row.StartLine as number) ||
      typeof row.Fingerprint !== 'string' ||
      row.Fingerprint !==
        `${row.Commit}:${row.File}:${row.RuleID}:${row.StartLine}` ||
      seen.has(row.Fingerprint)
    )
      return error;
    seen.add(row.Fingerprint);
    findings.push({
      Commit: row.Commit,
      File: row.File,
      RuleID: row.RuleID,
      StartLine: row.StartLine as number,
      EndLine: row.EndLine as number,
      Fingerprint: row.Fingerprint,
    });
  }
  if (findings.length === 0) return error;
  if (evidence.exitCode !== 1) return error;
  const exact =
    findings.length === ASSESSED_HISTORY_FIXTURES.length &&
    ASSESSED_HISTORY_FIXTURES.every((expected) =>
      findings.some((finding) =>
        Object.entries(expected).every(
          ([key, value]) => finding[key as keyof HistoryFinding] === value,
        ),
      ),
    );
  return {
    status: exact ? 'accepted-history-fixtures' : 'blocked-findings',
    findings,
  };
}
