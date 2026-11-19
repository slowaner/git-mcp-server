/**
 * @fileoverview Exact two historical fixtures require complete canonical scan scope.
 * @module tests/scripts/security/history-result
 */
import { describe, expect, it } from 'bun:test';
import '../../../scripts/check-secret-history.js';
import {
  ASSESSED_HISTORY_FIXTURES,
  HISTORY_POLICY_ANCHOR,
  classifyHistoryScan,
  historyLogOptions,
  type HistoryEvidence,
} from '../../../scripts/security/history-result.js';
import { TOOLCHAIN_PINS } from '../../../scripts/security/toolchain-pins.js';

const ref = 'a'.repeat(40);
function evidence(): HistoryEvidence {
  return {
    ref,
    before: ref,
    after: ref,
    scannerVersion: '8.30.1',
    scannerArchiveSha256: TOOLCHAIN_PINS.gitleaks.linuxX64.sha256,
    rulesSha256: TOOLCHAIN_PINS.gitleaks.rulesSha256,
    rulesBytes: TOOLCHAIN_PINS.gitleaks.rulesBytes,
    rulesGitBlob: TOOLCHAIN_PINS.gitleaks.rulesGitBlob,
    ignoreSha256: TOOLCHAIN_PINS.gitleaks.emptyIgnoreSha256,
    logOptions: historyLogOptions(ref),
    shallow: false,
    anchor: HISTORY_POLICY_ANCHOR,
    anchorReachable: true,
    reachableCommits: 427,
    alteredHistory: false,
    exitCode: 1,
    stderr: '',
    executionError: false,
    report: ASSESSED_HISTORY_FIXTURES.map((row) => ({ ...row })),
  };
}
const classify = (value: HistoryEvidence) =>
  classifyHistoryScan(value, ref, 'linuxX64');

describe('exact two history-only dispositions', () => {
  it('reports accepted-history-fixtures/count2 rather than clean or zero', () => {
    const result = classify(evidence());
    expect(result.status).toBe('accepted-history-fixtures');
    expect(result.findings).toEqual(
      ASSESSED_HISTORY_FIXTURES.map((row) => ({ ...row })),
    );
    expect(
      classify({
        ...evidence(),
        report: [...ASSESSED_HISTORY_FIXTURES].reverse(),
      }).status,
    ).toBe('accepted-history-fixtures');
  });
  it('blocks zero and each missing fixture in known descendant closures', () => {
    expect(classify({ ...evidence(), exitCode: 0, report: [] }).status).toBe(
      'error',
    );
    expect(classify({ ...evidence(), report: [] }).status).toBe('error');
    for (const row of ASSESSED_HISTORY_FIXTURES)
      expect(classify({ ...evidence(), report: [row] }).status).toBe(
        'blocked-findings',
      );
  });
  it('blocks success status contradicting the two findings', () => {
    expect(classify({ ...evidence(), exitCode: 0 }).status).toBe('error');
  });
  for (const mutation of [
    { Commit: 'b'.repeat(40) },
    { File: 'other.test.ts' },
    { RuleID: 'other-rule' },
    { StartLine: 158 },
    { EndLine: 158 },
    { Fingerprint: 'other' },
  ])
    for (const index of [0, 1]) {
      it(`blocks fixture${index} mutation ${Object.keys(mutation)[0]}`, () => {
        const rows = ASSESSED_HISTORY_FIXTURES.map((row) => ({ ...row }));
        rows[index] = { ...rows[index]!, ...mutation } as (typeof rows)[number];
        expect(classify({ ...evidence(), report: rows }).status).not.toBe(
          'accepted-history-fixtures',
        );
      });
    }
  it('blocks an extra internally consistent finding', () => {
    const other = {
      ...ASSESSED_HISTORY_FIXTURES[0],
      Commit: 'b'.repeat(40),
      Fingerprint: `${'b'.repeat(40)}:${ASSESSED_HISTORY_FIXTURES[0].File}:generic-api-key:157`,
    };
    expect(
      classify({ ...evidence(), report: [...ASSESSED_HISTORY_FIXTURES, other] })
        .status,
    ).toBe('blocked-findings');
  });
  it('blocks duplicated, incomplete and malformed finding metadata', () => {
    expect(
      classify({
        ...evidence(),
        report: [...ASSESSED_HISTORY_FIXTURES, ASSESSED_HISTORY_FIXTURES[0]],
      }).status,
    ).toBe('error');
    expect(
      classify({
        ...evidence(),
        report: [{ Fingerprint: ASSESSED_HISTORY_FIXTURES[0].Fingerprint }],
      }).status,
    ).toBe('error');
    expect(classify({ ...evidence(), report: [null] }).status).toBe('error');
  });
  for (const mutation of [
    { ref: 'b'.repeat(40) },
    { before: 'b'.repeat(40) },
    { after: 'b'.repeat(40) },
    { scannerVersion: 'latest' },
    { scannerArchiveSha256: 'unknown' },
    {
      rulesSha256:
        '6a671c074575dec8e6c7550e8bd388b721950b6eac048fde1a21c4884d4e719f',
    },
    { rulesBytes: 97730 },
    { rulesGitBlob: 'unknown' },
    { ignoreSha256: 'unknown' },
    { logOptions: `--full-history --first-parent ${ref} --` },
    { logOptions: `--full-history ${ref} --` },
    { logOptions: '--all' },
    { shallow: true },
    { anchor: 'b'.repeat(40) },
    { anchorReachable: false },
    { reachableCommits: 421 },
    { reachableCommits: 427.5 },
    { alteredHistory: true },
    { executionError: true },
    { stderr: 'infrastructure failure' },
    { exitCode: null },
    { exitCode: 2 },
    { report: null },
    { report: {} },
  ])
    it(`blocks incomplete/untrusted evidence ${Object.keys(mutation)[0]} ${JSON.stringify(mutation)}`, () => {
      expect(classify({ ...evidence(), ...mutation }).status).toBe('error');
    });
});
