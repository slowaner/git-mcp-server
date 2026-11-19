/**
 * @fileoverview Audit evidence must never turn infrastructure failure green.
 * @module tests/scripts/security/audit-result
 */
import { describe, expect, it } from 'bun:test';
import {
  AUDIT_SEVERITIES,
  classifyAuditResult,
} from '../../../scripts/security/audit-result.js';
import { auditAllowsProgress } from '../../../scripts/security/audit-runner.js';

const advisory = {
  id: 1234,
  title: 'Synthetic vulnerable dependency',
  severity: 'high',
  vulnerable_versions: '<2.0.0',
  url: 'https://github.com/advisories/GHSA-test-only',
};
const execution = { exitCode: 0, stdout: '{}', stderr: '' };

// Minimal shape-preserving fixture from G4's 2026-11-03 bulk response. Prose,
// CWE and CVSS details sanitized; raw command logs stay outside the repository.
const moderateExample = {
  glob: [
    {
      id: 1244013,
      url: 'https://github.com/advisories/GHSA-3g3m-2fjr-6pw4',
      severity: 'moderate',
      vulnerable_versions: '>=9.0.0 <=14.0.1',
      title:
        'Sanitized text may mention critical; structured severity controls policy.',
      cwe: [],
      cvss: { score: 0, vectorString: null },
    },
  ],
  minimatch: [
    {
      id: 1244012,
      url: 'https://github.com/advisories/GHSA-g3hv-75wg-m249',
      severity: 'moderate',
      vulnerable_versions: '<11.0.1',
      title: 'Sanitized real-shape fixture',
      cwe: [],
      cvss: { score: 0, vectorString: null },
    },
  ],
};

describe('audit evidence classification', () => {
  it('permits recognized Moderate findings with unfiltered CLI exit 1', () => {
    const outcome = classifyAuditResult({
      exitCode: 1,
      stdout: JSON.stringify(moderateExample),
      stderr: '',
    });
    expect(outcome.status).toBe('findings');
    expect(
      auditAllowsProgress({
        schemaVersion: 1,
        checkedAt: '',
        bunVersion: '1.4.3',
        packageSha256: '',
        lockSha256: '',
        policy: 'high',
        outcome,
      }),
    ).toBe(true);
  });
  it('does not label high-filtered exit 0 as zero vulnerabilities', () => {
    const result = {
      exitCode: 0,
      stdout: JSON.stringify(moderateExample),
      stderr: '',
    };
    const outcome = classifyAuditResult(result, 'high', 'high-filtered');
    expect(outcome.status).toBe('findings');
    expect(outcome.status === 'findings' && outcome.findings.length).toBe(2);
    expect(classifyAuditResult(result).status).toBe('error');
  });
  it('blocks diagnostics even alongside recognized policy-permitted findings', () => {
    expect(
      classifyAuditResult({
        exitCode: 1,
        stdout: JSON.stringify(moderateExample),
        stderr: 'registry skipped',
      }).status,
    ).toBe('error');
  });
  it('accepts only a completed structured zero-findings response', () => {
    expect(classifyAuditResult(execution)).toEqual({
      status: 'clean',
      findings: [],
    });
  });

  for (const severity of AUDIT_SEVERITIES) {
    it(`classifies valid ${severity} findings under the existing High/Critical policy`, () => {
      expect(
        classifyAuditResult({
          exitCode: 1,
          stdout: JSON.stringify({
            '@example/dependency': [{ ...advisory, severity }],
          }),
          stderr: '',
        }),
      ).toEqual({
        status: 'findings',
        blocking: severity === 'high' || severity === 'critical',
        findings: [
          {
            packageName: '@example/dependency',
            id: advisory.id,
            severity,
            url: advisory.url,
          },
        ],
      });
    });
  }

  it('supports explicit strict all-severities policy without changing the default', () => {
    const result = classifyAuditResult(
      {
        exitCode: 1,
        stdout: JSON.stringify({
          dependency: [{ ...advisory, severity: 'low' }],
        }),
        stderr: '',
      },
      'all',
    );
    expect(result.status === 'findings' && result.blocking).toBe(true);
  });

  const failures = [
    { ...execution, exitCode: 1 },
    { ...execution, exitCode: 127 },
    { ...execution, exitCode: 137 },
    { ...execution, exitCode: null },
    { ...execution, stdout: '' },
    { ...execution, stdout: '   ' },
    { ...execution, stdout: '0 vulnerabilities found' },
    {
      ...execution,
      exitCode: 1,
      stderr: 'audit request failed: network unavailable',
    },
    { ...execution, exitCode: 1, stdout: '', stderr: 'permission denied' },
    { ...execution, stderr: 'skipped private registry' },
    { ...execution, stdout: '{' },
    { ...execution, stdout: '{}\n{}' },
    { ...execution, stdout: '[]' },
    { ...execution, stdout: 'null' },
    { ...execution, stdout: '{"error":"registry failure"}' },
    { ...execution, stdout: '{"dependency":[]}' },
    { ...execution, stdout: JSON.stringify({ dependency: [advisory] }) },
    {
      ...execution,
      exitCode: 1,
      stdout: JSON.stringify({
        dependency: [{ ...advisory, severity: 'unknown' }],
      }),
    },
    {
      ...execution,
      exitCode: 1,
      stdout: JSON.stringify({ dependency: [{ ...advisory, id: null }] }),
    },
    {
      ...execution,
      exitCode: 1,
      stdout: JSON.stringify({
        dependency: [{ ...advisory, vulnerable_versions: '' }],
      }),
    },
    {
      ...execution,
      exitCode: 1,
      stdout: JSON.stringify({
        dependency: [{ ...advisory, url: 'file:///tmp/untrusted' }],
      }),
    },
    {
      ...execution,
      exitCode: 1,
      stdout: JSON.stringify({ dependency: [{ ...advisory, name: 'other' }] }),
    },
    {
      ...execution,
      exitCode: 1,
      stdout: JSON.stringify({ dependency: [advisory, { id: 2 }] }),
    },
  ];

  for (const [index, failure] of failures.entries()) {
    it(`blocks incomplete, inconsistent or failed execution ${index + 1}`, () => {
      expect(classifyAuditResult(failure).status).toBe('error');
    });
  }
});
