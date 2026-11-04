/**
 * @fileoverview Complete CodeQL evidence required even when analyzer exits zero.
 * @module tests/scripts/security/sarif-result
 */
import { describe, expect, it } from 'bun:test';
import { evaluateSarif } from '../../../scripts/check-sarif.js';

function report(severity?: string) {
  return {
    version: '2.1.0',
    runs: [
      {
        invocations: [{ executionSuccessful: true }],
        tool: {
          driver: {
            rules: [
              {
                id: 'js/example',
                properties: { 'security-severity': severity },
              },
            ],
          },
        },
        results: severity === undefined ? [] : [{ ruleId: 'js/example' }],
      },
    ],
  };
}

describe('CodeQL result gate', () => {
  it('accepts complete clean and explicitly lower-severity analyses', () => {
    expect(evaluateSarif(report())).toBe('allowed');
    expect(evaluateSarif(report('6.9'))).toBe('allowed');
  });
  for (const severity of ['7', '7.0', '9.9', '10']) {
    it(`blocks security severity ${severity}`, () => {
      expect(evaluateSarif(report(severity))).toBe('findings');
    });
  }
  for (const severity of ['', '-1', 'NaN', 'unknown', '10.1']) {
    it(`blocks unsupported severity ${severity}`, () => {
      expect(evaluateSarif(report(severity))).toBe('error');
    });
  }
  it('blocks empty, truncated and failed reports', () => {
    expect(evaluateSarif({})).toBe('error');
    expect(evaluateSarif({ version: '2.1.0', runs: [] })).toBe('error');
    const failed = report();
    failed.runs[0]!.invocations[0]!.executionSuccessful = false;
    expect(evaluateSarif(failed)).toBe('error');
    failed.runs[0]!.invocations = [];
    expect(evaluateSarif(failed)).toBe('error');
  });
  it('blocks a result whose rule metadata is missing', () => {
    const partial = report('8.0');
    partial.runs[0]!.tool.driver.rules = [];
    expect(evaluateSarif(partial)).toBe('error');
  });
});
