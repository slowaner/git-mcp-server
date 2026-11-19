/**
 * @fileoverview Current artifact scans never inherit historical fixture dispositions.
 * @module tests/scripts/security/secret-result
 */
import { describe, expect, it } from 'bun:test';
import { assertZeroSecretScan } from '../../../scripts/security/secret-result.js';

describe('zero-only artifact secret gate', () => {
  const clean = { exitCode: 0, stderr: '', executionError: false, report: [] };
  it('accepts only a completed structured zero-finding result', () => {
    expect(() => assertZeroSecretScan(clean)).not.toThrow();
  });
  for (const mutation of [
    { exitCode: 1 },
    { exitCode: null },
    { exitCode: 2 },
    { stderr: 'permission failure' },
    { executionError: true },
    { report: undefined },
    { report: '' },
    { report: {} },
    { report: null },
    { report: [{ Fingerprint: 'assessed-history-fixture' }] },
  ])
    it(`blocks incomplete or nonzero result ${Object.keys(mutation)[0]} ${JSON.stringify(mutation)}`, () => {
      expect(() => assertZeroSecretScan({ ...clean, ...mutation })).toThrow();
    });
});
