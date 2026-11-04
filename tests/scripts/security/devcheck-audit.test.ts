/**
 * @fileoverview Registered devcheck gate cannot rewrite unknown audit failures.
 * @module tests/scripts/security/devcheck-audit
 */
import { afterEach, beforeEach, describe, expect, it, spyOn } from 'bun:test';
import { ALL_CHECKS, runCheck } from '../../../scripts/devcheck.js';
// Typecheck the guarded Linux CI program without executing its native fixture.
import '../../../scripts/security/linux-filename-profile.js';

let log: ReturnType<typeof spyOn>;
beforeEach(() => {
  log = spyOn(console, 'log').mockImplementation(() => {});
});
afterEach(() => {
  log.mockRestore();
});

describe('registered devcheck security gate', () => {
  for (const failure of [
    { exitCode: 1, stdout: '', stderr: 'network failure' },
    { exitCode: 127, stdout: '', stderr: 'permission denied' },
    { exitCode: 1, stdout: '0 vulnerabilities found', stderr: '' },
    { exitCode: 2, stdout: '{}', stderr: '' },
  ]) {
    it(`preserves execution failure ${failure.exitCode}/${failure.stdout}`, async () => {
      const check = ALL_CHECKS.find(
        (candidate) => candidate.name === 'Security Audit',
      )!;
      expect(check.isSuccess).toBeUndefined();
      const result = await runCheck(
        check,
        {
          flags: new Set(),
          noFix: true,
          isHuskyHook: false,
          rootDir: process.cwd(),
          stagedFiles: [],
        },
        async (command) => {
          expect(command[0]).toBe(process.execPath);
          expect(command[1]).toEndWith('/scripts/security-audit.ts');
          return failure;
        },
      );
      expect(result.exitCode).toBe(failure.exitCode);
    });
  }
});
