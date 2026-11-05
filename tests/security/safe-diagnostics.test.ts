/**
 * @fileoverview Telemetry diagnostic console privacy, bounds and failure paths.
 * @module tests/security/safe-diagnostics
 */
import { describe, expect, it, spyOn } from 'bun:test';
import { safeDiagnosticLogger } from '@/utils/telemetry/safe-diagnostics.js';

describe('telemetry diagnostics', () => {
  it('uses only payload-free stderr console methods by default', () => {
    const error = spyOn(console, 'error').mockImplementation(() => {});
    const warning = spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const diagnostics = safeDiagnosticLogger();
      for (const level of [
        'error',
        'warn',
        'info',
        'debug',
        'verbose',
      ] as const)
        diagnostics[level]('SYNTHETIC_CONSOLE_PRIVATE');
      expect(error).toHaveBeenCalledWith('telemetry.error');
      expect(warning).toHaveBeenCalledTimes(4);
      expect(
        JSON.stringify([error.mock.calls, warning.mock.calls]),
      ).not.toContain('SYNTHETIC_');
    } finally {
      error.mockRestore();
      warning.mockRestore();
    }
  });
  it('drops every raw argument including URLs, nested claims, exceptions and non-JSON values', () => {
    const captures: unknown[] = [];
    const diagnostics = safeDiagnosticLogger((...args) => captures.push(args));
    const sentinel = 'SYNTHETIC_DIAGNOSTIC_PRIVATE';
    for (const level of ['error', 'warn', 'info', 'debug', 'verbose'] as const)
      diagnostics[level](
        `https://synthetic:${sentinel}@example.invalid/`,
        new Error(sentinel),
        { claims: [sentinel] },
        Symbol(sentinel),
      );
    expect(captures).toHaveLength(5);
    expect(JSON.stringify(captures)).not.toContain(sentinel);
    expect(captures).toContainEqual(['error', 'telemetry.error']);
  });

  it('bounds diagnostic emission under unique error strings without a raw fallback', () => {
    let emissions = 0;
    const diagnostics = safeDiagnosticLogger(() => {
      emissions++;
      throw new Error('SYNTHETIC_SINK_ERROR');
    });
    for (let i = 0; i < 20_000; i++)
      expect(() => diagnostics.error(`SYNTHETIC_UNIQUE_${i}`)).not.toThrow();
    expect(emissions).toBe(10);
  });
});
