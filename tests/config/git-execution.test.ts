/**
 * @fileoverview Validation and upgrade defaults for native Git execution.
 * @module tests/config/git-execution.test
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { parseConfig } from '../../src/config/index.js';

describe('native Git execution configuration', () => {
  let saved: NodeJS.ProcessEnv;
  const keys = [
    'GIT_EXECUTION_PROFILE',
    'GIT_BINARY_PATH',
    'GIT_TRUSTED_HOME',
    'GIT_TRUSTED_PATH',
    'GIT_MAX_COMMAND_TIMEOUT_MS',
    'GIT_MAX_BUFFER_SIZE_MB',
    'GIT_MAX_OUTPUT_BYTES',
    'GIT_MAX_STDOUT_BYTES',
    'GIT_MAX_STDERR_BYTES',
    'GIT_TERMINATION_GRACE_MS',
  ];
  beforeEach(() => {
    saved = { ...process.env };
    for (const key of keys) delete process.env[key];
  });
  afterEach(() => {
    process.env = saved;
  });
  it('defaults to restricted with validated legacy aggregate output fallback', () => {
    const git = parseConfig().git;
    expect(git.executionProfile).toBe('restricted');
    expect(git.binaryPath).toBe('/usr/bin/git');
    expect(git.maxCommandTimeoutMs).toBe(30000);
    expect(git.maxOutputBytes).toBe(10 * 1024 * 1024);
    expect(git.maxStdoutBytes).toBe(git.maxOutputBytes);
    expect(git.maxStderrBytes).toBe(git.maxOutputBytes);
  });
  it('requires explicit trusted opt-in and resolves independently configured byte caps', () => {
    Object.assign(process.env, {
      GIT_EXECUTION_PROFILE: 'trusted',
      GIT_MAX_OUTPUT_BYTES: '9',
      GIT_MAX_STDOUT_BYTES: '5',
      GIT_MAX_STDERR_BYTES: '7',
      GIT_TERMINATION_GRACE_MS: '0',
    });
    const git = parseConfig().git;
    expect(git.executionProfile).toBe('trusted');
    expect([
      git.maxOutputBytes,
      git.maxStdoutBytes,
      git.maxStderrBytes,
      git.terminationGraceMs,
    ]).toEqual([9, 5, 7, 0]);
  });
  for (const [key, value] of [
    ['GIT_EXECUTION_PROFILE', 'permissive'],
    ['GIT_BINARY_PATH', 'git'],
    ['GIT_TRUSTED_HOME', 'relative'],
    ['GIT_TRUSTED_PATH', '/bin:.'],
    ['GIT_TRUSTED_PATH', '/bin:'],
    ['GIT_MAX_COMMAND_TIMEOUT_MS', '0'],
    ['GIT_MAX_COMMAND_TIMEOUT_MS', '2147483648'],
    ['GIT_MAX_OUTPUT_BYTES', '0'],
    ['GIT_MAX_STDOUT_BYTES', '1.5'],
    ['GIT_MAX_STDERR_BYTES', '134217729'],
    ['GIT_MAX_BUFFER_SIZE_MB', 'Infinity'],
    ['GIT_TERMINATION_GRACE_MS', '5001'],
  ]) {
    it(`rejects invalid ${key} at startup`, () => {
      process.env[key!] = value;
      expect(() => parseConfig()).toThrow();
    });
  }
});
