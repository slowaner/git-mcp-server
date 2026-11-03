/**
 * @fileoverview Validated operator policy and early Git profile assertion.
 * @module services/git/providers/cli/utils/configured-execution-policy
 */
import { config } from '@/config/index.js';
import { withGitExecutionContext } from './execution-context.js';
import {
  assertGitExecutionPolicy,
  type GitExecutionPolicy,
  type GitRepositoryExecutionBoundary,
} from './execution-policy.js';

/** Stable G1 seam, callable before any repository discovery or filesystem work. */
export function getConfiguredGitExecutionPolicy(): GitExecutionPolicy {
  return {
    profile: config.git.executionProfile,
    binaryPath: config.git.binaryPath,
    homeDirectory: config.git.trustedHome,
    helperPath: config.git.trustedPath,
  };
}

/** Assert actual configured support without native Git or filesystem side effects. */
export function assertConfiguredGitExecutionPolicy(
  boundary?: GitRepositoryExecutionBoundary,
): GitExecutionPolicy {
  const policy = getConfiguredGitExecutionPolicy();
  assertGitExecutionPolicy(policy, boundary);
  return policy;
}

/** Validated limits; maxOutputBytes is resolved, numeric and request-wide. */
export function getConfiguredGitExecutionLimits() {
  return {
    timeoutMs: config.git.maxCommandTimeoutMs,
    maxOutputBytes: config.git.maxOutputBytes,
    maxStdoutBytes: config.git.maxStdoutBytes,
    maxStderrBytes: config.git.maxStderrBytes,
    terminationGraceMs: config.git.terminationGraceMs,
  };
}

/** Own an SDK/provider lifetime; nested operations share its budget and deadline. */
export function withConfiguredGitExecutionContext<T>(
  signal: AbortSignal | undefined,
  operation: () => Promise<T>,
  deadline?: number,
): Promise<T> {
  const startedAt = Date.now();
  return withGitExecutionContext(
    {
      signal,
      startedAt,
      deadline: Math.min(
        startedAt + config.git.maxCommandTimeoutMs,
        deadline ?? Infinity,
      ),
    },
    operation,
  );
}
