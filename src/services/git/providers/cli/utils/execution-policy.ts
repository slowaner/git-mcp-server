/**
 * @fileoverview Validate native Git execution and build its operator environment.
 * @module services/git/providers/cli/utils/execution-policy
 */
import { delimiter, isAbsolute } from 'node:path';

import { GitExecutionError } from './execution-errors.js';

/** G1 supplies this after canonical repository authorization, never tool input. */
export interface GitRepositoryExecutionBoundary {
  canonicalWorkingDirectory: string;
  canonicalRoots: readonly string[];
  /** Attacker-writable repositories require OS containment. */
  repositoryTrust: 'operator-trusted' | 'untrusted';
}

/** Operator-owned process policy; repository configuration cannot change it. */
export interface GitExecutionPolicy {
  binaryPath: string;
  homeDirectory: string;
  helperPath: string;
}

/**
 * Check that native execution is supported before discovery or spawn.
 * Reject repositories explicitly classified as untrusted by the caller.
 */
export function assertGitExecutionPolicy(
  policy: GitExecutionPolicy,
  boundary?: GitRepositoryExecutionBoundary,
): void {
  if (boundary?.repositoryTrust === 'untrusted') {
    throw new GitExecutionError(
      'POLICY_UNSUPPORTED',
      'Native Git execution requires an operator-trusted repository.',
    );
  }
  if (process.platform !== 'linux' && process.platform !== 'darwin') {
    throw new GitExecutionError(
      'POLICY_UNSUPPORTED',
      'Git process supervision unavailable on this platform; no supported process-group or Job Object backend.',
    );
  }
  if (
    !isAbsolute(policy.binaryPath) ||
    policy.binaryPath.includes('\0') ||
    !isAbsolute(policy.homeDirectory) ||
    policy.homeDirectory.includes('\0') ||
    !policy.helperPath ||
    policy.helperPath.includes('\0') ||
    !policy.helperPath.split(delimiter).every((entry) => isAbsolute(entry))
  ) {
    throw new GitExecutionError(
      'INVALID_EXECUTION_OPTIONS',
      'Git binary and HOME must be absolute; helper PATH must be explicitly configured.',
    );
  }
}

/**
 * Build the deliberate native-trust environment. Inherited GIT_* routing/config,
 * loader options and arbitrary server secrets are never copied. Native Git config
 * under the operator HOME/system/repository, signing, agents and network helpers
 * remain trusted authority, not isolation. Author identity is added by the caller.
 */
export function buildTrustedGitEnvironment(
  policy: GitExecutionPolicy,
  inherited: NodeJS.ProcessEnv,
): Record<string, string> {
  assertGitExecutionPolicy(policy);
  const env: Record<string, string> = {
    HOME: policy.homeDirectory,
    PATH: policy.helperPath,
    GIT_TERMINAL_PROMPT: '0',
    GIT_PAGER: 'cat',
    GIT_EDITOR: 'true',
    GIT_SEQUENCE_EDITOR: 'true',
    LANG: 'en_US.UTF-8',
    LC_ALL: 'en_US.UTF-8',
  };
  for (const key of [
    'USER',
    'LOGNAME',
    'TMPDIR',
    'TMP',
    'TEMP',
    'SSH_AUTH_SOCK',
    'GNUPGHOME',
    'SSL_CERT_FILE',
    'SSL_CERT_DIR',
    'CURL_CA_BUNDLE',
    'HTTP_PROXY',
    'HTTPS_PROXY',
    'ALL_PROXY',
    'NO_PROXY',
    'http_proxy',
    'https_proxy',
    'all_proxy',
    'no_proxy',
  ]) {
    const value = inherited[key];
    if (value !== undefined) env[key] = value;
  }
  return env;
}
