/**
 * @fileoverview One supervised native Git lifecycle for Node and Bun.
 * @module services/git/providers/cli/utils/runtime-adapter
 */
import {
  assertGitExecutionPolicy,
  type GitExecutionPolicy,
} from './execution-policy.js';
import {
  assertConfiguredGitExecutionPolicy,
  getConfiguredGitExecutionLimits,
} from './configured-execution-policy.js';
import {
  superviseProcess,
  type SupervisedProcessResult,
} from './process-supervision.js';
import { buildGitEnv } from './command-builder.js';

/** Complete lossless UTF-8 output. Signals and execution-control failures reject. */
export type GitCommandResult = SupervisedProcessResult;

/** Internal server-owned spawn settings. */
export interface SpawnGitOptions {
  timeout?: number | undefined;
  signal?: AbortSignal | undefined;
  deadline?: number | undefined;
  allowNonZeroExit?: boolean | undefined;
  policy?: GitExecutionPolicy | undefined;
}

/** Report the runtime without changing the process-control route. */
export function detectRuntime(): 'bun' | 'node' {
  return typeof globalThis.Bun !== 'undefined' || process.versions.bun
    ? 'bun'
    : 'node';
}

/**
 * Spawn the controlled absolute Git binary. Both streams drain concurrently,
 * bytes are bounded before retention, and settlement waits for group cleanup.
 */
export async function spawnGitCommand(
  args: string[],
  cwd: string,
  env: Record<string, string>,
  timeout?: number,
  signal?: AbortSignal,
  allowNonZeroExit = false,
  options: SpawnGitOptions = {},
): Promise<GitCommandResult> {
  const policy = options.policy ?? assertConfiguredGitExecutionPolicy();
  assertGitExecutionPolicy(policy);
  const limits = getConfiguredGitExecutionLimits();
  return superviseProcess({
    ...limits,
    timeoutMs: Math.min(
      options.timeout ?? timeout ?? limits.timeoutMs,
      limits.timeoutMs,
    ),
    binaryPath: policy.binaryPath,
    args,
    cwd,
    env: buildGitEnv(env, policy),
    signal: options.signal ?? signal,
    deadline: options.deadline,
    allowNonZeroExit: options.allowNonZeroExit ?? allowNonZeroExit,
  });
}
