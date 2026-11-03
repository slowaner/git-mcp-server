/**
 * @fileoverview Controlled, supervised native Git execution.
 * @module services/git/providers/cli/utils/git-executor
 */
import { existsSync, statSync } from 'node:fs';
import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import { mapGitError } from './error-mapper.js';
import { buildGitEnv, validateGitArgs } from './command-builder.js';
import { spawnGitCommand, type GitCommandResult } from './runtime-adapter.js';
import {
  assertConfiguredGitExecutionPolicy,
  withConfiguredGitExecutionContext,
} from './configured-execution-policy.js';
import { getGitExecutionFailure } from './execution-context.js';

/** Internal provider options; repository roots are issued by server authorization. */
export interface ExecuteGitOptions {
  allowNonZeroExit?: boolean | undefined;
  signal?: AbortSignal | undefined;
  deadline?: number | undefined;
  readonly repositoryRoots?: readonly string[] | undefined;
}

/** Complete UTF-8 output only. Control failures cannot become soft Git exits. */
export async function executeGitCommand(
  args: string[],
  cwd: string,
  options: ExecuteGitOptions = {},
): Promise<GitCommandResult> {
  // Must precede cwd stat, repository discovery and every Git invocation.
  const policy = assertConfiguredGitExecutionPolicy();
  const failure = getGitExecutionFailure();
  if (failure) throw failure;
  return withConfiguredGitExecutionContext(
    options.signal,
    async () => {
      try {
        validateGitArgs(args);
        if (!existsSync(cwd)) {
          throw new McpError(
            JsonRpcErrorCode.InvalidRequest,
            'Working directory does not exist.',
          );
        }
        if (!statSync(cwd).isDirectory()) {
          throw new McpError(
            JsonRpcErrorCode.InvalidRequest,
            'Working directory is not a directory.',
          );
        }
        return await spawnGitCommand(
          args,
          cwd,
          buildGitEnv(process.env, policy),
          undefined,
          options.signal,
          options.allowNonZeroExit,
          { policy, deadline: options.deadline },
        );
      } catch (error) {
        throw mapGitError(error, args[0] || 'unknown');
      }
    },
    options.deadline,
  );
}
