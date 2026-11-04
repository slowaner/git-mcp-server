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
import {
  getGitExecutionFailure,
  recordGitExecutionFailure,
} from './execution-context.js';
import { GitExecutionError } from './execution-errors.js';
import path from 'node:path';
import { getConfiguredRepositoryPolicy } from '../../../core/configured-repository-policy.js';
import { containsPath } from '../../../core/repository-capability.js';
import {
  authorizeGitCommand,
  disableSubmoduleRecursion,
} from '../../../core/repository-command-gate.js';

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
        args = disableSubmoduleRecursion(args);
        validateGitArgs(args);
        const roots = getConfiguredRepositoryPolicy(options.repositoryRoots);
        cwd = roots.resolve(cwd).path;
        const env = buildGitEnv(process.env, policy);
        if (roots.roots)
          env.GIT_CEILING_DIRECTORIES = [
            ...new Set(
              roots.roots
                .filter(
                  (root) =>
                    !roots.roots!.some(
                      (other) => other !== root && containsPath(other, root),
                    ),
                )
                .map((root) => path.dirname(root)),
            ),
          ].join(path.delimiter);
        // Private closure: all discovery uses the same controlled environment,
        // execution lifetime, raw aggregate budget and strict UTF-8 decoder.
        const introspect = (command: string[], directory: string) =>
          spawnGitCommand(
            command,
            directory,
            env,
            undefined,
            options.signal,
            true,
            { policy, deadline: options.deadline },
          );
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
        cwd = await authorizeGitCommand(roots, args, cwd, introspect);
        return await spawnGitCommand(
          args,
          cwd,
          env,
          undefined,
          options.signal,
          options.allowNonZeroExit,
          { policy, deadline: options.deadline },
        );
      } catch (error) {
        if (
          error instanceof McpError &&
          error.code === JsonRpcErrorCode.Forbidden
        ) {
          throw recordGitExecutionFailure(
            new GitExecutionError('REPOSITORY_BOUNDARY', error.message),
          );
        }
        throw mapGitError(error, args[0] || 'unknown');
      }
    },
    options.deadline,
  );
}
