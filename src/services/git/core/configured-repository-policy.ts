/**
 * @fileoverview Operator repository ceiling and server-issued request restrictions.
 * @module services/git/core/configured-repository-policy
 */
import { AsyncLocalStorage } from 'node:async_hooks';
import { config } from '@/config/index.js';
import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import { assertConfiguredGitExecutionPolicy } from '../providers/cli/utils/configured-execution-policy.js';
import { RepositoryPathPolicy } from './repository-capability.js';

const requestRoots = new AsyncLocalStorage<{
  roots: readonly string[] | undefined;
}>();
let ceiling: { key: string; policy: RepositoryPathPolicy } | undefined;

/** Validate internal context, never a tool input or unverified token claim. */
export function repositoryRootsFromContext(context: {
  repositoryRoots?: unknown;
}): readonly string[] | undefined {
  const roots = context.repositoryRoots;
  if (roots === undefined) return undefined;
  if (!Array.isArray(roots) || roots.some((root) => typeof root !== 'string')) {
    throw new McpError(
      JsonRpcErrorCode.Forbidden,
      'Repository boundary denied: invalid server roots.',
    );
  }
  return Object.freeze([...(roots as string[])]);
}

/** Scope every secondary path to the same restriction; undefined never clears a parent. */
export function withRepositoryRoots<T>(
  roots: readonly string[] | undefined,
  operation: () => T,
): T {
  const inherited = requestRoots.getStore()?.roots;
  if (roots === undefined) return operation();
  // Nested explicit restrictions are checked against the current request ceiling.
  const narrowed =
    getConfiguredRepositoryPolicy(inherited).restrict(roots).roots;
  return requestRoots.run({ roots: narrowed }, operation);
}

/** Canonical intersection with the configured ceiling; [] is always deny. */
export function getConfiguredRepositoryPolicy(
  roots?: readonly string[],
): RepositoryPathPolicy {
  // No root lstat/realpath before the actual execution profile permits FS work.
  assertConfiguredGitExecutionPolicy();
  const configured = config.git.baseDirs;
  const key = JSON.stringify([configured, process.cwd()]);
  if (!ceiling || ceiling.key !== key)
    ceiling = { key, policy: new RepositoryPathPolicy(configured) };
  const parent = ceiling.policy.restrict(requestRoots.getStore()?.roots);
  return parent.restrict(roots);
}
