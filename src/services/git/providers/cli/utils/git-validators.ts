/**
 * @fileoverview CLI provider git validators using git command execution
 * @module services/git/providers/cli/utils/git-validators
 *
 * This module contains validators that require git command execution.
 * These are used internally by the CLI provider for pre-flight checks.
 */

import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import { logger, type RequestContext } from '@/utils/index.js';

import { executeGitCommand, type ExecuteGitOptions } from './git-executor.js';

/**
 * Validate that a directory is a git repository.
 *
 * Uses `git rev-parse --is-inside-work-tree` to check if the path
 * is within a git working directory.
 *
 * @param path - Path to check
 * @param context - Request context for logging
 * @param options - Server-owned controls composed with the current request scope
 * @returns Promise resolving to true if valid git repository
 * @throws {McpError} If not a git repository or path is invalid
 *
 * @example
 * ```typescript
 * await validateGitRepository('/path/to/repo', appContext);
 * // Throws if not a git repo
 * ```
 */
export async function validateGitRepository(
  path: string,
  _context: RequestContext,
  options: ExecuteGitOptions = {},
): Promise<boolean> {
  try {
    const result = await executeGitCommand(
      ['rev-parse', '--is-inside-work-tree'],
      path,
      options,
    );

    if (result.stdout.trim() !== 'true') {
      throw new McpError(
        JsonRpcErrorCode.ValidationError,
        `Not a git repository: ${path}`,
      );
    }

    return true;
  } catch (error) {
    if (error instanceof McpError) {
      throw error;
    }
    throw new McpError(
      JsonRpcErrorCode.ValidationError,
      `Not a git repository: ${path}`,
    );
  }
}

/**
 * Get current branch name.
 *
 * Returns the name of the current branch, or null if in detached HEAD state.
 * Uses `git symbolic-ref` which fails gracefully for detached HEAD.
 *
 * @param path - Repository path
 * @param context - Request context for logging
 * @returns Promise resolving to branch name or null if detached HEAD
 *
 * @example
 * ```typescript
 * const branch = await getCurrentBranch('/path/to/repo', appContext);
 * // Returns: 'main' or null
 * ```
 */
export async function getCurrentBranch(
  path: string,
  context: RequestContext,
): Promise<string | null> {
  try {
    const result = await executeGitCommand(
      ['symbolic-ref', '--short', 'HEAD'],
      path,
    );

    const branch = result.stdout.trim();
    return branch || null;
  } catch (_error) {
    // If symbolic-ref fails, we're in detached HEAD state
    logger.debug('Not on a branch (detached HEAD)', { ...context, path });
    return null;
  }
}

/**
 * Check if repository has uncommitted changes.
 *
 * Returns true if the working directory is clean (no staged or unstaged changes).
 * Uses `git status --porcelain` which outputs nothing when clean.
 *
 * @param path - Repository path
 * @param context - Request context for logging
 * @returns Promise resolving to true if working directory is clean
 *
 * @example
 * ```typescript
 * const isClean = await isWorkingDirectoryClean('/path/to/repo', appContext);
 * if (!isClean) {
 *   console.log('Repository has uncommitted changes');
 * }
 * ```
 */
export async function isWorkingDirectoryClean(
  path: string,
  _context: RequestContext,
): Promise<boolean> {
  const result = await executeGitCommand(['status', '--porcelain'], path);
  return result.stdout.trim() === '';
}

/**
 * Check if repository has uncommitted changes and validate for destructive operations.
 *
 * Many git operations should not proceed if there are uncommitted changes,
 * as they could result in data loss. This validator ensures the working
 * directory is clean unless explicitly forced.
 *
 * @param path - Repository path
 * @param context - Request context for logging
 * @param operation - Operation being performed (for error messages)
 * @param force - Whether operation is forced (bypasses check if true)
 * @throws {McpError} If uncommitted changes exist and operation is not forced
 *
 * @example
 * ```typescript
 * await validateCleanWorkingDirectory(
 *   '/path/to/repo',
 *   appContext,
 *   'checkout branch',
 *   false // force
 * );
 * // Throws if working directory has changes
 * ```
 */
export async function validateCleanWorkingDirectory(
  path: string,
  context: RequestContext,
  operation: string,
  force = false,
): Promise<void> {
  const result = await executeGitCommand(['status', '--porcelain'], path);

  const hasChanges = result.stdout.trim().length > 0;

  if (hasChanges && !force) {
    throw new McpError(
      JsonRpcErrorCode.ValidationError,
      `Cannot perform '${operation}' with uncommitted changes. Commit or stash changes first, or use force=true.`,
      {
        operation,
        hint: 'Use git_status to see uncommitted changes, or set force=true to proceed anyway.',
      },
    );
  }

  if (hasChanges && force) {
    logger.warning(
      `Proceeding with '${operation}' despite uncommitted changes`,
      {
        ...context,
        operation,
      },
    );
  }
}

/**
 * Validate that target branch exists before attempting merge/rebase/checkout.
 *
 * Prevents errors from attempting operations on non-existent branches.
 * Uses `git rev-parse --verify` to check branch existence.
 *
 * @param branchName - Branch name to validate
 * @param path - Repository path
 * @param context - Request context for logging
 * @throws {McpError} If branch does not exist
 *
 * @example
 * ```typescript
 * await validateBranchExists('feature/my-branch', '/path/to/repo', appContext);
 * // Throws if branch doesn't exist
 * ```
 */
export async function validateBranchExists(
  branchName: string,
  path: string,
  _context: RequestContext,
): Promise<void> {
  try {
    await executeGitCommand(
      ['rev-parse', '--verify', `refs/heads/${branchName}`],
      path,
    );
  } catch {
    throw new McpError(
      JsonRpcErrorCode.ValidationError,
      `Branch '${branchName}' does not exist`,
      {
        branchName,
        hint: 'Use git_branch to list available branches.',
      },
    );
  }
}

/**
 * Validate that remote exists before attempting remote operations.
 *
 * @param remoteName - Remote name to validate (e.g., 'origin')
 * @param path - Repository path
 * @param context - Request context for logging
 * @throws {McpError} If remote does not exist
 *
 * @example
 * ```typescript
 * await validateRemoteExists('origin', '/path/to/repo', appContext);
 * ```
 */
export async function validateRemoteExists(
  remoteName: string,
  path: string,
  _context: RequestContext,
): Promise<void> {
  try {
    await executeGitCommand(['remote', 'get-url', remoteName], path);
  } catch {
    throw new McpError(
      JsonRpcErrorCode.ValidationError,
      `Remote '${remoteName}' does not exist`,
      {
        remoteName,
        hint: 'Use git_remote to list available remotes.',
      },
    );
  }
}

/**
 * Validate that current HEAD has commits (repository is not empty).
 *
 * Some git operations require at least one commit to exist.
 * This check prevents errors from operations on empty repositories.
 *
 * @param path - Repository path
 * @param context - Request context for logging
 * @throws {McpError} If repository has no commits
 *
 * @example
 * ```typescript
 * await validateHasCommits('/path/to/repo', appContext);
 * // Throws if repository is empty (no commits)
 * ```
 */
export async function validateHasCommits(
  path: string,
  _context: RequestContext,
): Promise<void> {
  try {
    await executeGitCommand(['rev-parse', 'HEAD'], path);
  } catch {
    throw new McpError(
      JsonRpcErrorCode.ValidationError,
      'Repository has no commits yet',
      {
        hint: 'Make at least one commit before attempting this operation.',
      },
    );
  }
}

/**
 * Validate merge state - ensure no merge is in progress.
 *
 * Prevents starting a new merge/rebase/cherry-pick while another
 * operation is already in progress.
 *
 * @param path - Repository path
 * @param context - Request context for logging
 * @throws {McpError} If merge/rebase is in progress
 *
 * @example
 * ```typescript
 * await validateNotInMergeState('/path/to/repo', appContext);
 * ```
 */
export async function validateNotInMergeState(
  path: string,
  _context: RequestContext,
): Promise<void> {
  try {
    const result = await executeGitCommand(
      ['rev-parse', '--verify', 'MERGE_HEAD'],
      path,
    );

    if (result.stdout.trim()) {
      throw new McpError(
        JsonRpcErrorCode.ValidationError,
        'A merge is already in progress',
        {
          hint: 'Complete or abort the current merge before starting a new operation.',
        },
      );
    }
  } catch (error) {
    // MERGE_HEAD not found means no merge in progress - this is OK
    if (
      error instanceof McpError &&
      error.code === JsonRpcErrorCode.ValidationError
    ) {
      throw error; // Re-throw our own errors
    }
    // Other errors (MERGE_HEAD doesn't exist) are expected and mean we're good to proceed
  }
}

/**
 * Validate that the current branch is not detached HEAD.
 *
 * Some operations require being on a branch, not in detached HEAD state.
 *
 * @param path - Repository path
 * @param context - Request context for logging
 * @throws {McpError} If in detached HEAD state
 *
 * @example
 * ```typescript
 * await validateNotDetachedHead('/path/to/repo', appContext);
 * ```
 */
export async function validateNotDetachedHead(
  path: string,
  context: RequestContext,
): Promise<void> {
  const currentBranch = await getCurrentBranch(path, context);

  if (!currentBranch) {
    throw new McpError(
      JsonRpcErrorCode.ValidationError,
      'Cannot perform this operation in detached HEAD state',
      {
        hint: 'Checkout a branch first using git_checkout.',
      },
    );
  }
}

/**
 * Get the root directory of a git repository.
 *
 * Returns the absolute path to the top-level directory of the repository,
 * regardless of where in the working tree the path parameter points to.
 *
 * @param path - Path within the repository (can be any subdirectory)
 * @param context - Request context for logging
 * @returns Promise resolving to absolute path of repository root
 * @throws {McpError} If not within a git repository
 *
 * @example
 * ```typescript
 * const root = await getGitRoot('/path/to/repo/subdir', appContext);
 * // Returns: '/path/to/repo'
 * ```
 */
export async function getGitRoot(
  path: string,
  _context: RequestContext,
): Promise<string> {
  const result = await executeGitCommand(
    ['rev-parse', '--show-toplevel'],
    path,
  );
  return result.stdout.trim();
}

/**
 * Validate commit reference (hash, branch, tag).
 *
 * Uses `git rev-parse --verify` to check if the reference is valid.
 * Accepts full/short commit hashes, branch names, and tag names.
 *
 * @param ref - Reference to validate (hash, branch, or tag)
 * @param path - Repository path
 * @param context - Request context for logging
 * @returns Promise resolving to true if valid reference
 * @throws {McpError} If reference is invalid or doesn't exist
 *
 * @example
 * ```typescript
 * await validateCommitRef('main', '/path/to/repo', appContext); // OK
 * await validateCommitRef('a1b2c3d', '/path/to/repo', appContext); // OK
 * await validateCommitRef('invalid-ref', '/path/to/repo', appContext); // Throws
 * ```
 */
export async function validateCommitRef(
  ref: string,
  path: string,
  _context: RequestContext,
): Promise<boolean> {
  const result = await executeGitCommand(['rev-parse', '--verify', ref], path);

  if (!result.stdout.trim()) {
    throw new McpError(
      JsonRpcErrorCode.ValidationError,
      `Invalid commit reference: ${ref}`,
    );
  }

  return true;
}

/**
 * Get the commit hash for a given reference.
 *
 * Resolves any valid git reference (branch, tag, short hash, HEAD~1, etc.)
 * to its full SHA-1 commit hash.
 *
 * @param ref - Reference to resolve (branch, tag, hash, etc.)
 * @param path - Repository path
 * @param context - Request context for logging
 * @returns Promise resolving to full commit hash
 * @throws {McpError} If reference cannot be resolved
 *
 * @example
 * ```typescript
 * const hash = await getCommitHash('HEAD', '/path/to/repo', appContext);
 * // Returns: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0'
 * ```
 */
export async function getCommitHash(
  ref: string,
  path: string,
  _context: RequestContext,
): Promise<string> {
  const result = await executeGitCommand(['rev-parse', ref], path);
  return result.stdout.trim();
}

/**
 * Check if a remote exists in the repository.
 *
 * @param remoteName - Name of the remote to check
 * @param path - Repository path
 * @param context - Request context for logging
 * @returns Promise resolving to true if remote exists
 *
 * @example
 * ```typescript
 * const hasOrigin = await hasRemote('origin', '/path/to/repo', appContext);
 * ```
 */
export async function hasRemote(
  remoteName: string,
  path: string,
  _context: RequestContext,
): Promise<boolean> {
  try {
    const result = await executeGitCommand(
      ['remote', 'get-url', remoteName],
      path,
    );
    return Boolean(result.stdout.trim());
  } catch {
    return false;
  }
}

/**
 * Get the remote URL for a given remote name.
 *
 * @param remoteName - Name of the remote (e.g., 'origin')
 * @param path - Repository path
 * @param context - Request context for logging
 * @returns Promise resolving to remote URL
 * @throws {McpError} If remote doesn't exist
 *
 * @example
 * ```typescript
 * const url = await getRemoteUrl('origin', '/path/to/repo', appContext);
 * // Returns: 'https://github.com/user/repo.git'
 * ```
 */
export async function getRemoteUrl(
  remoteName: string,
  path: string,
  _context: RequestContext,
): Promise<string> {
  const result = await executeGitCommand(
    ['remote', 'get-url', remoteName],
    path,
  );

  const url = result.stdout.trim();
  if (!url) {
    throw new McpError(
      JsonRpcErrorCode.ValidationError,
      `Remote '${remoteName}' does not exist`,
    );
  }

  return url;
}

/**
 * Validate branch name format according to git naming conventions.
 *
 * Git branch names must follow these rules:
 * - Cannot start with '.'
 * - Cannot contain '..' (consecutive dots)
 * - Cannot contain '//' (consecutive slashes)
 * - Cannot contain '@{' (ref syntax)
 * - Cannot contain control characters
 * - Cannot contain special characters: ~^:?*[\\
 * - Cannot end with '.lock'
 * - Cannot end with '/'
 * - Cannot be empty
 *
 * @param branchName - Branch name to validate
 * @throws {McpError} If branch name is invalid
 *
 * @example
 * ```typescript
 * validateBranchName('feature/my-feature'); // OK
 * validateBranchName('main'); // OK
 * validateBranchName('../etc/passwd'); // Throws error
 * ```
 */
export function validateBranchName(branchName: string): void {
  // Git branch naming rules
  const invalidPatterns = [
    /^\./, // Cannot start with .
    /\.\./, // Cannot contain ..
    /\/\//, // Cannot contain consecutive slashes
    /@\{/, // Cannot contain @{
    /[\x00-\x1F\x7F]/, // No control characters
    /[~^:?*\[\\]/, // No special characters
    /\.lock$/, // Cannot end with .lock
    /\/$/, // Cannot end with /
  ];

  if (branchName.length === 0) {
    throw new McpError(
      JsonRpcErrorCode.ValidationError,
      'Branch name cannot be empty',
    );
  }

  for (const pattern of invalidPatterns) {
    if (pattern.test(branchName)) {
      throw new McpError(
        JsonRpcErrorCode.ValidationError,
        `Invalid branch name: ${branchName}`,
        { pattern: pattern.source },
      );
    }
  }
}
