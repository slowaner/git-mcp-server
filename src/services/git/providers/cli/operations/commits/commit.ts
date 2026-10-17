/**
 * @fileoverview CLI provider git commit operation
 * @module services/git/providers/cli/operations/commits/commit
 */

import { logger, type RequestContext } from '@/utils/index.js';

import type {
  GitCommitOptions,
  GitCommitResult,
  GitOperationContext,
} from '../../../../types.js';
import {
  buildGitCommand,
  GIT_FIELD_DELIMITER,
  GIT_RECORD_DELIMITER,
  mapGitError,
  shouldSignCommits,
} from '../../utils/index.js';

/**
 * Execute git commit to create a new commit.
 */
export async function executeCommit(
  options: GitCommitOptions,
  context: GitOperationContext,
  execGit: (
    args: string[],
    cwd: string,
    ctx: RequestContext,
  ) => Promise<{ stdout: string; stderr: string }>,
): Promise<GitCommitResult> {
  try {
    // Stage specified files before committing (atomic stage+commit)
    if (options.filesToStage?.length) {
      const addCmd = buildGitCommand({
        command: 'add',
        args: ['--', ...options.filesToStage],
      });
      await execGit(addCmd, context.workingDirectory, context.requestContext);
    }

    const args: string[] = [`--message=${options.message}`];

    if (options.amend) {
      args.push('--amend');
    }

    if (options.allowEmpty) {
      args.push('--allow-empty');
    }

    if (options.noVerify) {
      args.push('--no-verify');
    }

    // Explicitly request signing when enabled; otherwise let native Git
    // configuration decide. A retry removes only our explicit request.
    const signRequested = shouldSignCommits();
    let signingWarning: string | undefined;

    if (signRequested) {
      args.push('--gpg-sign');
    }

    if (options.author) {
      const authorStr = `${options.author.name} <${options.author.email}>`;
      args.push(`--author=${authorStr}`);
    }

    const cmd = buildGitCommand({ command: 'commit', args });

    try {
      await execGit(cmd, context.workingDirectory, context.requestContext);
    } catch (error) {
      if (!signRequested) {
        throw error;
      }
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      logger.warning(
        'Explicit commit signing failed; retrying with native Git configuration. Set GIT_SIGN_COMMITS=false to defer to Git from the first attempt.',
        { ...context.requestContext, error },
      );
      signingWarning = `Explicit commit signing failed; retried with native Git configuration. Check signing key availability (gpg-agent running, SSH key accessible). Underlying error: ${errorMessage}`;
      const nativeArgs = args.filter((a) => a !== '--gpg-sign');
      const nativeCmd = buildGitCommand({
        command: 'commit',
        args: nativeArgs,
      });
      await execGit(
        nativeCmd,
        context.workingDirectory,
        context.requestContext,
      );
    }

    // Get commit hash reliably
    const hashCmd = buildGitCommand({
      command: 'rev-parse',
      args: ['HEAD'],
    });
    const hashResult = await execGit(
      hashCmd,
      context.workingDirectory,
      context.requestContext,
    );
    const commitHash = hashResult.stdout.trim();

    // Get commit details using the reliable hash
    const showCmd = buildGitCommand({
      command: 'show',
      args: [
        `--format=%an${GIT_FIELD_DELIMITER}%at${GIT_RECORD_DELIMITER}`,
        '--name-only',
        commitHash,
      ],
    });
    const showResult = await execGit(
      showCmd,
      context.workingDirectory,
      context.requestContext,
    );

    const parts = showResult.stdout.split(GIT_RECORD_DELIMITER);
    const metaParts = parts[0]?.split(GIT_FIELD_DELIMITER) || [];
    const authorName = metaParts[0] || '';
    const timestamp = parseInt(metaParts[1] || '0', 10);

    // Parse changed files from the second part of the output
    // git show --name-only outputs filenames after the metadata section
    const filesChanged = parts[1]?.split('\n').filter((f) => f.trim()) || [];

    // Read signature presence, not validity: verification can require trust
    // configuration or a key that is unavailable on this machine.
    const objectResult = await execGit(
      buildGitCommand({ command: 'cat-file', args: ['commit', commitHash] }),
      context.workingDirectory,
      context.requestContext,
    );
    const headers = objectResult.stdout.split('\n\n', 1)[0] || '';
    const signed = /^gpgsig(?:-sha256)? /m.test(headers);

    const result: GitCommitResult = {
      success: true,
      commitHash,
      message: options.message,
      author: authorName,
      timestamp,
      filesChanged,
      signed,
    };

    if (signingWarning) {
      result.signingWarning = signingWarning;
    }

    return result;
  } catch (error) {
    throw mapGitError(error, 'commit');
  }
}
