/**
 * @fileoverview Single-attempt commit creation and identity-bound inspection.
 * @module services/git/providers/cli/operations/commits/commit
 */
import type { RequestContext } from '@/utils/index.js';
import type {
  GitCommitOptions,
  GitCommitResult,
  GitOperationContext,
} from '../../../../types.js';
import { mapGitError, shouldSignCommits } from '../../utils/index.js';
import {
  literalFileArguments,
  nativeFileNames,
} from '../../utils/git-file-operands.js';
import {
  validateObjectId,
  parseGitObject,
  objectHeader,
  parseGitIdentity,
} from '../../utils/git-object-reader.js';
import {
  createWithSigningPolicy,
  signingPolicy,
} from '../../utils/signing-policy.js';

/** Create once; a failed signing request or hook never triggers another commit. */
export async function executeCommit(
  options: GitCommitOptions,
  context: GitOperationContext,
  execGit: (
    args: string[],
    cwd: string,
    ctx: RequestContext,
  ) => Promise<{ stdout: string; stderr: string }>,
): Promise<GitCommitResult> {
  const read = (args: string[]) =>
    execGit(args, context.workingDirectory, context.requestContext);
  try {
    if (options.filesToStage?.length)
      await read(['add', ...literalFileArguments(options.filesToStage)]);
    return await createWithSigningPolicy(
      signingPolicy(shouldSignCommits()),
      async (sign) => {
        const args = ['commit', `--message=${options.message}`];
        if (options.amend) args.push('--amend');
        if (options.allowEmpty) args.push('--allow-empty');
        if (options.noVerify) args.push('--no-verify');
        if (sign) args.push('--gpg-sign');
        if (options.author)
          args.push(
            `--author=${options.author.name} <${options.author.email}>`,
          );
        await read(args);
      },
      async () => {
        const id = validateObjectId(
          (await read(['rev-parse', '--verify', 'HEAD'])).stdout.replace(
            /\n$/,
            '',
          ),
        );
        const object = parseGitObject(
          id,
          'commit',
          (await read(['cat-file', 'commit', id])).stdout,
        );
        const author = parseGitIdentity(objectHeader(object, 'author'));
        const names = await read([
          'show',
          '--format=',
          '--name-only',
          '-z',
          id,
        ]);
        // Native output passed the inherited fatal UTF-8 EOF boundary; re-encoding
        // is byte-exact. Arbitrary legacy strings are not a supported executor.
        const filesChanged = nativeFileNames(names.stdout);
        return {
          success: true,
          commitHash: id,
          message: options.message,
          author: author.name,
          timestamp: author.timestamp,
          filesChanged,
          signed:
            object.headers.has('gpgsig') || object.headers.has('gpgsig-sha256'),
        };
      },
    );
  } catch (error) {
    throw mapGitError(error, 'commit');
  }
}
