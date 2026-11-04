/**
 * @fileoverview Identity-bound Git history with opaque per-object diff output.
 * @module services/git/providers/cli/operations/commits/log
 */
import type { RequestContext } from '@/utils/index.js';
import type {
  GitLogOptions,
  GitLogResult,
  GitOperationContext,
} from '../../../../types.js';
import { mapGitError } from '../../utils/index.js';
import { parseObjectIds } from '../../utils/git-object-reader.js';
import { readCommitRecord } from '../../utils/structured-object-reader.js';
import { objectReadBudget } from '../../utils/object-read-budget.js';
import { literalFileArguments } from '../../utils/git-file-operands.js';

/** Enumerate only complete OIDs, then authenticate each immutable object. */
export async function executeLog(
  options: GitLogOptions,
  context: GitOperationContext,
  execGit: (
    args: string[],
    cwd: string,
    ctx: RequestContext,
  ) => Promise<{ stdout: string; stderr: string }>,
): Promise<GitLogResult> {
  const read = objectReadBudget(
    (args) => execGit(args, context.workingDirectory, context.requestContext),
    { maxBytes: 16 * 1024 * 1024, maxCalls: 4096 },
  );
  try {
    const limit = options.maxCount ?? 100;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
      throw new Error('History requires between 1 and 1000 records');
    const args = ['log', '--format=%H', `-n${limit}`];
    if (options.skip !== undefined) args.push(`--skip=${options.skip}`);
    if (options.since) args.push(`--since=${options.since}`);
    if (options.until) args.push(`--until=${options.until}`);
    if (options.author) args.push(`--author=${options.author}`);
    if (options.grep) args.push(`--grep=${options.grep}`);
    if (options.branch) {
      if (options.branch.startsWith('-') || options.branch.includes('\0'))
        throw new Error('Invalid history revision');
      args.push('--end-of-options', options.branch);
    }
    const pathTail = options.path ? literalFileArguments([options.path]) : [];
    args.push(...pathTail);
    const ids = parseObjectIds((await read(args)).stdout);
    if (ids.length > limit) throw new Error('Unexpected history record count');
    const commits: GitLogResult['commits'] = [];
    for (const id of ids) {
      const commit = await readCommitRecord(id, read, options.oneline);
      // Each response belongs to exactly one validated OID. Patch/stat content
      // is opaque; filenames and body markers cannot introduce more records.
      if (options.stat) {
        const stat = (
          await read(['show', '--format=', '--stat', id, ...pathTail])
        ).stdout;
        if (stat) commit.stat = stat;
      }
      if (options.patch) {
        const patch = (await read(['show', '--format=', '-p', id, ...pathTail]))
          .stdout;
        if (patch) commit.patch = patch;
      }
      commits.push(commit);
    }
    return { commits, totalCount: commits.length };
  } catch (error) {
    throw mapGitError(error, 'log');
  }
}
