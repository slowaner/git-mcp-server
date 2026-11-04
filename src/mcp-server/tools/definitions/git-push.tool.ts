/**
 * @fileoverview Git push tool - upload changes to remote repository
 * @module mcp-server/tools/definitions/git-push
 */
import { z } from 'zod';

import type { ToolDefinition } from '../utils/toolDefinition.js';
import { withToolAuth } from '@/mcp-server/transports/auth/lib/withAuth.js';
import {
  PathSchema,
  RemoteNameSchema,
  BranchNameSchema,
  ForceSchema,
  DryRunSchema,
} from '../schemas/common.js';
import {
  createToolHandler,
  type ToolLogicDependencies,
} from '../utils/toolHandlerFactory.js';
import {
  createJsonFormatter,
  type VerbosityLevel,
} from '../utils/json-response-formatter.js';
import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';

const TOOL_NAME = 'git_push';
const TOOL_TITLE = 'Git Push';
const TOOL_DESCRIPTION =
  'Push changes to a remote repository. Uploads local commits to the remote branch.';

const InputSchema = z
  .object({
    path: PathSchema,
    remote: RemoteNameSchema.optional().describe(
      'Remote name (default: origin).',
    ),
    branch: BranchNameSchema.optional().describe(
      'Branch name (default: current branch).',
    ),
    force: ForceSchema.describe('Force push (overwrites remote history).'),
    forceWithLease: z
      .boolean()
      .default(false)
      .describe(
        'Safer force push - only succeeds if remote branch is at expected state.',
      ),
    setUpstream: z
      .boolean()
      .default(false)
      .describe('Set upstream tracking relationship for the branch.'),
    tags: z.boolean().default(false).describe('Push all tags to the remote.'),
    dryRun: DryRunSchema,
    delete: z
      .boolean()
      .default(false)
      .describe('Delete the specified remote branch.'),
    remoteBranch: BranchNameSchema.optional().describe(
      'Remote branch name to push to (if different from local branch name).',
    ),
    confirmed: z
      .boolean()
      .default(false)
      .describe(
        'Caller assertion required for every force, lease or deletion push. Host approval remains separate.',
      ),
  })
  .strict();

const OutputSchema = z.object({
  success: z.boolean().describe('Indicates if the operation was successful.'),
  remote: z.string().describe('Selected remote name or destination.'),
  branch: z
    .string()
    .describe('Selected branch; empty when no local tags were selected.'),
  upstreamSet: z
    .boolean()
    .describe('Whether upstream tracking was set for the branch.'),
  pushedRefs: z
    .array(z.string())
    .describe('References that were successfully pushed.'),
  rejectedRefs: z
    .array(z.string())
    .describe('References that were rejected by the remote.'),
});

type ToolInput = z.infer<typeof InputSchema>;
type ToolOutput = z.infer<typeof OutputSchema>;

async function gitPushLogic(
  input: ToolInput,
  { provider, targetPath, appContext }: ToolLogicDependencies,
): Promise<ToolOutput> {
  if ((input.force || input.forceWithLease || input.delete) && !input.confirmed)
    throw new McpError(
      JsonRpcErrorCode.ValidationError,
      'Caller confirmation is required for every force, lease or deletion push.',
    );
  const pushOptions: {
    confirmed?: boolean;
    remote?: string;
    branch?: string;
    force?: boolean;
    forceWithLease?: boolean;
    setUpstream?: boolean;
    tags?: boolean;
    dryRun?: boolean;
    delete?: boolean;
    remoteBranch?: string;
  } = { confirmed: input.confirmed };

  if (input.remote !== undefined) {
    pushOptions.remote = input.remote;
  }
  if (input.branch !== undefined) {
    pushOptions.branch = input.branch;
  }
  if (input.force !== undefined) {
    pushOptions.force = input.force;
  }
  if (input.forceWithLease !== undefined) {
    pushOptions.forceWithLease = input.forceWithLease;
  }
  if (input.setUpstream !== undefined) {
    pushOptions.setUpstream = input.setUpstream;
  }
  if (input.tags !== undefined) {
    pushOptions.tags = input.tags;
  }
  if (input.dryRun !== undefined) {
    pushOptions.dryRun = input.dryRun;
  }
  if (input.delete !== undefined) {
    pushOptions.delete = input.delete;
  }
  if (input.remoteBranch !== undefined) {
    pushOptions.remoteBranch = input.remoteBranch;
  }

  const result = await provider.push(pushOptions, {
    workingDirectory: targetPath,
    requestContext: appContext,
    tenantId: appContext.tenantId || 'default-tenant',
  });

  return {
    success: result.success,
    remote: result.remote,
    branch: result.branch,
    upstreamSet: result.upstreamSet,
    pushedRefs: result.pushedRefs,
    rejectedRefs: result.rejectedRefs,
  };
}

/**
 * Filter git_push output based on verbosity level.
 *
 * Verbosity levels:
 * - minimal: Success, remote, and branch only
 * - standard: Above + complete lists of pushed and rejected refs (RECOMMENDED)
 * - full: Complete output
 */
function filterGitPushOutput(
  result: ToolOutput,
  level: VerbosityLevel,
): Partial<ToolOutput> {
  // minimal: Essential info only
  if (level === 'minimal') {
    return {
      success: result.success,
      remote: result.remote,
      branch: result.branch,
    };
  }

  // standard & full: Complete output
  // (LLMs need complete context - include all pushed/rejected refs)
  return result;
}

// Create JSON response formatter with verbosity filtering
const responseFormatter = createJsonFormatter<ToolOutput>({
  filter: filterGitPushOutput,
});

export const gitPushTool: ToolDefinition<
  typeof InputSchema,
  typeof OutputSchema
> = {
  name: TOOL_NAME,
  title: TOOL_TITLE,
  description: TOOL_DESCRIPTION,
  inputSchema: InputSchema,
  outputSchema: OutputSchema,
  annotations: { readOnlyHint: false },
  logic: withToolAuth(['tool:git:write'], createToolHandler(gitPushLogic)),
  responseFormatter,
};
