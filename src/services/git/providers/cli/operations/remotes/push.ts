/**
 * @fileoverview CLI provider git push operation
 * @module services/git/providers/cli/operations/remotes/push
 */

import type { RequestContext } from '@/utils/index.js';

import type {
  GitOperationContext,
  GitPushOptions,
  GitPushResult,
} from '../../../../types.js';
import { buildGitCommand, mapGitError } from '../../utils/index.js';
import { parseEffectiveGitConfig } from '../../../../core/repository-effective-config.js';
import { assertPushPolicy } from '../../utils/push-policy.js';
import { resolvePrivatePushPlan } from '../../utils/push-plan.js';

/**
 * Execute git push to upload local changes.
 */
export async function executePush(
  options: GitPushOptions,
  context: GitOperationContext,
  execGit: (
    args: string[],
    cwd: string,
    ctx: RequestContext,
  ) => Promise<{ stdout: string; stderr: string }>,
  authorizeEmptyTags?: (remote: string) => Promise<void>,
): Promise<GitPushResult> {
  try {
    // Require the assertion before introspection; a configured force/delete
    // refspec is checked again after effective destination resolution.
    assertPushPolicy(options);
    const read = (args: string[]) =>
      execGit(args, context.workingDirectory, context.requestContext);
    const config = parseEffectiveGitConfig(
      (await read(['config', '--null', '--list', '--includes'])).stdout,
    );
    const last = (key: string) => config.get(key)?.at(-1);
    const current = (
      await read(['rev-parse', '--abbrev-ref', 'HEAD'])
    ).stdout.replace(/\n$/, '');
    const branch = current === 'HEAD' ? undefined : current;
    const remote =
      options.remote ??
      (branch && last(`branch.${branch}.pushremote`)) ??
      last('remote.pushdefault') ??
      (branch && last(`branch.${branch}.remote`)) ??
      'origin';
    if (!remote || remote.startsWith('-') || /[\x00-\x20\x7f]/.test(remote))
      throw new Error('Invalid effective push remote');
    const bool = (key: string) => {
      const value = last(key)?.toLowerCase();
      if (value === undefined || ['false', 'no', 'off', '0'].includes(value))
        return false;
      if (['true', 'yes', 'on', '1', ''].includes(value)) return true;
      throw new Error('Invalid effective push configuration');
    };
    if (bool('push.followtags'))
      throw new Error(
        'Implicit followed tags are unsupported; select explicit tag destinations',
      );
    let tagRefs: string[] | undefined;
    if (options.tags) {
      const tags = (
        await read([
          'for-each-ref',
          '--format=%(refname)',
          '--count=257',
          'refs/tags',
        ])
      ).stdout;
      tagRefs = tags === '' ? [] : tags.replace(/\n$/, '').split('\n');
    }
    const upstreamRemote = branch && last(`branch.${branch}.remote`);
    const upstream = branch && config.get(`branch.${branch}.merge`);
    if (upstream && upstream.length !== 1)
      throw new Error('Ambiguous push upstream');
    const plan = resolvePrivatePushPlan(options, {
      ...(branch ? { currentBranch: branch } : {}),
      ...(config.has(`remote.${remote}.push`)
        ? { configuredRefspecs: config.get(`remote.${remote}.push`)! }
        : {}),
      ...(last('push.default') ? { pushDefault: last('push.default')! } : {}),
      ...(upstreamRemote === remote && upstream?.[0]
        ? { upstreamDestination: upstream[0] }
        : {}),
      ...(upstreamRemote
        ? { pushRemoteMatchesTracking: upstreamRemote === remote }
        : {}),
      mirror: bool(`remote.${remote}.mirror`),
      ...(tagRefs ? { tagRefs } : {}),
    });
    if (plan.kind === 'empty-explicit-tags') {
      if (!authorizeEmptyTags)
        throw new Error(
          'Empty tag selection requires destination authorization',
        );
      await authorizeEmptyTags(remote);
      return {
        success: true,
        remote,
        branch: '',
        upstreamSet: false,
        pushedRefs: [],
        rejectedRefs: [],
      };
    }
    const args: string[] = [];
    if (options.forceWithLease) args.push('--force-with-lease');
    if (options.setUpstream) args.push('--set-upstream');
    if (options.dryRun) args.push('--dry-run');
    // Explicit normalized refspecs prevent defaults changing the checked target.
    args.push(
      '--',
      remote,
      ...plan.entries.map(
        (entry) =>
          `${entry.force ? '+' : ''}${entry.source}:${entry.destination}`,
      ),
    );

    const cmd = buildGitCommand({ command: 'push', args });
    const gitOutput = await execGit(
      cmd,
      context.workingDirectory,
      context.requestContext,
    );

    // Parse pushed and rejected refs
    const pushedRefs: string[] = [];
    const rejectedRefs: string[] = [];

    const lines = gitOutput.stderr.split('\n'); // git push outputs to stderr
    for (const line of lines) {
      if (line.includes('->')) {
        // Match both new branch and normal push lines:
        //   * [new branch]      main -> main
        //   abc1234..def5678    main -> main
        const refMatch = line.match(/\s+(\S+)\s+->\s+(\S+)/);
        if (refMatch) {
          pushedRefs.push(refMatch[2]!);
        }
      }
      if (line.includes('rejected')) {
        const match = line.match(/!\s+\[rejected\]\s+(\S+)/);
        if (match) {
          rejectedRefs.push(match[1]!);
        }
      }
    }

    const result = {
      success: rejectedRefs.length === 0,
      remote,
      branch: options.branch || 'HEAD',
      upstreamSet: options.setUpstream || false,
      pushedRefs,
      rejectedRefs,
    };

    return result;
  } catch (error) {
    throw mapGitError(error, 'push');
  }
}
