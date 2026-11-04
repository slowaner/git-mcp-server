/**
 * @fileoverview Canonical authorization before controlled native Git execution.
 * @module services/git/core/repository-command-gate
 */
import { lstatSync } from 'node:fs';
import path from 'node:path';
import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import {
  localRemotePath,
  containsPath,
  type RepositoryPathPolicy,
} from './repository-capability.js';
import { discoverRepository } from './repository-discovery.js';
import {
  parseEffectiveGitConfig,
  resolveEffectiveRepository,
  type EffectiveConfigReader,
} from './repository-effective-config.js';
import { authorizeRemoteUrl, rewriteRemoteUrl } from './repository-remotes.js';

function deny(): never {
  throw new McpError(
    JsonRpcErrorCode.Forbidden,
    'Repository boundary denied: unsupported command path.',
  );
}

/** Fixed private introspection closure shares the operation's actual env and budget. */
export type RepositoryIntrospection = (
  args: string[],
  cwd: string,
) => Promise<{ stdout: string; exitCode: number }>;

/**
 * Pin transfers to the superproject; native recursive children cannot re-enter
 * this capability gate. The fixed option comes last before literal operands.
 */
export function disableSubmoduleRecursion(args: readonly string[]): string[] {
  const command = args[0];
  if (!['fetch', 'pull', 'push', 'clone'].includes(command ?? ''))
    return [...args];
  const separator = args.findIndex(
    (arg) => arg === '--' || arg === '--end-of-options',
  );
  const end = separator < 0 ? args.length : separator;
  const fixed =
    command === 'push' ? '--recurse-submodules=no' : '--no-recurse-submodules';
  return [...args.slice(0, end), fixed, ...args.slice(end)];
}

/** Gate every public command, without exposing a discovery/raw bypass option. */
export async function authorizeGitCommand(
  policy: RepositoryPathPolicy,
  args: readonly string[],
  inputCwd: string,
  introspect: RepositoryIntrospection,
): Promise<string> {
  const cwd = policy.resolve(inputCwd).path;
  const command = args[0];
  if (command === '--version') return cwd;
  const noIndex = command === 'diff' && args.includes('--no-index');
  const bodyDiff =
    args.length === 4 && args[1] === '--no-index' && args[2] === '/dev/null';
  const statDiff =
    args.length === 5 &&
    args[1] === '--no-index' &&
    args[2] === '--stat' &&
    args[3] === '/dev/null';
  const combinedDiff =
    args.length === 8 &&
    args[1] === '--no-index' &&
    args[2] === '--numstat' &&
    args[3] === '-z' &&
    args[4] === '--patch' &&
    args[5] === '--' &&
    args[6] === '/dev/null';
  const filesystemDiff = noIndex && (bodyDiff || statDiff || combinedDiff);
  if (noIndex && (!filesystemDiff || args.at(-1)!.startsWith('-'))) deny();
  const readConfig: EffectiveConfigReader = (directory) =>
    introspect(['config', '--null', '--list', '--includes'], directory);
  const isCreation = command === 'init' || command === 'clone';
  const local = discoverRepository(policy, cwd, true);
  let config: ReadonlyMap<string, readonly string[]>;
  let topLevel: string | undefined;
  if (local) {
    const repo = await resolveEffectiveRepository(policy, cwd, readConfig);
    config = repo.config;
    topLevel = repo.worktree;
    // Only these fixed filesystem comparisons do not use Git's database
    // namespace. Their config, complete metadata and operand gates stay fresh.
    // Every repository operation keeps both native namespace comparisons.
    if (!filesystemDiff) {
      const metadata = await introspect(
        [
          'rev-parse',
          '--path-format=absolute',
          '--absolute-git-dir',
          '--git-common-dir',
        ],
        cwd,
      );
      const fields = metadata.stdout.replace(/\n$/, '').split('\n');
      if (
        metadata.exitCode !== 0 ||
        fields.length !== 2 ||
        policy.resolve(fields[0]!, cwd).path !== repo.gitDirectory ||
        policy.resolve(fields[1]!, cwd).path !== repo.commonDirectory
      )
        deny();
      if (repo.worktree && config.get('core.bare')?.at(-1) !== 'true') {
        const top = await introspect(['rev-parse', '--show-toplevel'], cwd);
        const value = top.stdout.replace(/\n$/, '');
        if (
          top.exitCode !== 0 ||
          value.includes('\n') ||
          policy.resolve(value, cwd).path !== repo.worktree
        )
          deny();
      }
    }
  } else {
    if (!isCreation)
      throw new McpError(
        JsonRpcErrorCode.ValidationError,
        'Repository metadata denied: not a git repository before root boundary.',
      );
    const result = await readConfig(cwd);
    if (result.exitCode !== 0) deny();
    config = parseEffectiveGitConfig(result.stdout);
    // Even init must not inherit a global path redirect outside its grant.
    for (const worktree of config.get('core.worktree') ?? []) {
      if (worktree.startsWith('~') || worktree.includes('%(')) deny();
      policy.resolve(worktree, cwd);
    }
  }

  const transfer =
    command === 'fetch' || command === 'push' || command === 'pull';
  const checkUrl = (
    url: string,
    push = false,
    explicit = false,
    inspectSource = transfer,
  ): void => {
    const rewritten = rewriteRemoteUrl(url, config, push, explicit);
    authorizeRemoteUrl(policy, rewritten, cwd);
    const localPath = localRemotePath(rewritten, cwd);
    if (localPath !== undefined && inspectSource)
      discoverRepository(policy, localPath);
  };
  // Configured fetch/push endpoints can be consulted by native defaults/helpers.
  // Validate every URL, not merely the first selected one.
  for (const [key, urls] of config) {
    if (!key.startsWith('remote.')) continue;
    if (key.endsWith('.url'))
      for (const url of urls) {
        checkUrl(url);
        checkUrl(url, true, config.has(key.slice(0, -4) + '.pushurl'));
      }
    if (key.endsWith('.pushurl'))
      for (const url of urls) checkUrl(url, true, true);
  }
  if (command === 'clone') {
    const separator = args.indexOf('--end-of-options');
    if (
      separator < 0 ||
      args.length !== separator + 3 ||
      args
        .slice(1, separator)
        .some((arg) => /^--recurse-submodules(?:=|$)/.test(arg))
    )
      deny();
    const destination = policy.resolve(args[separator + 2]!, cwd);
    if (destination.path !== path.resolve(args[separator + 2]!)) deny();
    checkUrl(args[separator + 1]!, false, false, true);
  }
  if (command === 'init') {
    const separator = args.indexOf('--');
    if (separator < 0 || args.length !== separator + 2) deny();
    discoverRepository(
      policy,
      policy.resolve(args[separator + 1]!, cwd).path,
      true,
    );
  }
  if (command === 'remote' && (args[1] === 'add' || args[1] === 'set-url')) {
    const url = args.at(-1);
    if (!url) deny();
    checkUrl(url);
    checkUrl(url, true, args.includes('--push'));
  }
  if (command === 'fetch' || command === 'push' || command === 'pull') {
    const endpoint = args.slice(1).find((arg) => !arg.startsWith('-'));
    if (endpoint && !config.has(`remote.${endpoint}.url`))
      checkUrl(endpoint, command === 'push');
  }
  if (command === 'worktree') {
    const separator = args.indexOf('--');
    if (['add', 'remove', 'move'].includes(args[1] ?? '')) {
      if (separator < 0) deny();
      const operands = args.slice(separator + 1);
      const count = args[1] === 'move' ? 2 : 1;
      for (const operand of operands.slice(0, count))
        policy.resolve(operand, cwd);
    }
  }
  const authorizeFile = (operand: string, afterSeparator = false): void => {
    // Strip one known outer wrapper only; the literal filename can start with
    // the same bytes. Arbitrary native magic does not confer path authority.
    const wrapped = afterSeparator && operand.startsWith(':(literal)');
    // Existing diff auto-exclusions only remove a plain basename; they never
    // add a path operand or authorize native glob/pathspec expansion.
    if (
      afterSeparator &&
      command === 'diff' &&
      /^:\(exclude\)[A-Za-z0-9][A-Za-z0-9._-]{0,239}$/.test(operand)
    )
      return;
    if (afterSeparator && operand.startsWith(':(') && !wrapped) deny();
    const target = policy.resolve(
      wrapped ? operand.slice(':(literal)'.length) : operand,
      cwd,
    ).path;
    if (!topLevel || !containsPath(topLevel, target)) deny();
    if (noIndex) {
      let regular: boolean;
      try {
        regular = lstatSync(target).isFile();
      } catch {
        deny();
      }
      if (!regular) deny();
    }
  };
  if (noIndex) {
    const files = args.slice(-2);
    if (files.length !== 2 || files[0] !== '/dev/null') deny();
    authorizeFile(files[1]!);
  } else if (
    [
      'add',
      'reset',
      'clean',
      'checkout',
      'diff',
      'blame',
      'log',
      'show',
    ].includes(command ?? '')
  ) {
    const separator = args.indexOf('--');
    if (separator >= 0)
      for (const operand of args.slice(separator + 1))
        authorizeFile(operand, true);
    if (command === 'add' && separator < 0)
      for (const operand of args.slice(1).filter((arg) => !arg.startsWith('-')))
        authorizeFile(operand);
  }
  // Revalidate after introspection; trusted mode still assumes no hostile rename.
  policy.resolve(cwd);
  if (local) discoverRepository(policy, cwd);
  return cwd;
}
