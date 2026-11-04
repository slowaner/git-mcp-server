/**
 * @fileoverview Git CLI command builder utility
 * @module services/git/providers/cli/utils/command-builder
 */

import { loadConfig } from './config-helper.js';
import { getConfiguredGitExecutionPolicy } from './configured-execution-policy.js';
import {
  buildTrustedGitEnvironment,
  type GitExecutionPolicy,
} from './execution-policy.js';

/**
 * Git command configuration.
 */
export interface GitCommandConfig {
  /** Base git command (e.g., 'status', 'commit', 'log') */
  command: string;
  /** Command arguments */
  args?: string[];
  /** Working directory for command execution */
  cwd?: string;
  /** Environment variables */
  env?: Record<string, string>;
  /** Timeout in milliseconds */
  timeout?: number;
}

/**
 * Build a git command with arguments.
 *
 * @param config - Command configuration
 * @returns Array of command parts for execution
 *
 * @example
 * ```typescript
 * buildGitCommand({
 *   command: 'log',
 *   args: ['--pretty=format:%H', '--max-count=10'],
 * })
 * // Returns: ['log', '--pretty=format:%H', '--max-count=10']
 * ```
 */
export function buildGitCommand(config: GitCommandConfig): string[] {
  const parts: string[] = [config.command];

  // Add positional arguments
  if (config.args && config.args.length > 0) {
    parts.push(...config.args);
  }

  return parts;
}

/**
 * Build the allowlisted environment under explicit operator authority.
 * Inherited GIT routing/config variables and unrelated server secrets are dropped.
 */
export function buildGitEnv(
  inherited: Record<string, string | undefined> = process.env,
  policy: GitExecutionPolicy = getConfiguredGitExecutionPolicy(),
): Record<string, string> {
  const env = buildTrustedGitEnvironment(policy, inherited);
  const config = loadConfig();
  if (config?.git.authorName) env.GIT_AUTHOR_NAME = config.git.authorName;
  if (config?.git.authorEmail) env.GIT_AUTHOR_EMAIL = config.git.authorEmail;
  if (config?.git.committerName)
    env.GIT_COMMITTER_NAME = config.git.committerName;
  if (config?.git.committerEmail)
    env.GIT_COMMITTER_EMAIL = config.git.committerEmail;
  return env;
}

/**
 * Allow-list of git option flags this server is permitted to pass.
 *
 * Any `-`-prefixed argument reaching `validateGitArgs` must be on this list
 * (matched on the flag name, before any `=value`). This is the primary
 * defense against argument injection via attacker-controlled refs, URLs,
 * or paths (CVE-2017-1000117 / CVE-2018-17456 class).
 *
 * To add a flag: only add it if it is genuinely needed by an operation.
 * Dangerous flags like `--upload-pack`, `--exec`, `--config`,
 * `--receive-pack`, `--server-option` must NEVER be added — they enable
 * arbitrary command execution by the git binary.
 */
const SAFE_GIT_OPTIONS = new Set([
  // Separators: `--end-of-options` stops option parsing; `--` is the pathspec
  // separator every path-taking operation emits before user-supplied paths.
  '--end-of-options',
  '--',
  // Common flags
  '--version',
  '--help',
  // Pre-flight validators (`git rev-parse`)
  '--is-inside-work-tree',
  '--show-toplevel',
  '--absolute-git-dir',
  '--git-common-dir',
  '--path-format',
  '--verify',
  // Read effective native signing configuration.
  '--get',
  '--null',
  '--includes',
  '--show-origin',
  '--raw',
  '-z',
  '-s',
  '-p',
  '-n',
  '-x',
  '--type',
  // Message-taking commands (commit, merge, stash push, tag) emit the message
  // attached (`--message=<text>`) so a message that starts with `-` is never a
  // standalone argv entry the validator would have to reject.
  '--message',
  '--all',
  '--force',
  '--force-with-lease',
  '--quiet',
  '--verbose',
  '-v',
  '-f',
  '-q',
  '-S',
  // Status flags
  '--porcelain',
  '-b',
  '--untracked-files',
  '--ignore-submodules',
  '--short',
  // Branch flags
  '--list',
  '--remote',
  '--no-abbrev',
  '--track',
  '--count',
  '--merged',
  '--no-merged',
  '-m',
  '-d',
  '-D',
  // Log flags
  '--pretty',
  '--oneline',
  '--graph',
  '--decorate',
  '--max-count',
  '--skip',
  '--author',
  '--since',
  '--until',
  '--grep',
  '--abbrev-ref',
  // Add flags
  '--update',
  '-u',
  '-A',
  // Commit flags
  '--amend',
  '--no-verify',
  '--allow-empty',
  // Diff flags
  '--stat',
  '--cached',
  '--staged',
  '--unified',
  '--name-only',
  '--name-status',
  '--no-index',
  '--others',
  '--exclude-standard',
  // Reset flags
  '--soft',
  '--mixed',
  '--hard',
  '--merge',
  '--keep',
  // Cherry-pick/merge flags
  '--mainline',
  '--strategy',
  '--signoff',
  '--gpg-sign',
  '--no-commit',
  '--abort',
  '--continue',
  '--no-ff',
  '--ff-only',
  '--squash',
  '--interactive',
  '--preserve-merges',
  '--onto',
  // Clone flags
  '--branch',
  '--depth',
  '--bare',
  '--mirror',
  '--recurse-submodules',
  '--no-recurse-submodules',
  // Fetch/push/pull flags
  '--prune',
  '--tags',
  '--set-upstream',
  '--delete',
  '--rebase',
  '--push',
  // Tag flags
  '--annotate',
  '--sort',
  '-a',
  '-t',
  // Stash flags
  '--include-untracked',
  '--keep-index',
  // Worktree flags
  '--dry-run',
  '--detach',
  // Show/log/blame flags
  '-L',
  '-w',
  // Format flags (accept any --pretty=..., --format=... value)
  '--format',
  '--initial-branch',
]);

/**
 * Validate git command arguments for safety.
 *
 * SECURITY MODEL:
 * Process spawning uses array arguments (`Bun.spawn` / `child_process.spawn`),
 * which makes shell-metacharacter injection (`;`, `|`, `$`, backticks, etc.)
 * impossible — those characters reach git as literal data, not shell syntax.
 *
 * The remaining attack class is **argument injection** — values that look like
 * git options (start with `-`) being parsed by git's own argument parser.
 * Examples: a clone URL like `--config=core.sshCommand=<cmd>` (the classic
 * CVE-2017-1000117 vector), or a branch ref like `--upload-pack=<cmd>`.
 *
 * Defense:
 * 1. Null bytes are rejected (corrupt many internal C string boundaries).
 * 2. Every `-`-prefixed argument must be an allowlisted short flag, one of the
 *    attached-value short forms the operations emit (`-n<count>`,
 *    `-L<start>,<end>`), or a long flag whose **name** (the part before any
 *    `=value`) is in `SAFE_GIT_OPTIONS`. Unknown flags throw — there is no
 *    "permissive" path.
 * 3. Operations that pass user-controlled values positionally MUST also
 *    insert `--end-of-options` before the positional segment, so even a
 *    schema bypass can't escalate to argument injection.
 *
 * @param args - Arguments to validate (after the git subcommand)
 * @throws Error if any argument is unsafe
 */
/** Short flags the operations emit with the value attached: `-n<count>`, `-L<start>,<end>`. */
const SHORT_FLAG_WITH_VALUE = /^-(?:n\d+|L\d+,\d*)$/;

export function validateGitArgs(args: string[]): void {
  // The qualified combined untracked producer is a complete private tuple,
  // never generic permission for numstat/patch flags or arbitrary no-index argv.
  const combinedUntracked =
    args.length === 8 &&
    args[0] === 'diff' &&
    args[1] === '--no-index' &&
    args[2] === '--numstat' &&
    args[3] === '-z' &&
    args[4] === '--patch' &&
    args[5] === '--' &&
    args[6] === '/dev/null' &&
    !!args[7] &&
    !args[7].startsWith('-');
  for (const arg of args) {
    if (arg.includes('\0')) {
      throw new Error(`Null byte detected in git argument: ${arg}`);
    }

    if (!arg.startsWith('-')) {
      continue;
    }

    const flagName = arg.split('=')[0] || arg;
    const isShortFlag = SHORT_FLAG_WITH_VALUE.test(arg);
    const isSafeOption =
      SAFE_GIT_OPTIONS.has(flagName) ||
      (combinedUntracked && (arg === '--numstat' || arg === '--patch'));

    if (!isShortFlag && !isSafeOption) {
      throw new Error(
        `Unsafe git flag rejected: ${arg}. ` +
          `Flag name "${flagName}" is not in the allow-list. ` +
          `This protects against argument injection (CVE-2017-1000117 class).`,
      );
    }
  }
}
