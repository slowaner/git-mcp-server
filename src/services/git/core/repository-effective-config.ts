/**
 * @fileoverview Bounded parsing and authorization of Git's effective config.
 * @module services/git/core/repository-effective-config
 */
import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import { RepositoryPathPolicy } from './repository-capability.js';
import {
  discoverRepository,
  type AuthorizedRepository,
} from './repository-discovery.js';
import { authorizeRepositoryRemotes } from './repository-remotes.js';

const CONFIG_BYTE_LIMIT = 1024 * 1024;
const CONFIG_ENTRY_LIMIT = 10000;

function denied(): never {
  throw new McpError(
    JsonRpcErrorCode.Forbidden,
    'Effective Git configuration is incomplete, unsupported, or exceeds repository authority.',
  );
}

/** Parse complete `git config --null --list --includes` output. */
export function parseEffectiveGitConfig(
  raw: string,
): ReadonlyMap<string, readonly string[]> {
  if (
    Buffer.byteLength(raw) > CONFIG_BYTE_LIMIT ||
    (raw !== '' && !raw.endsWith('\0'))
  )
    denied();
  const entries = raw === '' ? [] : raw.slice(0, -1).split('\0');
  if (entries.length > CONFIG_ENTRY_LIMIT) denied();
  const result = new Map<string, string[]>();
  for (const entry of entries) {
    const separator = entry.indexOf('\n');
    const key = separator < 0 ? entry : entry.slice(0, separator);
    // Git section and variable names are case-insensitive; subsection bytes
    // remain case-sensitive. Git forbids newline/NUL in subsection names.
    const firstDot = key.indexOf('.');
    const lastDot = key.lastIndexOf('.');
    if (
      firstDot <= 0 ||
      lastDot === key.length - 1 ||
      /[\r\n\x00-\x1f\x7f]/.test(key)
    )
      denied();
    const section = key.slice(0, firstDot).toLowerCase();
    const variable = key.slice(lastDot + 1).toLowerCase();
    if (
      !/^[a-z][a-z0-9-]*$/.test(section) ||
      !/^[a-z][a-z0-9-]*$/.test(variable)
    )
      denied();
    const normalized = section + key.slice(firstDot, lastDot + 1) + variable;
    const value = separator < 0 ? 'true' : entry.slice(separator + 1);
    if (
      (normalized === 'core.worktree' ||
        section === 'remote' ||
        section === 'url') &&
      /[\x00-\x1f\x7f]/.test(value)
    )
      denied();
    result.set(normalized, [...(result.get(normalized) ?? []), value]);
  }
  return result;
}

/**
 * A private runtime closure executing only fixed read-only config introspection
 * in the supplied cwd with the exact operation's controlled env/profile/signal.
 * It must never be exposed as a client-controlled discovery bypass.
 */
export type EffectiveConfigReader = (
  cwd: string,
) => Promise<{ stdout: string; exitCode: number }>;

/** Authorize effective path/URL values after local non-executing discovery. */
export async function resolveEffectiveRepository(
  policy: RepositoryPathPolicy,
  input: string,
  readConfig: EffectiveConfigReader,
): Promise<AuthorizedRepository> {
  const local = discoverRepository(policy, input);
  const result = await readConfig(local.path);
  if (result.exitCode !== 0) denied();
  const config = parseEffectiveGitConfig(result.stdout);
  let worktree = local.worktree;
  const effectiveWorktree = config.get('core.worktree')?.at(-1);
  if (effectiveWorktree !== undefined) {
    if (effectiveWorktree.startsWith('~') || effectiveWorktree.includes('%('))
      denied();
    worktree = policy.resolve(effectiveWorktree, local.gitDirectory).path;
  }
  const effective = Object.freeze({ ...local, config, worktree });
  authorizeRepositoryRemotes(policy, effective, 'fetch');
  authorizeRepositoryRemotes(policy, effective, 'push');
  return effective;
}
