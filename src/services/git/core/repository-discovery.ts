/**
 * @fileoverview Non-executing repository metadata discovery within capabilities.
 * Run inside the execution profile's filesystem boundary for hostile trees.
 * @module services/git/core/repository-discovery
 */
import { lstatSync, readdirSync } from 'node:fs';
import path from 'node:path';

import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import {
  RepositoryPathPolicy,
  type RepositoryCapability,
} from './repository-capability.js';

function deny(reason: string): never {
  throw new McpError(
    JsonRpcErrorCode.Forbidden,
    `Repository metadata denied: ${reason}`,
  );
}

function statIfPresent(
  filename: string,
): ReturnType<typeof lstatSync> | undefined {
  try {
    return lstatSync(filename);
  } catch (error) {
    if (
      typeof error === 'object' &&
      error !== null &&
      'code' in error &&
      error.code === 'ENOENT'
    )
      return undefined;
    throw error;
  }
}

/** Pointer records allow one line ending, never Unicode whitespace trimming. */
function metadataPointer(
  policy: RepositoryPathPolicy,
  filename: string,
): string {
  const value = policy.readMetadata(filename).replace(/\r?\n$/, '');
  if (!value || /[\r\n\0]/.test(value) || /^[ \t]|[ \t]$/.test(value))
    deny('unsupported metadata path pointer');
  return value;
}

/** Conservative config: one initial BOM is syntax, value BOMs remain literal. */
export function metadataConfig(
  raw: string,
): ReadonlyMap<string, readonly string[]> {
  const values = new Map<string, string[]>();
  let section = '';
  const document = raw.startsWith('\ufeff') ? raw.slice(1) : raw;
  for (const line of document.split(/\r?\n/)) {
    const text = line.replace(/^[ \t]+|[ \t]+$/g, '');
    if (!text || /^[#;]/.test(text)) continue;
    if (text.startsWith('[')) {
      const match = text.match(
        /^\[([A-Za-z0-9.-]+)(?: "([^"\\]*)")?\][ \t]*(?:[#;].*)?$/,
      );
      if (!match) deny('unsupported configuration section');
      const name = match[1]!.toLowerCase();
      if (name === 'include' || name === 'includeif')
        deny('configuration includes are unsupported');
      section = name + (match[2] === undefined ? '' : `.${match[2]}`);
      continue;
    }
    const match = text.match(/^([A-Za-z][A-Za-z0-9-]*)(?:[ \t]*=[ \t]*(.*))?$/);
    if (!match || !section) deny('unsupported configuration assignment');
    const key = `${section}.${match[1]!.toLowerCase()}`;
    // Only fields used as paths/URLs are interpreted here. Other Git config
    // remains the runtime profile's responsibility (hooks, filters, signing).
    if (
      key !== 'core.worktree' &&
      !key.startsWith('remote.') &&
      !key.startsWith('url.')
    )
      continue;
    const value = match[2] ?? 'true';
    // Native Git supports escapes, continuations, comments and interpolation.
    // Reject these forms instead of disagreeing with Git about an effective URL.
    if (
      /[\\"#;]/.test(value) ||
      value.replace(/^[ \t]+|[ \t]+$/g, '') !== value ||
      value.includes('\0')
    )
      deny('ambiguous path or URL configuration');
    if (
      key === 'core.worktree' &&
      (value.startsWith('~') || value.includes('%('))
    )
      deny('unsupported worktree interpolation');
    values.set(key, [...(values.get(key) ?? []), value]);
  }
  return values;
}

/** All effective repository filesystem locations, with canonical path authority. */
export interface AuthorizedRepository extends RepositoryCapability {
  readonly gitDirectory: string;
  readonly commonDirectory: string;
  readonly worktree: string | undefined;
  readonly config: ReadonlyMap<string, readonly string[]>;
}

/**
 * Discover without starting Git or following config includes. Ancestor walking
 * stops at the authorized union. Normal, bare and linked repositories work
 * when every administrative backing path stays in that union.
 */
export function discoverRepository(
  policy: RepositoryPathPolicy,
  input: string,
  allowMissing?: false,
): AuthorizedRepository;
export function discoverRepository(
  policy: RepositoryPathPolicy,
  input: string,
  allowMissing: true,
): AuthorizedRepository | undefined;
export function discoverRepository(
  policy: RepositoryPathPolicy,
  input: string,
  allowMissing = false,
): AuthorizedRepository | undefined {
  const capability = policy.resolve(input);
  let current = capability.path;
  let gitDirectory: string | undefined;
  let worktree: string | undefined;
  for (;;) {
    const marker = path.join(current, '.git');
    const stat = statIfPresent(marker);
    if (stat) {
      policy.resolve(marker);
      if (stat.isDirectory()) gitDirectory = marker;
      else if (stat.isFile()) {
        const match = policy
          .readMetadata(marker)
          .match(/^gitdir: ([^\r\n\0]+)\r?\n?$/);
        if (!match) deny('invalid gitdir pointer');
        gitDirectory = policy.resolve(match[1]!, current).path;
      } else deny('unsupported gitdir marker');
      worktree = current;
      break;
    }
    if (
      statIfPresent(path.join(current, 'HEAD')) &&
      statIfPresent(path.join(current, 'objects')) &&
      statIfPresent(path.join(current, 'config'))
    ) {
      gitDirectory = current;
      break;
    }
    const parent = path.dirname(current);
    if (
      parent === current ||
      (policy.roots &&
        !policy.roots.some(
          (root) =>
            root !== current &&
            root.length <= parent.length &&
            (parent === root || parent.startsWith(`${root}${path.sep}`)),
        ))
    ) {
      if (allowMissing) return undefined;
      throw new McpError(
        JsonRpcErrorCode.ValidationError,
        'Repository metadata denied: not a git repository before root boundary.',
      );
    }
    current = policy.resolve(parent).path;
  }
  gitDirectory = policy.resolve(gitDirectory).path;
  const commonFile = path.join(gitDirectory, 'commondir');
  const commonDirectory = statIfPresent(commonFile)
    ? policy.resolve(metadataPointer(policy, commonFile), gitDirectory).path
    : gitDirectory;
  const config = new Map<string, readonly string[]>();
  for (const filename of [
    ...new Set([
      path.join(commonDirectory, 'config'),
      path.join(gitDirectory, 'config.worktree'),
    ]),
  ]) {
    if (!statIfPresent(filename)) continue;
    for (const [key, values] of metadataConfig(policy.readMetadata(filename)))
      config.set(key, [...(config.get(key) ?? []), ...values]);
  }
  const configuredWorktree = config.get('core.worktree');
  if (configuredWorktree)
    worktree = policy.resolve(configuredWorktree.at(-1)!, gitDirectory).path;
  if (worktree) policy.resolve(worktree);

  const visited = new Set<string>();
  let entries = 0;
  const scan = (directory: string): void => {
    const resolved = policy.resolve(directory).path;
    if (visited.has(resolved)) return;
    visited.add(resolved);
    if (!lstatSync(resolved).isDirectory()) deny('metadata directory expected');
    for (const entry of readdirSync(resolved, { withFileTypes: true })) {
      if (++entries > 100000) deny('metadata inventory exceeds entry limit');
      const filename = path.join(resolved, entry.name);
      policy.resolve(filename);
      if (entry.isDirectory()) scan(filename);
      else if (!entry.isFile()) deny('linked or special metadata');
      else if (entry.name === 'index' && lstatSync(filename).nlink !== 1)
        deny('hardlinked index');
      if (
        entry.isFile() &&
        (entry.name === 'config' || entry.name === 'config.worktree')
      ) {
        const nested = metadataConfig(policy.readMetadata(filename));
        const nestedWorktree = nested.get('core.worktree')?.at(-1);
        if (nestedWorktree !== undefined)
          policy.resolve(nestedWorktree, resolved);
      }
    }
    const alternates = path.join(resolved, 'info/alternates');
    const httpAlternates = path.join(resolved, 'info/http-alternates');
    if (
      statIfPresent(httpAlternates) &&
      policy.readMetadata(httpAlternates) !== ''
    )
      deny('HTTP object alternates are unsupported');
    if (statIfPresent(alternates)) {
      for (const alternate of policy
        .readMetadata(alternates)
        .split(/\r?\n/)
        .filter(Boolean)) {
        if (/["\\\0]/.test(alternate)) deny('unsupported alternate encoding');
        scan(policy.resolve(alternate, resolved).path);
      }
    }
  };
  scan(commonDirectory);
  if (gitDirectory !== commonDirectory) scan(gitDirectory);
  // Linked worktree records may point to a worktree not currently selected.
  const worktrees = path.join(commonDirectory, 'worktrees');
  if (statIfPresent(worktrees)) {
    for (const entry of readdirSync(worktrees)) {
      const pointer = path.join(worktrees, entry, 'gitdir');
      if (statIfPresent(pointer))
        policy.resolve(metadataPointer(policy, pointer), path.dirname(pointer));
    }
  }
  return Object.freeze({
    ...capability,
    gitDirectory,
    commonDirectory,
    worktree,
    config,
  });
}
