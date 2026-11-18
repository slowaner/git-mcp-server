/**
 * @fileoverview Effective local fetch/push URL authorization after Git rewrites.
 * @module services/git/core/repository-remotes
 */
import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import {
  localRemotePath,
  RepositoryPathPolicy,
} from './repository-capability.js';
import type { AuthorizedRepository } from './repository-discovery.js';

/** Apply Git's longest-prefix rewrite, preserving first-match tie ordering. */
export function rewriteRemoteUrl(
  url: string,
  config: ReadonlyMap<string, readonly string[]>,
  push: boolean,
  explicitPushUrl = false,
): string {
  const rewrite = (suffix: string): string | undefined => {
    let best: { prefix: string; base: string } | undefined;
    for (const [key, prefixes] of config) {
      if (!key.startsWith('url.') || !key.endsWith(suffix)) continue;
      const base = key.slice(4, -suffix.length);
      for (const prefix of prefixes) {
        if (
          url.startsWith(prefix) &&
          (!best || prefix.length > best.prefix.length)
        )
          best = { prefix, base };
      }
    }
    return best ? best.base + url.slice(best.prefix.length) : undefined;
  };
  // Explicit pushurl bypasses pushInsteadOf, but still uses insteadOf.
  if (push && !explicitPushUrl) {
    const pushed = rewrite('.pushinsteadof');
    if (pushed !== undefined) return pushed;
  }
  return rewrite('.insteadof') ?? url;
}

/** Authorize a concrete URL, including file URLs and relative stored paths. */
export function authorizeRemoteUrl(
  policy: RepositoryPathPolicy,
  url: string,
  cwd: string,
): string {
  const local = localRemotePath(url, cwd);
  if (local !== undefined) {
    if (url.startsWith('~'))
      throw new McpError(
        JsonRpcErrorCode.Forbidden,
        'Home-relative local remotes are unsupported.',
      );
    return policy.resolve(local).path;
  }
  // No native remote helpers or ambiguous URL schemes at this boundary.
  if (
    !/^(https?|ssh|git):\/\//i.test(url) &&
    !/^[^/:]+@?[^/:]*:[^:]/.test(url)
  ) {
    throw new McpError(
      JsonRpcErrorCode.Forbidden,
      'Unsupported remote transport.',
    );
  }
  if (url.includes('::'))
    throw new McpError(
      JsonRpcErrorCode.Forbidden,
      'Remote helper syntax is unsupported.',
    );
  return url;
}

/**
 * Check every configured URL before transfer, including defaults, multiple URLs,
 * separate push URLs and rewrites. A dormant outside URL is deliberately denied
 * rather than guessing which branch/default combination native Git will use.
 */
export function authorizeRepositoryRemotes(
  policy: RepositoryPathPolicy,
  repo: AuthorizedRepository,
  direction: 'fetch' | 'push',
): void {
  const names = new Set<string>();
  for (const key of repo.config.keys()) {
    if (key.startsWith('remote.') && key.endsWith('.url'))
      names.add(key.slice(7, -4));
    if (key.startsWith('remote.') && key.endsWith('.pushurl'))
      names.add(key.slice(7, -8));
  }
  for (const name of names) {
    const explicit =
      direction === 'push' && repo.config.has(`remote.${name}.pushurl`);
    const urls =
      repo.config.get(`remote.${name}.${explicit ? 'pushurl' : 'url'}`) ?? [];
    for (const url of urls)
      authorizeRemoteUrl(
        policy,
        rewriteRemoteUrl(url, repo.config, direction === 'push', explicit),
        repo.path,
      );
  }
}
