/**
 * @fileoverview Lexical allowlist for Git repository and destination paths.
 * @module mcp-server/tools/utils/git-path-policy
 */
import path from 'node:path';

import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import { sanitization } from '@/utils/index.js';

/** Resolve once against a fixed base; never search relative paths across roots. */
export function resolvePathWithinGitRoots(
  input: string,
  roots?: readonly string[],
  relativeTo?: string,
): string {
  if (typeof input !== 'string' || input.length === 0 || input.includes('\0')) {
    throw new McpError(
      JsonRpcErrorCode.ValidationError,
      'Path must be non-empty and contain no null bytes.',
    );
  }
  const base = relativeTo ?? roots?.[0] ?? process.cwd();
  const candidate = path.resolve(base, input);
  // Retain shared input validation without changing storage sanitizer semantics.
  sanitization.sanitizePath(candidate, { allowAbsolute: true });
  if (
    roots &&
    !roots.some((root) => {
      const relative = path.relative(root, candidate);
      return (
        relative === '' ||
        (relative !== '..' &&
          !relative.startsWith(`..${path.sep}`) &&
          !path.isAbsolute(relative))
      );
    })
  ) {
    throw new McpError(
      JsonRpcErrorCode.ValidationError,
      'Path traversal detected: attempts to escape the defined root directory.',
    );
  }
  return candidate;
}

/** Apply the configured roots to a repository, local source, or destination. */
export async function resolveGitPath(
  input: string,
  options: { relativeTo?: string; unrestrictedRelative?: boolean } = {},
): Promise<string> {
  const { config } = await import('@/config/index.js');
  const roots = config?.git?.baseDirs;
  if (!roots && !options.relativeTo && !options.unrestrictedRelative) {
    // Preserve the legacy relative-path validation when no roots are configured.
    input = sanitization.sanitizePath(input, {
      allowAbsolute: true,
    }).sanitizedPath;
  }
  return resolvePathWithinGitRoots(input, roots, options.relativeTo);
}
