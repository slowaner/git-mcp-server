/**
 * @fileoverview Canonical filesystem capabilities for repository entrypoints.
 * These checks are not a substitute for runtime containment in writable trees.
 * @module services/git/core/repository-capability
 */
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';

/** Component-aware containment; sibling prefixes do not confer authority. */
export function containsPath(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return (
    relative === '' ||
    (relative !== '..' &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative))
  );
}

function denied(reason: string): never {
  throw new McpError(
    JsonRpcErrorCode.Forbidden,
    `Repository boundary denied: ${reason}`,
  );
}

function missing(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'ENOENT'
  );
}

/** Immutable roots supplied by configuration or a narrower per-request ACL. */
export interface RepositoryCapability {
  readonly path: string;
  readonly roots: readonly string[] | undefined;
  readonly existingParent: string;
}

type Root = { input: string; canonical: string; dev: number; ino: number };

/**
 * Authorize existing paths and new destinations against pinned canonical roots.
 * Relative paths always use the first configured root, never a search over roots.
 * Links beneath a root are deliberately rejected, including dangling links.
 * Windows/reparse-point confinement is unsupported and fails closed.
 */
export class RepositoryPathPolicy {
  private readonly entries: readonly Root[] | undefined;
  private relativeBase: string;
  private ceiling: RepositoryPathPolicy | undefined;
  readonly roots: readonly string[] | undefined;

  constructor(roots?: readonly string[]) {
    if (
      roots !== undefined &&
      (roots.length === 0 || process.platform === 'win32')
    ) {
      denied('empty roots or unsupported reparse-point platform');
    }
    this.entries = roots?.map((input) => {
      if (/[\uD800-\uDFFF]/u.test(input)) denied('invalid Unicode root');
      const absolute = path.resolve(input);
      if (absolute.includes(path.delimiter) || /[\r\n\0]/.test(absolute))
        denied(
          'configured root cannot be represented by native discovery ceiling',
        );
      let ancestor = path.dirname(absolute);
      for (;;) {
        const parentStat = lstatSync(ancestor);
        // System aliases (/var -> /private/var on macOS) are immutable under
        // the trusted operator profile. User-controlled root aliases are not.
        if (
          parentStat.isSymbolicLink() &&
          !(parentStat.uid === 0 && ['/var', '/tmp', '/etc'].includes(ancestor))
        ) {
          denied('configured root has a symbolic-link ancestor');
        }
        const parent = path.dirname(ancestor);
        if (parent === ancestor) break;
        ancestor = parent;
      }
      const stat = lstatSync(absolute);
      if (!stat.isDirectory() || stat.isSymbolicLink())
        denied('root must be a real directory');
      return {
        input: absolute,
        canonical: realpathSync(absolute),
        dev: stat.dev,
        ino: stat.ino,
      };
    });
    this.roots =
      this.entries && Object.freeze(this.entries.map((root) => root.canonical));
    this.relativeBase = this.entries?.[0]?.input ?? process.cwd();
  }

  /** Narrow server-issued roots against the operator ceiling; never widen it. */
  restrict(roots: readonly string[] | undefined): RepositoryPathPolicy {
    if (roots === undefined) return this;
    const canonical = roots.map((root) => this.resolve(root).path);
    const narrowed = new RepositoryPathPolicy(canonical);
    narrowed.relativeBase = this.relativeBase;
    narrowed.ceiling = this;
    return narrowed;
  }

  /** Resolve without creating anything. Missing leaves require an authorized parent. */
  resolve(input: string, relativeTo?: string): RepositoryCapability {
    if (
      typeof input !== 'string' ||
      !input ||
      input.includes('\0') ||
      /[\uD800-\uDFFF]/u.test(input) ||
      /^[A-Za-z]:[\\/]/.test(input) ||
      input.startsWith('\\\\')
    ) {
      denied('invalid or unsupported path encoding');
    }
    let lexicalCandidate = path.resolve(relativeTo ?? this.relativeBase, input);
    if (!this.entries) {
      for (const alias of ['/var', '/tmp', '/etc']) {
        if (!containsPath(alias, lexicalCandidate)) continue;
        const stat = lstatSync(alias);
        if (stat.uid === 0 && stat.isSymbolicLink())
          lexicalCandidate = path.join(
            realpathSync(alias),
            path.relative(alias, lexicalCandidate),
          );
      }
    }
    const candidate =
      this.ceiling?.resolve(lexicalCandidate).path ?? lexicalCandidate;
    for (const root of this.entries ?? []) {
      const stat = lstatSync(root.input);
      if (
        !stat.isDirectory() ||
        stat.isSymbolicLink() ||
        stat.dev !== root.dev ||
        stat.ino !== root.ino ||
        realpathSync(root.input) !== root.canonical
      ) {
        denied('configured root changed');
      }
    }
    const root = this.entries?.find(
      (entry) =>
        containsPath(entry.input, candidate) ||
        containsPath(entry.canonical, candidate),
    );
    if (this.entries && !root)
      denied('Path traversal detected: path escapes configured roots');

    // Start at the selected root to avoid treating OS aliases such as /tmp as
    // untrusted child links. Every component below that root is checked.
    const lexicalRoot = root
      ? containsPath(root.input, candidate)
        ? root.input
        : root.canonical
      : path.parse(candidate).root;
    let current = root?.canonical ?? lexicalRoot;
    let existingParent = current;
    const components = path
      .relative(lexicalRoot, candidate)
      .split(path.sep)
      .filter(Boolean);
    let absent = false;
    for (const component of components) {
      current = path.join(current, component);
      if (absent) continue;
      try {
        const stat = lstatSync(current);
        if (stat.isSymbolicLink())
          denied('symbolic links beneath repository roots are unsupported');
        if (
          !stat.isDirectory() &&
          current !== path.join(root?.canonical ?? lexicalRoot, ...components)
        )
          denied('non-directory ancestor');
        existingParent = current;
      } catch (error) {
        if (!missing(error)) throw error;
        absent = true;
      }
    }
    if (
      this.roots &&
      !this.roots.some((allowed) => containsPath(allowed, current))
    )
      denied('canonical target escapes roots');
    return Object.freeze({ path: current, roots: this.roots, existingParent });
  }

  /** Read bounded regular UTF-8 metadata, retaining BOM and rejecting byte loss. */
  readMetadata(input: string, limit = 1024 * 1024): string {
    const authorized = this.resolve(input);
    const fd = openSync(
      authorized.path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    try {
      const stat = fstatSync(fd);
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > limit)
        denied('unsupported metadata file');
      const bytes = Buffer.alloc(limit + 1);
      // A bounded fd read is required even if the file grows after fstat.
      let count = 0;
      while (count < bytes.length) {
        const read = readSync(fd, bytes, count, bytes.length - count, count);
        if (read === 0) break;
        count += read;
      }
      if (count > limit) denied('metadata exceeds byte limit');
      try {
        return new TextDecoder('utf-8', {
          fatal: true,
          ignoreBOM: true,
        }).decode(bytes.subarray(0, count));
      } catch {
        denied('metadata must contain valid UTF-8');
      }
    } finally {
      closeSync(fd);
    }
  }
}

// Kept separate from path authorization so callers never decode ordinary paths.
/** Resolve all local transport spellings; return undefined for network URLs. */
export function localRemotePath(url: string, cwd: string): string | undefined {
  if (
    !url ||
    url.includes('\0') ||
    /[\uD800-\uDFFF]/u.test(url) ||
    url.startsWith('-')
  )
    denied('invalid remote');
  if (/^file:/i.test(url)) {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      denied('invalid file URL');
    }
    if (
      parsed.search ||
      parsed.hash ||
      parsed.username ||
      parsed.password ||
      (parsed.hostname && parsed.hostname !== 'localhost')
    )
      denied('unsupported file URL');
    try {
      return fileURLToPath(parsed);
    } catch {
      denied('invalid local URL encoding');
    }
  }
  if (/^[A-Za-z]:[\\/]/.test(url) || url.startsWith('\\\\'))
    denied('unsupported local platform path');
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(url) || /^[^/]+:/.test(url))
    return undefined;
  return path.resolve(cwd, url);
}
