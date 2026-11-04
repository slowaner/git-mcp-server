/**
 * @fileoverview Literal file operands and lossless bounded Git filename framing.
 * @module services/git/providers/cli/utils/git-file-operands
 */
import { recordGitExecutionFailure } from './execution-context.js';
import { GitExecutionError } from './execution-errors.js';

/** Server-owned filename limits, additional to the request-wide process budget. */
export interface GitFileLimits {
  readonly maxBytes: number;
  readonly maxFiles: number;
}

/** Finite semantic filename budget, in addition to the executor raw-byte cap. */
export const GIT_FILE_LIMITS: GitFileLimits = Object.freeze({
  maxBytes: 1024 * 1024,
  maxFiles: 4096,
});

function validateLimits(limits: GitFileLimits): void {
  if (
    !Number.isSafeInteger(limits.maxBytes) ||
    limits.maxBytes < 1 ||
    !Number.isSafeInteger(limits.maxFiles) ||
    limits.maxFiles < 1
  )
    throw new Error('Invalid Git filename limits');
}

function validatePath(path: string): void {
  if (typeof path !== 'string' || !path.length || path.includes('\0'))
    throw new Error('Invalid Git filename');
  for (const character of path) {
    const point = character.codePointAt(0)!;
    if (point >= 0xd800 && point <= 0xdfff)
      throw new Error('Invalid Git filename Unicode');
  }
}

function validatePaths(paths: readonly string[], limits: GitFileLimits): void {
  validateLimits(limits);
  if (paths.length > limits.maxFiles)
    throw new Error('Git filename item limit exceeded');
  let bytes = 0;
  for (const path of paths) {
    if (path.length >= limits.maxBytes - bytes)
      throw new Error('Git filename byte limit exceeded');
    validatePath(path);
    bytes += Buffer.byteLength(path, 'utf8') + 1;
    if (bytes > limits.maxBytes)
      throw new Error('Git filename byte limit exceeded');
  }
}

/**
 * Return the complete option-separated operand tail, with literal Git pathspecs.
 * Names containing magic/globs/dashes remain filenames; '.' remains a directory.
 * No native-pattern escape is accepted. Byte limits count names plus NUL framing;
 * the literal prefix is fixed overhead bounded by maxFiles. Callers must retain
 * G1 canonical-path/ACL authority and G2 process policy; this is neither consent
 * nor filesystem confinement.
 */
export function literalFileArguments(
  paths: readonly string[],
  limits: GitFileLimits = GIT_FILE_LIMITS,
): string[] {
  validatePaths(paths, limits);
  return ['--', ...paths.map((path) => `:(literal)${path}`)];
}

/**
 * For commands taking a POSIX repo-relative file rather than a pathspec (notably
 * diff --no-index). './-' names the actual file instead of Git's stdin marker.
 * Callers still add '--' and must authorize the path through G1.
 */
export function literalFileOperand(
  path: string,
  limits: GitFileLimits = GIT_FILE_LIMITS,
): string {
  validatePaths([path], limits);
  if (path.startsWith('/'))
    throw new Error('Repository-relative filename required');
  return `./${path}`;
}

/**
 * Parse actual native bytes from a Git '-z' filename-only stream. A decoded
 * legacy/lossy string re-encoded by the caller is not original-byte proof.
 * Encoding is valid only after G2's strict EOF boundary is proved lossless.
 * Fatal UTF-8
 * distinguishes invalid bytes from valid U+FFFD and preserves a leading BOM.
 * No trimming/normalization/truncation or partial result is permitted.
 */
export function nulFileNames(
  raw: Uint8Array,
  limits: GitFileLimits = GIT_FILE_LIMITS,
): string[] {
  validateLimits(limits);
  if (!(raw instanceof Uint8Array))
    throw new Error('Original Git filename bytes required');
  if (raw.byteLength > limits.maxBytes)
    throw new Error('Git filename byte limit exceeded');
  let output: string;
  try {
    output = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(
      raw,
    );
  } catch {
    throw new Error('Git filename output is not valid UTF-8');
  }
  if (!output.length) return [];
  if (!output.endsWith('\0')) throw new Error('Truncated Git filename stream');
  const paths: string[] = [];
  const seen = new Set<string>();
  let start = 0;
  while (start < output.length) {
    if (paths.length >= limits.maxFiles)
      throw new Error('Git filename item limit exceeded');
    const end = output.indexOf('\0', start);
    const path = output.slice(start, end);
    validatePath(path);
    if (seen.has(path)) throw new Error('Duplicate Git filename record');
    seen.add(path);
    paths.push(path);
    start = end + 1;
  }
  return paths;
}

/**
 * Consume only complete strings from the strict native executor boundary.
 * Check a cheap byte lower bound before allocating encoded bytes, reject lone
 * surrogates rather than replacing them, and poison malformed/over-budget
 * filename results so a caught optional read cannot return partial success.
 */
export function nativeFileNames(
  output: string,
  limits: GitFileLimits = GIT_FILE_LIMITS,
): string[] {
  try {
    validateLimits(limits);
    if (typeof output !== 'string')
      throw new Error('Invalid native filename output');
    if (output.length > limits.maxBytes)
      throw new RangeError('Filename limit exceeded');
    for (const character of output) {
      const point = character.codePointAt(0)!;
      if (point >= 0xd800 && point <= 0xdfff)
        throw new Error('Invalid native Unicode');
    }
    return nulFileNames(new TextEncoder().encode(output), limits);
  } catch (error) {
    const overflow =
      error instanceof RangeError ||
      (error instanceof Error && /limit exceeded/.test(error.message));
    throw recordGitExecutionFailure(
      new GitExecutionError(
        overflow ? 'OUTPUT_LIMIT' : 'INVALID_OUTPUT_FORMAT',
        overflow
          ? 'Git filename budget exceeded.'
          : 'Invalid Git filename output.',
      ),
    );
  }
}
