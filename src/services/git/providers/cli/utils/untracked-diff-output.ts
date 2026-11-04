/**
 * @fileoverview Bounded machine prefix for the qualified fixed untracked tuple.
 * Input must have crossed the executor's complete lossless UTF-8 boundary.
 * @module services/git/providers/cli/utils/untracked-diff-output
 */
import { recordGitExecutionFailure } from './execution-context.js';
import { GitExecutionError } from './execution-errors.js';
import { MAX_OUTPUT_BYTES } from './output-budget.js';

/** Exact native stats plus the opaque, unchanged standalone patch suffix. */
export interface UntrackedDiffOutput {
  readonly patch: string;
  readonly insertions: number;
  readonly deletions: number;
  readonly binary: boolean;
  readonly filesChanged: 1;
}

function invalid(): never {
  throw recordGitExecutionFailure(
    new GitExecutionError(
      'INVALID_OUTPUT_FORMAT',
      'Invalid combined untracked Git diff output.',
    ),
  );
}

/**
 * Parse only the bounded prefix, never patch markers or patch NULs. The
 * installed fixed /dev/null-versus-regular-file tuple is qualified to emit one
 * two-path record, including empty files. Other layouts fail closed until
 * qualified; this is deliberately not a generic tracked/rename parser.
 */
export function parseUntrackedDiffOutput(
  output: string,
  literalFile: string,
  maximumBytes = MAX_OUTPUT_BYTES,
): UntrackedDiffOutput {
  if (
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    maximumBytes > MAX_OUTPUT_BYTES ||
    output.length > maximumBytes ||
    Buffer.byteLength(output, 'utf8') > maximumBytes ||
    !literalFile ||
    literalFile.includes('\0') ||
    Buffer.byteLength(literalFile, 'utf8') > 32768 ||
    Buffer.from(literalFile, 'utf8').toString('utf8') !== literalFile
  )
    invalid();
  let cursor = 0;
  const count = (): number | undefined => {
    if (output[cursor] === '-') {
      cursor++;
      if (output[cursor++] !== '\t') invalid();
      return undefined;
    }
    const start = cursor;
    let value = 0;
    while (cursor - start < 16) {
      const character = output.charCodeAt(cursor);
      if (character < 48 || character > 57 || !Number.isFinite(character))
        break;
      value = value * 10 + character - 48;
      if (!Number.isSafeInteger(value)) invalid();
      cursor++;
    }
    if (
      cursor === start ||
      (cursor - start > 1 && output[start] === '0') ||
      output[cursor++] !== '\t'
    )
      invalid();
    return value;
  };
  const insertions = count();
  const deletions = count();
  if ((insertions === undefined) !== (deletions === undefined)) invalid();
  // Only actually qualified native layouts are supported. Every installed-Git
  // fixture for this tuple uses this complete two-path spelling.
  if (output[cursor++] !== '\0') invalid();
  const path = (expected: string): void => {
    if (
      !output.startsWith(expected, cursor) ||
      output[cursor + expected.length] !== '\0'
    )
      invalid();
    cursor += expected.length + 1;
  };
  path('/dev/null');
  path(literalFile);
  // The record terminator above and this additional separator are distinct.
  // All remaining code units belong to the opaque lossless patch, even NULs.
  if (output[cursor++] !== '\0') invalid();
  return {
    patch: output.slice(cursor),
    insertions: insertions ?? 0,
    deletions: deletions ?? 0,
    binary: insertions === undefined,
    filesChanged: 1,
  };
}
