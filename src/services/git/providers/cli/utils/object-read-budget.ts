/**
 * @fileoverview Aggregate bounds for sequential structured Git record reads.
 * @module services/git/providers/cli/utils/object-read-budget
 */
import type { ReadObjectCommand } from './structured-object-reader.js';
import { recordGitExecutionFailure } from './execution-context.js';
import { GitExecutionError } from './execution-errors.js';

/** Server-owned limits; independent from per-process and JSON-RPC wire caps. */
export interface ObjectReadLimits {
  readonly maxBytes: number;
  readonly maxCalls: number;
}

/**
 * Wrap an already byte-bounded executor with a per-operation read budget.
 * Calls are sequential to avoid multiplying concurrent process buffers. Failure
 * is terminal; callers must fail the whole result, never return partial records.
 * This helper grants neither Git-command nor repository/destination authority.
 */
export function objectReadBudget(
  read: ReadObjectCommand,
  limits: ObjectReadLimits,
): ReadObjectCommand {
  const { maxBytes, maxCalls } = limits;
  if (
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 1 ||
    !Number.isSafeInteger(maxCalls) ||
    maxCalls < 1
  )
    throw new RangeError('Invalid Git object read budget');
  let bytes = 0;
  let calls = 0;
  let failed = false;
  let inFlight = false;
  const exhausted = (message = 'Git object read budget exhausted.'): never => {
    failed = true;
    throw recordGitExecutionFailure(
      new GitExecutionError('OUTPUT_LIMIT', message),
    );
  };
  return async (args) => {
    if (failed || calls >= maxCalls) return exhausted();
    if (inFlight) {
      failed = true;
      return exhausted('Git object reads must be sequential.');
    }
    calls++;
    inFlight = true;
    try {
      const result = await read(args);
      if (failed) return exhausted();
      if (
        typeof result.stdout !== 'string' ||
        typeof result.stderr !== 'string'
      )
        throw new Error('Invalid Git object read result');
      const size =
        Buffer.byteLength(result.stdout, 'utf8') +
        Buffer.byteLength(result.stderr, 'utf8');
      if (size > maxBytes - bytes)
        return exhausted('Aggregate Git object output budget exceeded.');
      bytes += size;
      return result;
    } catch (error) {
      failed = true;
      throw error;
    } finally {
      inFlight = false;
    }
  };
}
