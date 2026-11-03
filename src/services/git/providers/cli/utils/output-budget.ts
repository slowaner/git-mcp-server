/**
 * @fileoverview Aggregate raw-byte accounting for one Git request lifetime.
 * @module services/git/providers/cli/utils/output-budget
 */
import { GitExecutionError } from './execution-errors.js';

/** Hard ceiling for configured stream and aggregate output budgets. */
export const MAX_OUTPUT_BYTES = 128 * 1024 * 1024;

/** A shared, non-resettable request budget. Overflow poisons all later calls. */
export class GitOutputBudget {
  #limit: number;
  #consumed = 0;
  #failure: GitExecutionError | undefined;

  constructor(limit: number) {
    this.validate(limit);
    this.#limit = limit;
  }

  private validate(limit: number): void {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_OUTPUT_BYTES) {
      throw new GitExecutionError(
        'INVALID_EXECUTION_OPTIONS',
        'Invalid Git output budget.',
      );
    }
  }

  /** Current accepted bytes, including stdout/stderr and internal metadata calls. */
  get consumedBytes(): number {
    return this.#consumed;
  }

  /** Stable control failure after the first overflow, without retained payloads. */
  get failure(): GitExecutionError | undefined {
    return this.#failure;
  }

  /** Tighten a request's limit; a nested operation can never replenish it. */
  constrain(limit: number): void {
    this.validate(limit);
    this.#limit = Math.min(this.#limit, limit);
    if (this.#consumed > this.#limit) throw this.poison();
    this.assertActive();
  }

  /** Mark any stream/combined limit breach as terminal for the entire request. */
  poison(failure?: GitExecutionError): GitExecutionError {
    this.#failure ??=
      failure ??
      new GitExecutionError(
        'OUTPUT_LIMIT',
        'Git operation output byte budget exceeded; no partial output returned.',
      );
    return this.#failure;
  }

  /** Reject subsequent Git calls even if intermediate code caught overflow. */
  assertActive(): void {
    if (this.#failure) throw this.#failure;
  }

  /** Charge actual raw bytes before buffering; concurrent callbacks share state. */
  consume(bytes: number): void {
    this.assertActive();
    if (!Number.isSafeInteger(bytes) || bytes < 0) {
      throw new GitExecutionError(
        'INVALID_EXECUTION_OPTIONS',
        'Invalid Git output byte charge.',
      );
    }
    if (bytes > this.#limit - this.#consumed) throw this.poison();
    this.#consumed += bytes;
  }
}
