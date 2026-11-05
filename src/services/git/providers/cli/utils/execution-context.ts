/**
 * @fileoverview Request-owned cancellation, deadlines, processes and raw output.
 * @module services/git/providers/cli/utils/execution-context
 */
import { AsyncLocalStorage } from 'node:async_hooks';

import { GitExecutionError } from './execution-errors.js';
import { GitOutputBudget } from './output-budget.js';

/** Server-owned execution lifetime; never populated from tool input. */
export interface GitExecutionContext {
  signal?: AbortSignal | undefined;
  deadline?: number | undefined;
  startedAt: number;
}

interface ExecutionState {
  controller: AbortController;
  pending: Set<Promise<unknown>>;
  budget?: GitOutputBudget;
  failure?: GitExecutionError;
  closing: boolean;
}

const executionContext = new AsyncLocalStorage<GitExecutionContext>();
const executionStates = new WeakMap<GitExecutionContext, ExecutionState>();

function getState(): ExecutionState | undefined {
  const context = executionContext.getStore();
  return context ? executionStates.get(context) : undefined;
}

/**
 * Own every nested Git call until cleanup. Nested provider calls reuse the
 * original request scope; tighter operation limits belong in executor options.
 */
export async function withGitExecutionContext<T>(
  context: GitExecutionContext,
  operation: () => Promise<T>,
): Promise<T> {
  if (executionContext.getStore()) return operation();
  const remaining =
    context.deadline === undefined ? undefined : context.deadline - Date.now();
  if (
    remaining !== undefined &&
    (!Number.isSafeInteger(context.deadline) || remaining > 2_147_483_647)
  ) {
    throw new GitExecutionError(
      'INVALID_EXECUTION_OPTIONS',
      'Invalid Git request deadline.',
    );
  }
  const controller = new AbortController();
  const state: ExecutionState = {
    controller,
    pending: new Set(),
    closing: false,
  };
  const forwardAbort = () => controller.abort();
  context.signal?.addEventListener('abort', forwardAbort, { once: true });
  if (context.signal?.aborted) forwardAbort();
  const scoped = Object.freeze({ ...context, signal: controller.signal });
  executionStates.set(scoped, state);
  let timer: ReturnType<typeof setTimeout> | undefined;
  if (remaining !== undefined) {
    if (remaining <= 0) {
      state.failure = new GitExecutionError(
        'DEADLINE',
        'Git operation deadline exceeded before execution.',
      );
      controller.abort();
    } else
      timer = setTimeout(() => {
        state.failure ??= new GitExecutionError(
          'DEADLINE',
          'Git operation deadline exceeded.',
        );
        controller.abort();
      }, remaining);
  }

  return executionContext.run(scoped, async () => {
    try {
      if (state.failure) throw state.failure;
      if (controller.signal.aborted)
        throw new GitExecutionError(
          'CANCELLED',
          'Git request cancelled before execution.',
        );
      const outcome = await Promise.resolve()
        .then(operation)
        .then(
          (value) => ({ ok: true as const, value }),
          (error: unknown) => ({ ok: false as const, error }),
        );
      state.closing = true;
      if (state.pending.size > 0) {
        if (outcome.ok)
          state.failure ??= new GitExecutionError(
            'CLEANUP_FAILED',
            'Git operation returned with active processes.',
          );
        controller.abort();
        await Promise.allSettled([...state.pending]);
      }
      if (state.failure) throw state.failure;
      state.budget?.assertActive();
      if (!outcome.ok) throw outcome.error;
      if (controller.signal.aborted)
        throw new GitExecutionError('CANCELLED', 'Git request cancelled.');
      return outcome.value;
    } finally {
      state.closing = true;
      controller.abort();
      await Promise.allSettled([...state.pending]);
      clearTimeout(timer);
      context.signal?.removeEventListener('abort', forwardAbort);
    }
  });
}

/** Read the current scope without sharing it with other requests. */
export function getGitExecutionContext(): GitExecutionContext | undefined {
  return executionContext.getStore();
}

/** One aggregate raw-byte budget across every command in the current request. */
export function getGitOutputBudget(limit: number): GitOutputBudget {
  const state = getState();
  if (!state) return new GitOutputBudget(limit);
  state.budget ??= new GitOutputBudget(limit);
  state.budget.constrain(limit);
  return state.budget;
}

/** Reject late calls after a request ended, and preserve its first control failure. */
export function getGitExecutionFailure(): GitExecutionError | undefined {
  const state = getState();
  return (
    state?.failure ??
    (state?.closing
      ? new GitExecutionError(
          'CLEANUP_FAILED',
          'Git execution scope already ended.',
        )
      : undefined)
  );
}

/** Preserve authorization failures even if an operation catches an optional call. */
export function recordGitExecutionFailure(
  error: GitExecutionError,
): GitExecutionError {
  const state = getState();
  if (state) {
    state.failure ??= error;
    state.controller.abort();
    return state.failure;
  }
  return error;
}

/** Observe all native calls, including forgotten promises, without retaining output. */
export function trackGitExecution<T>(promise: Promise<T>): Promise<T> {
  const state = getState();
  if (!state) return promise;
  const tracked = promise.finally(() => state.pending.delete(tracked));
  state.pending.add(tracked);
  void tracked.catch((error: unknown) => {
    if (error instanceof GitExecutionError) {
      state.failure ??= error;
      state.controller.abort();
    }
  });
  return tracked;
}

/** Combine a provider's explicit cancellation with the SDK-owned request signal. */
export function createGitExecutionSignal(signal?: AbortSignal): {
  signal: AbortSignal | undefined;
  dispose: () => void;
} {
  const signals = [
    ...new Set(
      [signal, getGitExecutionContext()?.signal].filter(
        (value): value is AbortSignal => value !== undefined,
      ),
    ),
  ];
  if (signals.length < 2) return { signal: signals[0], dispose: () => {} };
  const controller = new AbortController();
  const abort = () => controller.abort();
  for (const source of signals) {
    source.addEventListener('abort', abort, { once: true });
    if (source.aborted) abort();
  }
  return {
    signal: controller.signal,
    dispose: () => {
      for (const source of signals) source.removeEventListener('abort', abort);
    },
  };
}
