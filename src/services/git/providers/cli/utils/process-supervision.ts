/**
 * @fileoverview Bounded process I/O with an anchored POSIX group lifetime.
 * @module services/git/providers/cli/utils/process-supervision
 */
import { spawn } from 'node:child_process';
import { dirname, isAbsolute, resolve as resolvePath } from 'node:path';
import type { Readable } from 'node:stream';

import { GitExecutionError } from './execution-errors.js';
import { GIT_PROCESS_HOST_SOURCE } from './process-host.js';
import {
  createGitExecutionSignal,
  getGitExecutionContext,
  getGitExecutionFailure,
  getGitOutputBudget,
  trackGitExecution,
} from './execution-context.js';
import { MAX_OUTPUT_BYTES, type GitOutputBudget } from './output-budget.js';

/** Hard ceiling for configured per-stream and combined output budgets. */
export { MAX_OUTPUT_BYTES } from './output-budget.js';

/** Supervisor inputs, validated independently from application config loading. */
export interface SupervisedProcessOptions {
  binaryPath: string;
  args: readonly string[];
  cwd: string;
  env: Record<string, string>;
  timeoutMs: number;
  deadline?: number | undefined;
  signal?: AbortSignal | undefined;
  maxStdoutBytes: number;
  maxStderrBytes: number;
  maxOutputBytes: number;
  terminationGraceMs: number;
  allowNonZeroExit?: boolean | undefined;
  /** Shared aggregate budget for the owning request. */
  outputBudget?: GitOutputBudget | undefined;
}

/** Complete output only; execution-control failures are never soft Git exits. */
export interface SupervisedProcessResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/** Reject invalid bounds and unsupported platforms before creating a process. */
export function validateProcessOptions(
  options: SupervisedProcessOptions,
): void {
  const integer = (value: number, min: number, max: number) =>
    Number.isSafeInteger(value) && value >= min && value <= max;
  if (
    !isAbsolute(options.binaryPath) ||
    options.binaryPath.includes('\0') ||
    !integer(options.timeoutMs, 1, 2_147_483_647) ||
    !integer(options.terminationGraceMs, 0, 5000) ||
    ![
      options.maxStdoutBytes,
      options.maxStderrBytes,
      options.maxOutputBytes,
    ].every((value) => integer(value, 1, MAX_OUTPUT_BYTES)) ||
    (options.deadline !== undefined && !Number.isSafeInteger(options.deadline))
  ) {
    throw new GitExecutionError(
      'INVALID_EXECUTION_OPTIONS',
      'Invalid Git execution limits or binary path.',
    );
  }
  if (process.platform !== 'linux' && process.platform !== 'darwin') {
    throw new GitExecutionError(
      'POLICY_UNSUPPORTED',
      'Process-group supervision unsupported on this platform.',
    );
  }
}

/**
 * Keep the group leader alive until final KILL to prevent PID/PGID reuse and
 * post-exit signal races. Drain both streams concurrently from spawn through
 * cleanup. Native trusted helpers must not detach sessions; this group lifecycle
 * is not filesystem/egress containment. At most two bounded buffers are reserved
 * (one per stream), with no chunk-count amplification or partial-output success.
 */
export function superviseProcess(
  options: SupervisedProcessOptions,
): Promise<SupervisedProcessResult> {
  // Track the exact promise returned to the caller, including the signal lease.
  // An async wrapper around a tracked inner promise would itself reject unobserved
  // when a caller forgets to await it.
  return trackGitExecution(
    (async () => {
      const failure = getGitExecutionFailure();
      if (failure) throw failure;
      const lease = createGitExecutionSignal(options.signal);
      const deadline = getGitExecutionContext()?.deadline;
      try {
        return await runSupervisedProcess({
          ...options,
          signal: lease.signal,
          deadline:
            deadline === undefined
              ? options.deadline
              : Math.min(deadline, options.deadline ?? deadline),
        });
      } catch (error) {
        // A request deadline aborts its process signal. Preserve the recorded
        // request reason when this await resumes in that scope; cleanup errors
        // still retain their higher priority.
        if (error instanceof GitExecutionError && error.reason === 'CANCELLED')
          throw getGitExecutionFailure() ?? error;
        throw error;
      } finally {
        lease.dispose();
      }
    })(),
  );
}

async function runSupervisedProcess(
  options: SupervisedProcessOptions,
): Promise<SupervisedProcessResult> {
  validateProcessOptions(options);
  const outputBudget =
    options.outputBudget ?? getGitOutputBudget(options.maxOutputBytes);
  outputBudget.assertActive();
  if (options.signal?.aborted) {
    throw new GitExecutionError(
      'CANCELLED',
      'Git command cancelled before execution.',
    );
  }
  const remaining = Math.min(
    options.timeoutMs,
    (options.deadline ?? Infinity) - Date.now(),
  );
  if (remaining <= 0) {
    throw new GitExecutionError(
      'DEADLINE',
      'Git operation deadline exceeded before execution.',
    );
  }

  return new Promise((resolve, reject) => {
    const host = spawn(
      process.execPath,
      [
        '-e',
        GIT_PROCESS_HOST_SOURCE,
        '--',
        resolvePath(options.cwd),
        options.binaryPath,
        ...options.args,
      ],
      {
        // Runtime startup must not load repository-local Bun/package config.
        cwd: dirname(process.execPath),
        env: options.env,
        detached: true,
        shell: false,
        stdio: ['pipe', 'pipe', 'pipe', 'pipe'],
      },
    );
    // Immutable PID; never send to 0, -1, or a handle value changed after exit.
    const groupId = host.pid;
    const stdout = host.stdout;
    const stderr = host.stderr;
    const input = host.stdin;
    const control = host.stdio[3] as Readable;
    const buffers: Partial<Record<'stdout' | 'stderr', Buffer>> = {};
    const bytes = { stdout: 0, stderr: 0, total: 0 };
    let failure: Error | undefined;
    let cleanupFailure: GitExecutionError | undefined;
    let ready = false;
    let stopping = false;
    let killed = false;
    let anchorExited = false;
    let closed = false;
    let finished = false;
    let gitExit: { code: number | null; signal: string | null } | undefined;
    let stdoutEnded = false;
    let stderrEnded = false;
    let controlText = '';
    let controlBytes = 0;
    let escalation: ReturnType<typeof setTimeout> | undefined;
    let drainTimer: ReturnType<typeof setTimeout> | undefined;

    const signalGroup = (signal: NodeJS.Signals | 0): boolean => {
      // Never signal an ID after its anchor exited: it may belong to someone else.
      if (anchorExited || groupId === undefined || groupId <= 1) return false;
      try {
        process.kill(-groupId, signal);
        return true;
      } catch (error) {
        cleanupFailure = new GitExecutionError(
          'CLEANUP_FAILED',
          `Cannot signal anchored Git process group (${signal}: ${(error as NodeJS.ErrnoException).code ?? 'unknown'}).`,
        );
        return false;
      }
    };

    const finish = () => {
      if (finished || !closed) return;
      finished = true;
      clearTimeout(deadlineTimer);
      clearTimeout(escalation);
      clearTimeout(drainTimer);
      options.signal?.removeEventListener('abort', abort);
      if (cleanupFailure) {
        reject(cleanupFailure);
        return;
      }
      if (failure) {
        reject(failure);
        return;
      }
      const budgetFailure = outputBudget.failure;
      if (budgetFailure) {
        reject(budgetFailure);
        return;
      }
      if (!gitExit || gitExit.code === null || gitExit.signal !== null) {
        reject(
          new GitExecutionError(
            'SIGNAL_EXIT',
            'Git command did not complete with an ordinary exit.',
          ),
        );
        return;
      }
      let result: SupervisedProcessResult;
      try {
        // Complete streams only: preserve BOM and literal U+FFFD. Fatal decoding
        // makes re-encoding a lossless boundary for the original accepted bytes.
        const decode = (stream: 'stdout' | 'stderr') =>
          new TextDecoder('utf-8', {
            fatal: true,
            ignoreBOM: true,
          }).decode(buffers[stream]?.subarray(0, bytes[stream]));
        result = {
          stdout: decode('stdout'),
          stderr: decode('stderr'),
          exitCode: gitExit.code,
        };
      } catch {
        reject(
          outputBudget.poison(
            new GitExecutionError(
              'INVALID_OUTPUT_ENCODING',
              'Git output is not valid UTF-8; no partial output returned.',
            ),
          ),
        );
        return;
      }
      if (gitExit.code !== 0 && !options.allowNonZeroExit) {
        reject(
          new Error(
            `Exit Code: ${gitExit.code}\nStderr: ${result.stderr}\nStdout: ${result.stdout}`,
          ),
        );
      } else resolve(result);
    };

    const boundDrain = () => {
      drainTimer ??= setTimeout(() => {
        input.destroy();
        stdout.destroy();
        stderr.destroy();
        control.destroy();
        cleanupFailure ??= new GitExecutionError(
          'CLEANUP_FAILED',
          `Git streams did not close after group termination (anchorExited=${anchorExited}, killed=${killed}, stdoutEnded=${stdoutEnded}, stderrEnded=${stderrEnded}, gitExit=${gitExit?.code ?? 'none'}).`,
        );
        closed = true;
        finish();
      }, 1000);
    };

    const kill = () => {
      if (anchorExited) {
        boundDrain();
        return;
      }
      killed = signalGroup('SIGKILL');
      boundDrain();
    };

    const stop = (error?: Error) => {
      failure ??= error;
      if (stopping || finished) return;
      stopping = true;
      if (!ready) {
        // Before the TERM-ignore handshake, a single final KILL avoids any
        // re-signal of a reaped/reused process group. Git has not started yet.
        kill();
      } else if (signalGroup('SIGTERM')) {
        escalation = setTimeout(kill, options.terminationGraceMs);
      } else boundDrain();
    };

    const consume = (stream: 'stdout' | 'stderr', chunk: Buffer) => {
      if (failure || cleanupFailure) return;
      const limit =
        stream === 'stdout' ? options.maxStdoutBytes : options.maxStderrBytes;
      if (
        chunk.byteLength > limit - bytes[stream] ||
        chunk.byteLength > options.maxOutputBytes - bytes.total
      ) {
        delete buffers.stdout;
        delete buffers.stderr;
        stop(outputBudget.poison());
        return;
      }
      try {
        outputBudget.consume(chunk.byteLength);
      } catch (error) {
        delete buffers.stdout;
        delete buffers.stderr;
        stop(error instanceof Error ? error : outputBudget.poison());
        return;
      }
      const needed = bytes[stream] + chunk.byteLength;
      let buffer = buffers[stream];
      if (!buffer || buffer.byteLength < needed) {
        const capacity = Math.min(
          limit,
          options.maxOutputBytes,
          Math.max(needed, buffer ? buffer.byteLength * 2 : 1024),
        );
        const next = Buffer.allocUnsafe(capacity);
        buffer?.copy(next, 0, 0, bytes[stream]);
        buffers[stream] = next;
        buffer = next;
      }
      chunk.copy(buffer, bytes[stream]);
      bytes[stream] += chunk.byteLength;
      bytes.total += chunk.byteLength;
    };
    const drainComplete = () => {
      if (!gitExit || !stdoutEnded || !stderrEnded || stopping) return;
      // Git has exited and both output streams reached EOF. No graceful Git
      // shutdown remains: keep the anchor live until one final group KILL.
      stopping = true;
      kill();
    };
    stdout.on('data', (chunk: Buffer) => consume('stdout', chunk));
    stderr.on('data', (chunk: Buffer) => consume('stderr', chunk));
    stdout.on('end', () => {
      stdoutEnded = true;
      drainComplete();
    });
    stderr.on('end', () => {
      stderrEnded = true;
      drainComplete();
    });
    stdout.on('error', () =>
      stop(
        new GitExecutionError('CLEANUP_FAILED', 'Git stdout stream failed.'),
      ),
    );
    stderr.on('error', () =>
      stop(
        new GitExecutionError('CLEANUP_FAILED', 'Git stderr stream failed.'),
      ),
    );
    input.on('error', () => {
      if (!stopping)
        stop(
          new GitExecutionError(
            'SPAWN_FAILED',
            'Git host startup pipe failed.',
          ),
        );
    });
    control.on('error', () =>
      stop(
        new GitExecutionError('SPAWN_FAILED', 'Git host control pipe failed.'),
      ),
    );
    control.on('data', (chunk: Buffer) => {
      controlBytes += chunk.byteLength;
      if (controlBytes > 1024) {
        stop(
          new GitExecutionError(
            'SPAWN_FAILED',
            'Git host protocol byte budget exceeded.',
          ),
        );
        return;
      }
      controlText += chunk.toString('utf8');
      let newline: number;
      while ((newline = controlText.indexOf('\n')) !== -1) {
        const line = controlText.slice(0, newline);
        controlText = controlText.slice(newline + 1);
        let message: {
          type?: string;
          pid?: number;
          code?: unknown;
          signal?: unknown;
        };
        try {
          message = JSON.parse(line) as typeof message;
        } catch {
          stop(
            new GitExecutionError('SPAWN_FAILED', 'Invalid Git host protocol.'),
          );
          return;
        }
        if (message === null || typeof message !== 'object') {
          stop(
            new GitExecutionError(
              'SPAWN_FAILED',
              'Invalid Git host protocol value.',
            ),
          );
          return;
        }
        if (message.type === 'ready' && !ready && message.pid === groupId) {
          ready = true;
          if (!stopping && signalGroup(0)) input.write('\n');
          else if (!stopping)
            stop(
              new GitExecutionError(
                'CLEANUP_FAILED',
                'Cannot authorize anchored Git group startup.',
              ),
            );
        } else if (
          message.type === 'exit' &&
          ready &&
          !gitExit &&
          (message.code === null ||
            (Number.isInteger(message.code) &&
              Number(message.code) >= 0 &&
              Number(message.code) <= 255)) &&
          (message.signal === null || typeof message.signal === 'string')
        ) {
          gitExit = {
            code: message.code as number | null,
            signal: message.signal,
          };
          if (gitExit.signal !== null || gitExit.code === null)
            stop(
              new GitExecutionError(
                'SIGNAL_EXIT',
                'Git command terminated by signal.',
              ),
            );
          else drainComplete();
        } else if (message.type === 'spawn-error') {
          stop(
            new GitExecutionError(
              'SPAWN_FAILED',
              'Git process could not be started.',
            ),
          );
        } else {
          stop(
            new GitExecutionError(
              'SPAWN_FAILED',
              'Invalid Git host protocol state.',
            ),
          );
          return;
        }
      }
    });

    const abort = () =>
      stop(new GitExecutionError('CANCELLED', 'Git command cancelled.'));
    const deadlineTimer = setTimeout(
      () =>
        stop(
          new GitExecutionError('DEADLINE', 'Git operation deadline exceeded.'),
        ),
      remaining,
    );
    options.signal?.addEventListener('abort', abort, { once: true });
    if (options.signal?.aborted) abort();
    host.on('error', () =>
      stop(
        new GitExecutionError(
          'SPAWN_FAILED',
          'Git process host could not be started.',
        ),
      ),
    );
    host.on('exit', () => {
      anchorExited = true;
      clearTimeout(escalation);
      if (!killed)
        cleanupFailure = new GitExecutionError(
          'CLEANUP_FAILED',
          'Git group anchor exited before supervised termination.',
        );
      boundDrain();
    });
    host.on('close', () => {
      closed = true;
      finish();
    });
  });
}
