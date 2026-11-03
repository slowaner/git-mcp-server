/**
 * @fileoverview Stable, payload-free failures from Git execution controls.
 * @module services/git/providers/cli/utils/execution-errors
 */

import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';

/** Machine-readable failure reasons; output and command arguments are excluded. */
export type GitExecutionFailure =
  | 'POLICY_UNSUPPORTED'
  | 'INVALID_EXECUTION_OPTIONS'
  | 'OUTPUT_LIMIT'
  | 'INVALID_OUTPUT_ENCODING'
  | 'CANCELLED'
  | 'DEADLINE'
  | 'SIGNAL_EXIT'
  | 'DESCENDANTS'
  | 'CLEANUP_FAILED'
  | 'SPAWN_FAILED';

/** An execution-control failure that must never be accepted as a soft Git exit. */
export class GitExecutionError extends McpError {
  constructor(
    public readonly reason: GitExecutionFailure,
    message: string,
  ) {
    super(
      reason === 'DEADLINE' || reason === 'CANCELLED'
        ? JsonRpcErrorCode.Timeout
        : reason === 'POLICY_UNSUPPORTED' || reason === 'SPAWN_FAILED'
          ? JsonRpcErrorCode.ServiceUnavailable
          : reason === 'INVALID_EXECUTION_OPTIONS'
            ? JsonRpcErrorCode.ConfigurationError
            : reason === 'OUTPUT_LIMIT' || reason === 'INVALID_OUTPUT_ENCODING'
              ? JsonRpcErrorCode.InvalidRequest
              : JsonRpcErrorCode.InternalError,
      message,
      { reason },
    );
    Object.setPrototypeOf(this, GitExecutionError.prototype);
    this.name = 'GitExecutionError';
  }
}
