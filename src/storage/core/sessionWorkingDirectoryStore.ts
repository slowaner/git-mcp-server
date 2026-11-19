/**
 * @fileoverview Session-scoped working-directory state without legacy tenant fallback.
 * @module src/storage/core/sessionWorkingDirectoryStore
 */
import path from 'node:path';

import { authContext } from '@/mcp-server/transports/auth/lib/authContext.js';

import {
  principalFromVerifiedClaims,
  sessionWorkingDirectoryKey,
  type VerifiedPrincipal,
} from '@/mcp-server/transports/auth/lib/verifiedPrincipal.js';
import type { StorageService } from '@/storage/core/StorageService.js';
import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import type { RequestContext } from '@/utils/index.js';
import {
  currentPrincipal,
  currentServerSessionId,
} from '@/mcp-server/transports/auth/lib/requestIdentity.js';

/** Serializes the working-directory mutations of a single HTTP session. */
export class SessionWorkingDirectoryWrites {
  private settled: Promise<unknown> = Promise.resolve();
  private closing = false;
  private unconfirmed: 'write' | 'clear' | undefined;

  constructor(private readonly timeoutMs: number) {}

  run(write: (signal: AbortSignal) => Promise<void>): Promise<void> {
    return this.enqueue('write', write);
  }

  clear<T>(
    remove: (signal: AbortSignal) => Promise<T>,
    requestSignal?: AbortSignal,
  ): Promise<T> {
    return this.enqueue('clear', remove, requestSignal);
  }

  private enqueue<T>(
    operation: 'write' | 'clear',
    mutate: (signal: AbortSignal) => Promise<T>,
    requestSignal?: AbortSignal,
  ): Promise<T> {
    const pending = this.settled.then(() => {
      requestSignal?.throwIfAborted();
      return this.execute(operation, mutate);
    });
    this.settled = pending.catch(() => {});
    return pending;
  }

  private async execute<T>(
    operation: 'write' | 'clear',
    mutate: (signal: AbortSignal) => Promise<T>,
  ): Promise<T> {
    if (this.closing) {
      throw new McpError(
        JsonRpcErrorCode.InvalidRequest,
        'The HTTP session is closing.',
      );
    }
    if (
      this.unconfirmed &&
      (operation === 'clear' || this.unconfirmed === 'clear')
    ) {
      throw new McpError(
        JsonRpcErrorCode.InvalidRequest,
        `The working-directory ${this.unconfirmed} outcome is unknown.`,
      );
    }

    const signal = AbortSignal.timeout(this.timeoutMs);
    let abort!: () => void;
    const deadline = new Promise<never>((_, reject) => {
      abort = () => {
        this.unconfirmed ??= operation;
        reject(
          new McpError(
            JsonRpcErrorCode.Timeout,
            `Working-directory ${operation} deadline exceeded.`,
          ),
        );
      };
      signal.addEventListener('abort', abort, { once: true });
    });
    try {
      return await Promise.race([mutate(signal), deadline]);
    } catch (error) {
      if (error instanceof McpError && error.data?.writeOutcome === 'unknown') {
        this.unconfirmed ??= operation;
      }
      throw error;
    } finally {
      signal.removeEventListener('abort', abort);
    }
  }

  /** Stop queued and new mutations, then report whether the key can be deleted. */
  async close(): Promise<boolean> {
    this.closing = true;
    await this.settled;
    return !this.unconfirmed;
  }
}

/** Construct state from current verified server authority, ignoring caller identity fields. */
export function workingDirectoryStore(
  storage: Pick<StorageService, 'get' | 'set' | 'delete'>,
  context: RequestContext,
): SessionWorkingDirectoryStore {
  const session = authContext.getStore();
  return new SessionWorkingDirectoryStore(
    session?.stdioWorkingDirectoryStorage ?? storage,
    currentPrincipal(),
    currentServerSessionId(),
    context,
    session?.cwdWrites,
  );
}

/**
 * Persist cwd only for an already owner-authorized server session. This class
 * provides state isolation, not repository authorization: callers must apply G1's
 * current canonical repository policy to every read and before every write.
 */
export class SessionWorkingDirectoryStore {
  private readonly key: string;
  private readonly context: RequestContext;

  constructor(
    private readonly storage: Pick<StorageService, 'get' | 'set' | 'delete'>,
    principal: VerifiedPrincipal,
    serverSessionId: string,
    context: RequestContext,
    private readonly writes?: SessionWorkingDirectoryWrites,
  ) {
    // Defensive validation prevents malformed internal identity from reaching
    // StorageService's legacy default-tenant behavior during migration.
    const owner = principalFromVerifiedClaims({
      iss: principal.issuer,
      tid: principal.tenantId,
      cid: principal.clientId,
      sub: principal.subject,
    });
    this.key = sessionWorkingDirectoryKey(owner, serverSessionId);
    this.context = Object.freeze({
      ...context,
      tenantId: owner.tenantId,
      principal: owner,
      sessionId: serverSessionId,
    });
  }

  /** Read this session's state; callers reauthorize the returned path each time. */
  async get(): Promise<string | null> {
    const value = await this.storage.get<unknown>(this.key, this.context);
    if (value === null) return null;
    if (
      typeof value !== 'string' ||
      !path.isAbsolute(value) ||
      value.includes('\0')
    ) {
      throw new McpError(
        JsonRpcErrorCode.ValidationError,
        'Stored working directory is invalid.',
      );
    }
    return value;
  }

  /** Store an already authorized absolute path, never a relative implicit cwd. */
  set(authorizedPath: string): Promise<void> {
    if (!path.isAbsolute(authorizedPath) || authorizedPath.includes('\0')) {
      throw new McpError(
        JsonRpcErrorCode.ValidationError,
        'Working directory must be an authorized absolute path.',
      );
    }
    if (this.writes) {
      return this.writes.run((signal) =>
        this.storage.set(this.key, authorizedPath, this.context, { signal }),
      );
    }
    return this.storage.set(this.key, authorizedPath, this.context);
  }

  /** Clear only this owner/session state. */
  clear(signal?: AbortSignal): Promise<boolean> {
    if (this.writes) {
      return this.writes.clear((deadline) =>
        this.storage.delete(
          this.key,
          this.context,
          signal ? AbortSignal.any([signal, deadline]) : deadline,
        ),
      );
    }
    return this.storage.delete(this.key, this.context, signal);
  }

  /** Reauthorize the previous path and delete it in the same session turn. */
  clearWithPreviousPath(
    reauthorize: (stored: string) => Promise<string>,
    requestSignal?: AbortSignal,
  ): Promise<string | null> {
    const remove = async (deadline?: AbortSignal) => {
      if (!this.writes) requestSignal?.throwIfAborted();
      const stored = await this.get();
      const previousPath = stored === null ? null : await reauthorize(stored);
      requestSignal?.throwIfAborted();
      // Once dispatched, keep the delete under the queue's storage deadline.
      await this.storage.delete(this.key, this.context, deadline);
      return previousPath;
    };
    return this.writes ? this.writes.clear(remove, requestSignal) : remove();
  }
}
