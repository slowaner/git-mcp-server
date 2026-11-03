/**
 * @fileoverview Session-scoped working-directory state without legacy tenant fallback.
 * @module src/storage/core/sessionWorkingDirectoryStore
 */
import path from 'node:path';

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

/** Construct state from current verified server authority, ignoring caller identity fields. */
export function workingDirectoryStore(
  storage: Pick<StorageService, 'get' | 'set' | 'delete'>,
  context: RequestContext,
): SessionWorkingDirectoryStore {
  return new SessionWorkingDirectoryStore(
    storage,
    currentPrincipal(),
    currentServerSessionId(),
    context,
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
    return this.storage.set(this.key, authorizedPath, this.context);
  }

  /** Clear only this owner/session state on explicit clear or session cleanup. */
  clear(): Promise<boolean> {
    return this.storage.delete(this.key, this.context);
  }
}
