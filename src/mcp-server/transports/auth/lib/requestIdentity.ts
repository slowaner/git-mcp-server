/**
 * @fileoverview Verified request identity and explicit local-host session policy.
 * @module src/mcp-server/transports/auth/lib/requestIdentity
 */
import { randomUUID } from 'node:crypto';
import { config } from '@/config/index.js';
import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import { authContext } from './authContext.js';
import type { VerifiedPrincipal } from './verifiedPrincipal.js';

/** Local STDIO/anonymous identity is server-owned, never a client claim. */
export const hostPrincipal: VerifiedPrincipal = Object.freeze({
  issuer: 'urn:git-mcp:host',
  tenantId: 'default-tenant',
  clientId: 'host',
  subject: 'host-authorized',
});
const localSession = randomUUID();

/** HTTP auth is mandatory when configured; STDIO needs an explicit host scope. */
export function authenticationRequired(): boolean {
  return (
    config.mcpAuthMode !== 'none' &&
    authContext.getStore()?.transport !== 'stdio'
  );
}

/** Use only the current verified store; never recover identity from caller context. */
export function currentPrincipal(): VerifiedPrincipal {
  const principal = authContext.getStore()?.principal;
  if (principal) return principal;
  if (authenticationRequired()) {
    throw new McpError(
      JsonRpcErrorCode.Unauthorized,
      'Verified authentication context is required.',
    );
  }
  return hostPrincipal;
}

/** Require the already owner-authorized HTTP session, or a local STDIO session. */
export function currentServerSessionId(): string {
  const store = authContext.getStore();
  if (store?.sessionId) return store.sessionId;
  if (
    authenticationRequired() ||
    store?.transport === 'http' ||
    config.mcpTransportType === 'http'
  ) {
    throw new McpError(
      JsonRpcErrorCode.Unauthorized,
      'An owner-authorized server session is required.',
    );
  }
  return localSession;
}

/** Server-issued root restriction; missing enabled-auth ACL never means global access. */
export function currentRepositoryRoots(): readonly string[] | undefined {
  const store = authContext.getStore();
  if (
    authenticationRequired() &&
    (!store?.principal || store.repositoryRoots === undefined)
  ) {
    throw new McpError(
      JsonRpcErrorCode.Forbidden,
      'Verified repository access is required.',
    );
  }
  return store?.repositoryRoots;
}
