/**
 * @fileoverview Stable identity and session-state keys derived from verified claims.
 * @module src/mcp-server/transports/auth/lib/verifiedPrincipal
 */
import { createHash } from 'node:crypto';

import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';

/** Stable token owner. Refreshing token bytes or scopes does not change ownership. */
export interface VerifiedPrincipal {
  readonly issuer: string;
  readonly tenantId: string;
  readonly clientId: string;
  readonly subject: string;
}

function identityClaim(value: unknown, maxBytes: number): string {
  if (
    typeof value !== 'string' ||
    !value ||
    value.trim() !== value ||
    new TextEncoder().encode(value).length > maxBytes ||
    /[\u0000-\u001f\u007f-\u009f]/u.test(value)
  ) {
    throw new McpError(
      JsonRpcErrorCode.Unauthorized,
      'Token identity is missing or invalid.',
    );
  }
  for (const character of value) {
    const point = character.codePointAt(0)!;
    if (point >= 0xd800 && point <= 0xdfff) {
      throw new McpError(
        JsonRpcErrorCode.Unauthorized,
        'Token identity is missing or invalid.',
      );
    }
  }
  return value;
}

/**
 * Extract an immutable principal after cryptographic and issuer/audience checks.
 * Missing tenant/subject is rejected; no default tenant or client-only identity.
 */
export function principalFromVerifiedClaims(
  claims: Record<string, unknown>,
): VerifiedPrincipal {
  if (
    claims.cid !== undefined &&
    claims.client_id !== undefined &&
    claims.cid !== claims.client_id
  ) {
    throw new McpError(
      JsonRpcErrorCode.Unauthorized,
      'Token client claims disagree.',
    );
  }
  return Object.freeze({
    issuer: identityClaim(claims.iss, 2048),
    tenantId: identityClaim(claims.tid, 120),
    clientId: identityClaim(claims.cid ?? claims.client_id, 256),
    subject: identityClaim(claims.sub, 256),
  });
}

/** Compare every owner dimension before touching transport or session state. */
export function samePrincipal(
  left: VerifiedPrincipal,
  right: VerifiedPrincipal,
): boolean {
  return (
    left.issuer === right.issuer &&
    left.tenantId === right.tenantId &&
    left.clientId === right.clientId &&
    left.subject === right.subject
  );
}

/** Stable opaque identity for storage/admission; never use access-token bytes. */
export function principalFingerprint(principal: VerifiedPrincipal): string {
  return createHash('sha256')
    .update(
      JSON.stringify([
        principal.issuer,
        principal.tenantId,
        principal.clientId,
        principal.subject,
      ]),
    )
    .digest('hex');
}

/**
 * State key for one server-created session and verified owner. Call only after
 * owner validation; a caller-supplied header is not evidence of session creation.
 * Legacy tenant-wide working-directory keys are intentionally discarded.
 */
export function sessionWorkingDirectoryKey(
  principal: VerifiedPrincipal,
  serverSessionId: string,
): string {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      serverSessionId,
    )
  ) {
    throw new McpError(
      JsonRpcErrorCode.Unauthorized,
      'A server-generated session is required.',
    );
  }
  const digest = createHash('sha256')
    .update(JSON.stringify([principalFingerprint(principal), serverSessionId]))
    .digest('hex');
  return `cwd:v2:${digest}`;
}
