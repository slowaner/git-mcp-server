/**
 * @fileoverview Explicit JWT verification policy without environment-dependent bypass.
 * @module src/mcp-server/transports/auth/lib/jwtTokenPolicy
 */
import { jwtVerify, type JWTPayload } from 'jose';

import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import {
  principalFromVerifiedClaims,
  type VerifiedPrincipal,
} from './verifiedPrincipal.js';

/** JWT-only settings; issuer, audience and key are always required. */
export interface JwtTokenPolicyOptions {
  secret: string;
  issuer: string;
  audience: string;
  maxLifetimeSeconds: number;
  clockToleranceSeconds: number;
}

/** Verified authorization data, independent of access-token bytes. */
export interface VerifiedTokenIdentity {
  readonly principal: VerifiedPrincipal;
  readonly scopes: readonly string[];
  readonly expiresAt: number;
}

/** Strict HS256 verification with required expiration and bounded issued lifetime. */
export class JwtTokenPolicy {
  private readonly key: Uint8Array;
  private readonly options: Readonly<JwtTokenPolicyOptions>;

  constructor(options: JwtTokenPolicyOptions) {
    const key = new TextEncoder().encode(options.secret);
    if (
      typeof options.secret !== 'string' ||
      options.secret.trim() !== options.secret ||
      key.length < 32 ||
      key.length > 4096 ||
      typeof options.issuer !== 'string' ||
      !options.issuer.trim() ||
      options.issuer.trim() !== options.issuer ||
      typeof options.audience !== 'string' ||
      !options.audience.trim() ||
      options.audience.trim() !== options.audience ||
      !Number.isSafeInteger(options.maxLifetimeSeconds) ||
      options.maxLifetimeSeconds < 1 ||
      options.maxLifetimeSeconds > 86400 ||
      !Number.isSafeInteger(options.clockToleranceSeconds) ||
      options.clockToleranceSeconds < 0 ||
      options.clockToleranceSeconds > 60
    ) {
      throw new McpError(
        JsonRpcErrorCode.ConfigurationError,
        'JWT requires a 32-byte minimum secret, issuer, audience and bounded lifetime/clock tolerance.',
      );
    }
    this.key = key;
    this.options = Object.freeze({ ...options });
  }

  /** Verify signature/claims, then extract the stable principal and explicit scopes. */
  async verify(token: string): Promise<VerifiedTokenIdentity> {
    if (
      typeof token !== 'string' ||
      token.length === 0 ||
      token.length > 16384
    ) {
      throw new McpError(
        JsonRpcErrorCode.Unauthorized,
        'Token size is invalid.',
      );
    }
    const { payload } = await jwtVerify(token, this.key, {
      issuer: this.options.issuer,
      audience: this.options.audience,
      algorithms: ['HS256'],
      requiredClaims: ['exp', 'iat', 'sub', 'tid'],
      maxTokenAge: this.options.maxLifetimeSeconds,
      clockTolerance: this.options.clockToleranceSeconds,
    });
    return identityFromVerifiedPayload(
      payload,
      this.options.maxLifetimeSeconds,
    );
  }
}

/** Apply the same stable principal, scope and issued-lifetime rules after signature verification. */
export function identityFromVerifiedPayload(
  payload: JWTPayload,
  maxLifetimeSeconds: number,
): VerifiedTokenIdentity {
  if (
    !Number.isSafeInteger(payload.iat) ||
    !Number.isSafeInteger(payload.exp) ||
    payload.exp! <= payload.iat! ||
    payload.exp! - payload.iat! > maxLifetimeSeconds
  ) {
    throw new McpError(
      JsonRpcErrorCode.Unauthorized,
      'Token lifetime is invalid.',
    );
  }
  const principal = principalFromVerifiedClaims(payload);
  const scopes: unknown =
    payload.scp ??
    (typeof payload.scope === 'string'
      ? payload.scope.split(' ').filter(Boolean)
      : undefined);
  if (
    !Array.isArray(scopes) ||
    scopes.length === 0 ||
    scopes.length > 64 ||
    !scopes.every(
      (scope): scope is string =>
        typeof scope === 'string' && /^[\x21-\x7e]{1,128}$/u.test(scope),
    )
  ) {
    throw new McpError(
      JsonRpcErrorCode.Unauthorized,
      'Token scopes are missing or invalid.',
    );
  }
  return Object.freeze({
    principal,
    scopes: Object.freeze([...new Set(scopes)]),
    expiresAt: payload.exp!,
  });
}
