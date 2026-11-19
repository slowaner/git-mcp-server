/**
 * @fileoverview Explicit principal-to-repository grants, independent of global roots.
 * @module src/mcp-server/transports/auth/lib/principalRepositoryGrants
 */
import path from 'node:path';

import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import {
  principalFingerprint,
  principalFromVerifiedClaims,
  type VerifiedPrincipal,
} from './verifiedPrincipal.js';

/** Operator-authored grant. Roots remain subject to G1's canonical ceiling. */
export interface PrincipalRepositoryGrant extends VerifiedPrincipal {
  readonly roots: readonly string[];
}

function invalidGrants(): never {
  throw new McpError(
    JsonRpcErrorCode.ConfigurationError,
    'MCP_REPOSITORY_GRANTS must contain explicit principal identities and absolute repository roots.',
  );
}

/**
 * Parse operator configuration once at startup. This is not a tool input schema.
 * Matching is exact across issuer, tenant, client and subject; no wildcards or
 * default grant. G1 must validate each selected root against canonical operator
 * roots before creating a repository capability, including in trusted Git mode.
 */
export class PrincipalRepositoryGrants {
  private readonly grants = new Map<string, readonly string[]>();

  constructor(input: unknown) {
    if (!Array.isArray(input) || input.length === 0 || input.length > 1024) {
      return invalidGrants();
    }
    for (const entry of input) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry))
        return invalidGrants();
      const value = entry as Record<string, unknown>;
      if (
        Object.keys(value).some(
          (key) =>
            !['issuer', 'tenantId', 'clientId', 'subject', 'roots'].includes(
              key,
            ),
        )
      ) {
        return invalidGrants();
      }
      const principal = principalFromVerifiedClaims({
        iss: value.issuer,
        tid: value.tenantId,
        cid: value.clientId,
        sub: value.subject,
      });
      if (
        !Array.isArray(value.roots) ||
        value.roots.length === 0 ||
        value.roots.length > 64
      )
        return invalidGrants();
      const roots: string[] = [];
      for (const root of value.roots) {
        if (
          typeof root !== 'string' ||
          !path.isAbsolute(root) ||
          root.includes('\0') ||
          root.length > 4096
        ) {
          return invalidGrants();
        }
        roots.push(root);
      }
      const key = principalFingerprint(principal);
      if (this.grants.has(key)) return invalidGrants();
      this.grants.set(key, Object.freeze([...new Set(roots)]));
    }
  }

  /** Select a fresh immutable root restriction for a verified server-side owner. */
  rootsFor(principal: VerifiedPrincipal): readonly string[] {
    const roots = this.grants.get(principalFingerprint(principal));
    if (!roots) {
      throw new McpError(
        JsonRpcErrorCode.Forbidden,
        'No repository access is configured for this principal.',
      );
    }
    return roots;
  }

  /** Validate every configured grant against the canonical operator ceiling at startup. */
  validateRoots(validate: (roots: readonly string[]) => void): void {
    for (const roots of this.grants.values()) validate(roots);
  }
}
