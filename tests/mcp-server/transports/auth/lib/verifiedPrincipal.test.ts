/**
 * @fileoverview Stable owner and independent session-state identity tests.
 * @module tests/mcp-server/transports/auth/lib/verifiedPrincipal.test
 */
import { describe, expect, it } from 'vitest';

import {
  principalFingerprint,
  principalFromVerifiedClaims,
  samePrincipal,
  sessionWorkingDirectoryKey,
} from '@/mcp-server/transports/auth/lib/verifiedPrincipal.js';
import { encodeStorageKey } from '@/storage/core/storageKeyCodec.js';

const claims = {
  iss: 'https://issuer.example.test',
  tid: 'tenant',
  cid: 'client',
  sub: 'subject',
};
const sessionA = '11111111-1111-4111-8111-111111111111';
const sessionB = '22222222-2222-4222-8222-222222222222';

describe('verified principal', () => {
  it('keeps refresh/reconnect ownership stable while changing token and scopes', () => {
    const first = principalFromVerifiedClaims({
      ...claims,
      scope: 'read',
      jti: 'old',
    });
    const refreshed = principalFromVerifiedClaims({
      ...claims,
      scope: 'read write',
      jti: 'new',
    });
    expect(samePrincipal(first, refreshed)).toBe(true);
    expect(principalFingerprint(first)).toBe(principalFingerprint(refreshed));
    expect(sessionWorkingDirectoryKey(first, sessionA)).toBe(
      sessionWorkingDirectoryKey(refreshed, sessionA),
    );
  });

  it.each(['iss', 'tid', 'cid', 'sub'] as const)(
    'separates different %s even with equal scopes and session ids',
    (claim) => {
      const first = principalFromVerifiedClaims(claims);
      const other = principalFromVerifiedClaims({
        ...claims,
        [claim]: `${claims[claim]}-other`,
      });
      expect(samePrincipal(first, other)).toBe(false);
      expect(principalFingerprint(first)).not.toBe(principalFingerprint(other));
      expect(sessionWorkingDirectoryKey(first, sessionA)).not.toBe(
        sessionWorkingDirectoryKey(other, sessionA),
      );
    },
  );

  it('separates two same-principal sessions and fits shared storage codec', () => {
    const principal = principalFromVerifiedClaims(claims);
    const keyA = sessionWorkingDirectoryKey(principal, sessionA);
    const keyB = sessionWorkingDirectoryKey(principal, sessionB);
    expect(keyA).not.toBe(keyB);
    expect(encodeStorageKey(principal.tenantId, keyA).length).toBeLessThan(512);
    expect(keyA).not.toBe(`session:workingDir:${principal.tenantId}`);
  });

  it('frames principal fields without delimiter collisions', () => {
    const a = principalFromVerifiedClaims({ ...claims, tid: 'a:b', cid: 'c' });
    const b = principalFromVerifiedClaims({ ...claims, tid: 'a', cid: 'b:c' });
    expect(principalFingerprint(a)).not.toBe(principalFingerprint(b));
  });

  it.each(['', 'caller-selected', '11111111-1111-1111-1111-111111111111'])(
    'rejects invalid session identifiers %j',
    (session) => {
      expect(() =>
        sessionWorkingDirectoryKey(
          principalFromVerifiedClaims(claims),
          session,
        ),
      ).toThrow();
    },
  );
});
