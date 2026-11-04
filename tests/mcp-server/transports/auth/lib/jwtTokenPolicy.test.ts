/**
 * @fileoverview Cryptographic rejection matrix for the strict JWT policy.
 * @module tests/mcp-server/transports/auth/lib/jwtTokenPolicy.test
 */
import { SignJWT, type JWTPayload } from 'jose';
import { describe, expect, it } from 'vitest';

import {
  JwtTokenPolicy,
  type JwtTokenPolicyOptions,
} from '@/mcp-server/transports/auth/lib/jwtTokenPolicy.js';

// Synthetic fixture key, constructed solely for local signing and verification.
const secret = 'synthetic-test-key-'.repeat(4);
const options: JwtTokenPolicyOptions = {
  secret,
  issuer: 'https://issuer.example.test',
  audience: 'git-mcp-test',
  maxLifetimeSeconds: 3600,
  clockToleranceSeconds: 5,
};

function claims(
  overrides: JWTPayload | ((now: number) => JWTPayload) = {},
): JWTPayload {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: options.issuer,
    aud: options.audience,
    iat: now,
    exp: now + 300,
    sub: 'user-a',
    cid: 'client-a',
    tid: 'tenant-a',
    scope: 'tool:git:read',
    ...(typeof overrides === 'function' ? overrides(now) : overrides),
  };
}

async function sign(
  payload: JWTPayload,
  algorithm = 'HS256',
  key = secret,
): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: algorithm })
    .sign(new TextEncoder().encode(key));
}

const invalidLifetimes: ((now: number) => JWTPayload)[] = [
  (now) => ({ iat: now - 300, exp: now - 60 }),
  (now) => ({ iat: now + 60, exp: now + 300 }),
  (now) => ({ nbf: now + 60 }),
  (now) => ({ exp: now + 3601 }),
  (now) => ({ exp: now }),
  (now) => ({ iat: now - 4000, exp: now + 100 }),
  (now) => ({ exp: now + 100.5 }),
];

describe('strict JWT token policy', () => {
  it('accepts intended token and audience arrays with required principal', async () => {
    const policy = new JwtTokenPolicy(options);
    const result = await policy.verify(
      await sign(claims({ aud: ['other', options.audience] })),
    );
    expect(result.principal).toEqual({
      issuer: options.issuer,
      tenantId: 'tenant-a',
      clientId: 'client-a',
      subject: 'user-a',
    });
    expect(result.scopes).toEqual(['tool:git:read']);
    expect(Object.isFrozen(result.principal)).toBe(true);
    expect(Object.isFrozen(result.scopes)).toBe(true);
  });

  it('accepts client_id and array scopes without conflating different clients', async () => {
    const result = await new JwtTokenPolicy(options).verify(
      await sign(
        claims({
          cid: undefined,
          client_id: 'oauth-client',
          scp: ['tool:git:read', 'tool:git:write'],
        }),
      ),
    );
    expect(result.principal.clientId).toBe('oauth-client');
    expect(result.scopes).toEqual(['tool:git:read', 'tool:git:write']);
  });

  it.each([
    { aud: undefined },
    { aud: 'another-service' },
    { iss: undefined },
    { iss: 'https://foreign.example.test' },
    { exp: undefined },
    { iat: undefined },
    { tid: undefined },
    { sub: undefined },
    { cid: undefined },
    { tid: '' },
    { sub: ' ' },
    { cid: 123 },
    { cid: 'a', client_id: 'b' },
    { scope: '' },
    { scp: [123] },
    { scp: ['bad scope'] },
    { scp: ['x'.repeat(129)] },
    { scp: Array(65).fill('read') },
    { tid: 't'.repeat(121) },
    { sub: '\ud800' },
    { tid: 'tenant\n' },
  ])(
    'rejects missing/wrong authority or identity claims %j',
    async (overrides) => {
      await expect(
        new JwtTokenPolicy(options).verify(
          await sign(claims(overrides as JWTPayload)),
        ),
      ).rejects.toThrow();
    },
  );

  it.each(['HS384', 'HS512'])(
    'rejects %s despite a valid signature under the same key',
    async (algorithm) => {
      await expect(
        new JwtTokenPolicy(options).verify(await sign(claims(), algorithm)),
      ).rejects.toThrow();
    },
  );

  it('rejects wrong signing key and unsigned/malformed token', async () => {
    const policy = new JwtTokenPolicy(options);
    await expect(
      policy.verify(
        await sign(claims(), 'HS256', 'different-synthetic-key-'.repeat(4)),
      ),
    ).rejects.toThrow();
    await expect(policy.verify('eyJhbGciOiJub25lIn0.e30.')).rejects.toThrow();
    await expect(policy.verify('arbitrary-bearer')).rejects.toThrow();
    await expect(policy.verify('')).rejects.toThrow();
    await expect(policy.verify('a'.repeat(16385))).rejects.toThrow();
  });

  it('enforces expiration, issued lifetime and future issuance independently', async () => {
    const policy = new JwtTokenPolicy(options);
    for (const overrides of invalidLifetimes) {
      await expect(
        policy.verify(await sign(claims(overrides))),
      ).rejects.toThrow();
    }
    const boundary = claims((now) => ({ exp: now + 3600 }));
    expect((await policy.verify(await sign(boundary))).expiresAt).toBe(
      boundary.exp,
    );
    expect(
      (
        await policy.verify(
          await sign(claims((now) => ({ iat: now + 2, exp: now + 300 }))),
        )
      ).principal.subject,
    ).toBe('user-a');
  });

  it('keeps lifetime boundaries invalid after delayed fixture setup', async () => {
    const deferred = [invalidLifetimes[3]!, invalidLifetimes[1]!];
    await new Promise((resolve) => setTimeout(resolve, 1100));
    for (const [index, overrides] of deferred.entries()) {
      const payload = claims(overrides);
      expect(payload.exp! - payload.iat!).toBe(index === 0 ? 3601 : 240);
      await expect(
        new JwtTokenPolicy(options).verify(await sign(payload)),
      ).rejects.toThrow();
    }
  });

  it.each([
    { secret: '' },
    { secret: ' ' },
    { secret: 's'.repeat(31) },
    { secret: `${secret} ` },
    { issuer: '' },
    { audience: '' },
    { issuer: ' issuer ' },
    { maxLifetimeSeconds: 0 },
    { maxLifetimeSeconds: 86401 },
    { maxLifetimeSeconds: 1.5 },
    { clockToleranceSeconds: -1 },
    { clockToleranceSeconds: 61 },
  ])(
    'rejects invalid configuration without environment bypass %j',
    (override) => {
      expect(() => new JwtTokenPolicy({ ...options, ...override })).toThrow();
    },
  );
});
