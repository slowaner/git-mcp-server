/**
 * @fileoverview Actual JOSE/OAuth strategy verification with a controlled JWKS boundary.
 * @module tests/security/oauth-verification
 */
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { config } from '@/config/index.js';
import { logger } from '@/utils/index.js';
import { OauthStrategy } from '@/mcp-server/transports/auth/strategies/oauthStrategy.js';

describe('actual OAuth verification policy', () => {
  const issuer = 'https://oauth-fixture.example.test';
  const audience = 'git-oauth-fixture';
  let pair: Awaited<ReturnType<typeof generateKeyPair>>;
  let strategy: OauthStrategy;
  let fetchSpy: ReturnType<typeof vi.spyOn>;
  const options = {
    ...config,
    mcpAuthMode: 'oauth' as const,
    mcpTransportType: 'http' as const,
    oauthIssuerUrl: issuer,
    oauthJwksUri: `${issuer}/keys`,
    oauthAudience: audience,
    mcpAuthMaxTokenLifetimeSeconds: 300,
    mcpAuthClockToleranceSeconds: 0,
    mcpRepositoryGrants: JSON.stringify([
      {
        issuer,
        tenantId: 'tenant',
        clientId: 'client',
        subject: 'subject',
        roots: ['/operator/root'],
      },
    ]),
  };
  async function signed(
    overrides: Record<string, unknown> = {},
    key = pair.privateKey,
  ) {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
      iss: issuer,
      aud: audience,
      sub: 'subject',
      tid: 'tenant',
      client_id: 'client',
      scope: 'tool:git:read',
      iat: now,
      exp: now + 120,
      ...overrides,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'fixture' })
      .sign(key);
  }
  beforeAll(async () => {
    pair = await generateKeyPair('RS256');
    const jwk = {
      ...(await exportJWK(pair.publicKey)),
      kid: 'fixture',
      alg: 'RS256',
      use: 'sig',
    };
    fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) => {
        expect(String(input)).toBe(`${issuer}/keys`);
        return Response.json({ keys: [jwk] });
      });
    strategy = new OauthStrategy(options, logger);
  });
  afterAll(() => fetchSpy?.mockRestore());
  it('verifies intended issuer/audience/key and stable principal using actual remote-key resolver', async () => {
    const result = await strategy.verify(await signed());
    expect(result.principal).toEqual({
      issuer,
      tenantId: 'tenant',
      clientId: 'client',
      subject: 'subject',
    });
    expect(result.scopes).toEqual(['tool:git:read']);
    expect(result.expiresAt).toBeGreaterThan(Date.now() / 1000);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
  for (const [name, overrides] of Object.entries({
    missingTenant: { tid: undefined },
    missingSubject: { sub: undefined },
    missingClient: { client_id: undefined },
    wrongAudience: { aud: 'wrong' },
    wrongIssuer: { iss: 'https://foreign.example.test' },
    missingExpiry: { exp: undefined },
    missingIat: { iat: undefined },
    overlong: { exp: Math.floor(Date.now() / 1000) + 301 },
    expired: { exp: Math.floor(Date.now() / 1000) - 10 },
    future: { iat: Math.floor(Date.now() / 1000) + 30 },
    ambiguousClient: { cid: 'foreign' },
    emptyScope: { scope: '' },
    badTenant: { tid: '' },
    nonintegerExpiry: { exp: Date.now() / 1000 + 120 },
  }))
    it(`rejects ${name}`, async () => {
      await expect(strategy.verify(await signed(overrides))).rejects.toThrow();
    });
  it('rejects a wrong RSA key and symmetric-algorithm substitution', async () => {
    const foreign = await generateKeyPair('RS256');
    await expect(
      strategy.verify(await signed({}, foreign.privateKey)),
    ).rejects.toThrow();
    const symmetric = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .sign(new TextEncoder().encode('synthetic-symmetric-fixture-'.repeat(3)));
    await expect(strategy.verify(symmetric)).rejects.toThrow();
  });
});
