/**
 * @fileoverview Enabled-auth fail-closed behavior and server-owned context authority.
 * @module tests/security/auth-authority
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { config } from '@/config/index.js';
import { authContext } from '@/mcp-server/transports/auth/lib/authContext.js';
import {
  hostPrincipal,
  currentPrincipal,
  currentRepositoryRoots,
  currentServerSessionId,
} from '@/mcp-server/transports/auth/lib/requestIdentity.js';
import { withRequiredScopes } from '@/mcp-server/transports/auth/lib/authUtils.js';
import {
  validateAuthenticationConfiguration,
  parseRepositoryGrants,
} from '@/mcp-server/transports/auth/lib/authConfiguration.js';
import { requestContextService } from '@/utils/internal/requestContext.js';
import { StorageService } from '@/storage/core/StorageService.js';
import { InMemoryProvider } from '@/storage/providers/inMemory/inMemoryProvider.js';
import { workingDirectoryStore } from '@/storage/core/sessionWorkingDirectoryStore.js';

describe('verified authority across auth, context and storage', () => {
  const original = { ...config };
  const principal = Object.freeze({
    issuer: 'https://issuer.example.test',
    tenantId: 'tenant-a',
    clientId: 'client-a',
    subject: 'alice',
  });
  const context = {
    requestId: 'authority-fixture',
    timestamp: '2026-11-03T00:00:00Z',
  };
  beforeEach(() =>
    Object.assign(config, { mcpAuthMode: 'jwt', mcpTransportType: 'http' }),
  );
  afterEach(() => Object.assign(config, original));
  it('rejects missing ALS and authInfo-only enabled-auth contexts before protected work', () => {
    for (const operation of [
      () => withRequiredScopes(['tool:git:read']),
      currentPrincipal,
      currentRepositoryRoots,
      currentServerSessionId,
    ]) {
      expect(operation).toThrow();
      authContext.run(
        {
          authInfo: {
            token: 'synthetic',
            clientId: 'a',
            tenantId: 'a',
            scopes: ['tool:git:read'],
          },
        },
        () => expect(operation).toThrow(),
      );
    }
  });
  it('verified tuple and server session overwrite direct, parent and additional identity metadata', () => {
    const sessionId = randomUUID();
    authContext.run(
      {
        principal,
        sessionId,
        repositoryRoots: ['/operator/grant'],
        transport: 'http',
      },
      () => {
        const result = requestContextService.createRequestContext({
          parentContext: {
            tenantId: 'foreign',
            principal: hostPrincipal,
            sessionId: 'foreign',
          },
          tenantId: 'foreign',
          additionalContext: {
            tenantId: 'foreign',
            principal: hostPrincipal,
            sessionId: 'foreign',
          },
        });
        expect(result.tenantId).toBe(principal.tenantId);
        expect(result.principal).toBe(principal);
        expect(result.sessionId).toBe(sessionId);
        expect(result.repositoryRoots).toEqual(['/operator/grant']);
      },
    );
  });
  it('storage rejects forged or absent tenant authority before invoking backend', async () => {
    const backend = new InMemoryProvider();
    const service = new StorageService(backend);
    const get = vi.spyOn(backend, 'get');
    expect(() => service.get('key', context)).toThrow();
    await authContext.run({ principal, transport: 'http' }, async () => {
      expect(() =>
        service.get('key', { ...context, tenantId: 'foreign' }),
      ).toThrow();
      expect(get).not.toHaveBeenCalled();
      await expect(service.get('key', context)).resolves.toBeNull();
      expect(get.mock.calls[0]?.[0]).toBe(principal.tenantId);
    });
  });
  it('rejects invalid bulk keys before any partial write and deliberately ignores tenant-wide cwd', async () => {
    config.mcpAuthMode = 'none';
    config.mcpTransportType = 'stdio';
    const service = new StorageService(new InMemoryProvider());
    expect(() =>
      service.setMany(
        new Map([
          ['valid', 1],
          ['', 2],
        ]),
        context,
      ),
    ).toThrow();
    expect(await service.get('valid', context)).toBeNull();
    await service.set('session:workingDir:default-tenant', '/legacy', context);
    expect(await workingDirectoryStore(service, context).get()).toBeNull();
  });
  it('explicit STDIO host policy works with enabled HTTP auth configuration', () => {
    authContext.run(
      { principal: hostPrincipal, transport: 'stdio', sessionId: randomUUID() },
      () => {
        expect(() => withRequiredScopes(['tool:git:write'])).not.toThrow();
        expect(currentPrincipal()).toBe(hostPrincipal);
        expect(currentServerSessionId()).toMatch(/^[0-9a-f-]{36}$/);
      },
    );
  });
});

describe('environment-independent authentication configuration', () => {
  const valid = {
    ...config,
    mcpAuthMode: 'jwt' as const,
    mcpTransportType: 'http' as const,
    mcpAuthSecretKey: 'synthetic-config-fixture-'.repeat(3),
    mcpAuthIssuer: 'https://issuer.example.test',
    mcpAuthAudience: 'git-fixture',
    mcpRepositoryGrants: JSON.stringify([
      {
        issuer: 'https://issuer.example.test',
        tenantId: 'tenant',
        clientId: 'client',
        subject: 'user',
        roots: ['/operator/root'],
      },
    ]),
  };
  for (const environment of ['development', 'test', 'production'])
    it(`requires verification settings in ${environment}`, () => {
      const saved = process.env.NODE_ENV;
      process.env.NODE_ENV = environment;
      try {
        expect(() => validateAuthenticationConfiguration(valid)).not.toThrow();
        for (const override of [
          { mcpAuthSecretKey: undefined },
          { mcpAuthSecretKey: 'short' },
          { mcpAuthIssuer: undefined },
          { mcpAuthAudience: undefined },
          { mcpRepositoryGrants: undefined },
          { devMcpClientId: 'bypass' },
          { devMcpScopes: ['tool:git:write'] },
        ])
          expect(() =>
            validateAuthenticationConfiguration({ ...valid, ...override }),
          ).toThrow();
      } finally {
        if (saved === undefined) delete process.env.NODE_ENV;
        else process.env.NODE_ENV = saved;
      }
    });
  it('requires HTTPS OAuth anchors, audience and explicit grants', () => {
    const oauth = {
      ...valid,
      mcpAuthMode: 'oauth' as const,
      oauthIssuerUrl: 'https://issuer.example.test',
      oauthAudience: 'git-fixture',
    };
    expect(() => validateAuthenticationConfiguration(oauth)).not.toThrow();
    for (const override of [
      { oauthIssuerUrl: 'http://issuer.example.test' },
      { oauthJwksUri: 'http://keys.example.test' },
      { oauthJwksUri: 'https://user:password@example.test' },
      { oauthAudience: undefined },
    ])
      expect(() =>
        validateAuthenticationConfiguration({ ...oauth, ...override }),
      ).toThrow();
    for (const value of [undefined, '', '{}', '[]', '[{}]'])
      expect(() => parseRepositoryGrants(value)).toThrow();
  });
});
