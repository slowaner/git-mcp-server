/**
 * @fileoverview Real StorageService interleaving and legacy-state isolation tests.
 * @module tests/storage/sessionWorkingDirectoryStore.test
 */
import path from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  principalFromVerifiedClaims,
  sessionWorkingDirectoryKey,
} from '@/mcp-server/transports/auth/lib/verifiedPrincipal.js';
import { StorageService } from '@/storage/core/StorageService.js';
import { SessionWorkingDirectoryStore } from '@/storage/core/sessionWorkingDirectoryStore.js';
import { InMemoryProvider } from '@/storage/providers/inMemory/inMemoryProvider.js';
import type { RequestContext } from '@/utils/index.js';

const owner = principalFromVerifiedClaims({
  iss: 'https://issuer.example.test',
  tid: 'tenant',
  cid: 'client',
  sub: 'subject-a',
});
const sessionA = '11111111-1111-4111-8111-111111111111';
const sessionB = '22222222-2222-4222-8222-222222222222';
const context: RequestContext = {
  requestId: 'state-test',
  timestamp: new Date(0).toISOString(),
  tenantId: 'caller-override',
};
const repoA = path.resolve('/repositories/a');
const repoB = path.resolve('/repositories/b');

describe('session working-directory store', () => {
  it('keeps target paths independent while same-owner sessions interleave set and clear', async () => {
    const storage = new StorageService(new InMemoryProvider());
    const a = new SessionWorkingDirectoryStore(
      storage,
      owner,
      sessionA,
      context,
    );
    const b = new SessionWorkingDirectoryStore(
      storage,
      owner,
      sessionB,
      context,
    );
    await a.set(repoA);
    await b.set(repoB);
    expect(await a.get()).toBe(repoA);
    expect(await b.get()).toBe(repoB);
    await a.set(path.join(repoA, 'nested'));
    expect(await b.get()).toBe(repoB);
    expect(await a.clear()).toBe(true);
    expect(await a.get()).toBeNull();
    expect(await b.get()).toBe(repoB);
    expect(await a.clear()).toBe(false);
  });

  it('separates same-client different-subject owners even for an equal session id', async () => {
    const storage = new StorageService(new InMemoryProvider());
    const other = { ...owner, subject: 'subject-b' };
    const a = new SessionWorkingDirectoryStore(
      storage,
      owner,
      sessionA,
      context,
    );
    const b = new SessionWorkingDirectoryStore(
      storage,
      other,
      sessionA,
      context,
    );
    await a.set(repoA);
    expect(await b.get()).toBeNull();
    await b.set(repoB);
    await a.clear();
    expect(await b.get()).toBe(repoB);
  });

  it('uses verified tenant instead of caller context and never reads the legacy cwd key', async () => {
    const storage = new StorageService(new InMemoryProvider());
    const tenantContext = { ...context, tenantId: owner.tenantId };
    await storage.set(
      `session:workingDir:${owner.tenantId}`,
      repoB,
      tenantContext,
    );
    const state = new SessionWorkingDirectoryStore(
      storage,
      owner,
      sessionA,
      context,
    );
    expect(await state.get()).toBeNull();
    await state.set(repoA);
    const key = sessionWorkingDirectoryKey(owner, sessionA);
    expect(await storage.get(key, context)).toBeNull();
    expect(await storage.get(key, tenantContext)).toBe(repoA);
    expect(
      await storage.get(`session:workingDir:${owner.tenantId}`, tenantContext),
    ).toBe(repoB);
  });

  it('keeps refreshed owner reconnect state and starts a new server session without cwd', async () => {
    const storage = new StorageService(new InMemoryProvider());
    await new SessionWorkingDirectoryStore(
      storage,
      owner,
      sessionA,
      context,
    ).set(repoA);
    const refreshed = principalFromVerifiedClaims({
      iss: owner.issuer,
      tid: owner.tenantId,
      cid: owner.clientId,
      sub: owner.subject,
      jti: 'new-token',
    });
    expect(
      await new SessionWorkingDirectoryStore(
        storage,
        refreshed,
        sessionA,
        context,
      ).get(),
    ).toBe(repoA);
    expect(
      await new SessionWorkingDirectoryStore(
        storage,
        refreshed,
        sessionB,
        context,
      ).get(),
    ).toBeNull();
  });

  it('rejects missing tenant/session and malformed stored state without fallback', async () => {
    const storage = new StorageService(new InMemoryProvider());
    expect(
      () =>
        new SessionWorkingDirectoryStore(
          storage,
          { ...owner, tenantId: '' },
          sessionA,
          context,
        ),
    ).toThrow();
    expect(
      () =>
        new SessionWorkingDirectoryStore(
          storage,
          owner,
          'caller-selected',
          context,
        ),
    ).toThrow();
    const state = new SessionWorkingDirectoryStore(
      storage,
      owner,
      sessionA,
      context,
    );
    expect(() => state.set('relative')).toThrow();
    await storage.set(
      sessionWorkingDirectoryKey(owner, sessionA),
      { path: repoA },
      { ...context, tenantId: owner.tenantId },
    );
    await expect(state.get()).rejects.toThrow(
      'Stored working directory is invalid',
    );
  });
});
