/**
 * @fileoverview Tenant/key isolation across local storage providers.
 * @module tests/security/storage-namespaces
 */
import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { config } from '@/config/index.js';
import { StorageService } from '@/storage/core/StorageService.js';
import { InMemoryProvider } from '@/storage/providers/inMemory/inMemoryProvider.js';
import { FileSystemProvider } from '@/storage/providers/fileSystem/fileSystemProvider.js';

describe('storage namespace contracts', () => {
  const saved = { ...config };
  const directories: string[] = [];
  afterEach(() => {
    Object.assign(config, saved);
    for (const dir of directories.splice(0))
      rmSync(dir, { recursive: true, force: true });
  });
  for (const kind of ['memory', 'filesystem'] as const)
    it(`${kind} isolates delimiter, slash, case and Unicode tuples through read/list/clear`, async () => {
      config.mcpAuthMode = 'none';
      config.mcpTransportType = 'stdio';
      const dir = mkdtempSync(join(tmpdir(), 'codec-providers-'));
      directories.push(dir);
      const backend =
        kind === 'memory'
          ? new InMemoryProvider()
          : new FileSystemProvider(join(dir, 'store'));
      const service = new StorageService(backend);
      const tuples = [
        ['a:b', 'c'],
        ['a', 'b:c'],
        ['Tenant', 'k'],
        ['tenant', 'k'],
        ['é', 'k'],
        ['e\u0301', 'k'],
        ['tenant/../other', 'k'],
      ];
      const context = (tenantId: string) => ({
        requestId: 'codec-provider-fixture',
        timestamp: '2026-11-03T00:00:00Z',
        tenantId,
      });
      for (const [index, [tenant, key]] of tuples.entries())
        await service.set(key!, { index }, context(tenant!));
      for (const [index, [tenant, key]] of tuples.entries()) {
        expect(await service.get(key!, context(tenant!))).toEqual({ index });
        expect((await service.list('', context(tenant!))).keys).toEqual([key!]);
      }
      expect(await service.clear(context('a:b'))).toBe(1);
      expect(await service.get('b:c', context('a'))).toEqual({ index: 1 });
      expect(await service.get('c', context('a:b'))).toBeNull();
    });
});
