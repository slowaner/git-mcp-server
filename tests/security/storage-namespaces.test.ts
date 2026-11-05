/**
 * @fileoverview Cross-provider tenant/key collision and hostile listing regressions.
 * @module tests/security/storage-namespaces
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { KVNamespace, R2Bucket } from '@cloudflare/workers-types';
import { config } from '@/config/index.js';
import { StorageService } from '@/storage/core/StorageService.js';
import { InMemoryProvider } from '@/storage/providers/inMemory/inMemoryProvider.js';
import { FileSystemProvider } from '@/storage/providers/fileSystem/fileSystemProvider.js';
import { KvProvider } from '@/storage/providers/cloudflare/kvProvider.js';
import { R2Provider } from '@/storage/providers/cloudflare/r2Provider.js';
import { encodeStorageKey } from '@/storage/core/storageKeyCodec.js';

function cloudStores() {
  const kvValues = new Map<string, string>();
  const r2Values = new Map<string, string>();
  const kv = {
    get: async (key: string, type?: string) => {
      const value = kvValues.get(key);
      return value === undefined
        ? null
        : type === 'json'
          ? JSON.parse(value)
          : value;
    },
    put: async (key: string, value: string) => {
      kvValues.set(key, value);
    },
    delete: async (key: string) => {
      kvValues.delete(key);
    },
    list: async ({ prefix }: { prefix: string }) => ({
      keys: [...kvValues.keys()]
        .filter((k) => k.startsWith(prefix))
        .map((name) => ({ name })),
      list_complete: true,
    }),
  };
  const bucket = {
    get: async (key: string) =>
      r2Values.has(key) ? { text: async () => r2Values.get(key)! } : null,
    put: async (key: string, value: string) => {
      r2Values.set(key, value);
    },
    head: async (key: string) => (r2Values.has(key) ? {} : null),
    delete: async (key: string) => {
      r2Values.delete(key);
    },
    list: async ({ prefix }: { prefix: string }) => ({
      objects: [...r2Values.keys()]
        .filter((k) => k.startsWith(prefix))
        .map((key) => ({ key })),
      truncated: false,
    }),
  };
  return { kv, bucket };
}

describe('storage namespace contracts', () => {
  const saved = { ...config };
  const directories: string[] = [];
  afterEach(() => {
    Object.assign(config, saved);
    for (const dir of directories.splice(0))
      rmSync(dir, { recursive: true, force: true });
  });
  for (const kind of ['memory', 'filesystem', 'kv', 'r2'] as const)
    it(`${kind} isolates delimiter, slash, case and Unicode tuples through read/list/clear`, async () => {
      config.mcpAuthMode = 'none';
      config.mcpTransportType = 'stdio';
      const dir = mkdtempSync(join(tmpdir(), 'codec-providers-'));
      directories.push(dir);
      const { kv, bucket } = cloudStores();
      const backend =
        kind === 'memory'
          ? new InMemoryProvider()
          : kind === 'filesystem'
            ? new FileSystemProvider(join(dir, 'store'))
            : kind === 'kv'
              ? new KvProvider(kv as unknown as KVNamespace)
              : new R2Provider(bucket as unknown as R2Bucket);
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
  for (const kind of ['kv', 'r2'] as const)
    it(`${kind} rejects foreign or legacy backend keys before deleting any page item`, async () => {
      const remove = vi.fn();
      const names = [
        encodeStorageKey('owner', 'key'),
        encodeStorageKey('foreign', 'key'),
      ];
      const backend =
        kind === 'kv'
          ? new KvProvider({
              list: async () => ({
                keys: names.map((name) => ({ name })),
                list_complete: true,
              }),
              delete: remove,
            } as unknown as KVNamespace)
          : new R2Provider({
              list: async () => ({
                objects: names.map((key) => ({ key })),
                truncated: false,
              }),
              delete: remove,
            } as unknown as R2Bucket);
      const context = {
        requestId: 'hostile-list',
        timestamp: '2026-11-03T00:00:00Z',
      };
      await expect(backend.list('owner', '', context)).rejects.toThrow();
      await expect(backend.clear('owner', context)).rejects.toThrow();
      expect(remove).not.toHaveBeenCalled();
      names[1] = 'owner:legacy';
      await expect(backend.list('owner', '', context)).rejects.toThrow();
    });
});
