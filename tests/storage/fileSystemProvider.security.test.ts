/**
 * @fileoverview Production filesystem provider compliance and security sentinels.
 * @module tests/storage/fileSystemProvider.security.test
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  chmodSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { FileSystemProvider } from '@/storage/providers/fileSystem/fileSystemProvider.js';
import { encodeStorageComponent } from '@/storage/core/storageKeyCodec.js';
import { requestContextService } from '@/utils/index.js';
import { JsonRpcErrorCode } from '@/types-global/errors.js';
import { storageProviderTests } from './storageProviderCompliance.test.js';

describe('filesystem v2 production provider', () => {
  let dir: string;
  let root: string;
  let outside: string;
  let provider: FileSystemProvider;
  const context = requestContextService.createRequestContext({
    operation: 'filesystem-boundary-test',
    tenantId: 'tenant',
  });
  const filename = (tenant: string, key: string): string =>
    path.join(
      root,
      'v2',
      encodeStorageComponent(tenant),
      encodeStorageComponent(key),
    );
  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'filesystem-provider-'));
    root = path.join(dir, 'store');
    outside = path.join(dir, 'outside');
    writeFileSync(outside, 'unchanged', { mode: 0o600 });
    provider = new FileSystemProvider(root);
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('keeps tenant/key aliases distinct on disk and through get/list/clear', async () => {
    const pairs = [
      ['a:b', 'c'],
      ['a', 'b:c'],
      ['a/b', '../key'],
      ['A', 'KEY'],
      ['a', 'KEY'],
    ] as const;
    for (const [tenant, key] of pairs)
      await provider.set(tenant, key, `${tenant}:${key}`, context);
    for (const [tenant, key] of pairs)
      expect(await provider.get(tenant, key, context)).toBe(`${tenant}:${key}`);
    expect(await provider.clear('A', context)).toBe(1);
    expect(await provider.get('a', 'KEY', context)).toBe('a:KEY');
    expect(lstatSync(root).mode & 0o777).toBe(0o700);
    expect(lstatSync(filename('a', 'KEY')).mode & 0o777).toBe(0o600);
    await expect(provider.list('a', '\0', context)).rejects.toThrow();
    expect((await provider.list('a', '', context)).keys).toEqual([
      'KEY',
      'b:c',
    ]);
  });

  it('rejects linked values before get/set/delete/list/clear without touching outside', async () => {
    await provider.set('tenant', 'key', 'safe', context);
    const file = filename('tenant', 'key');
    for (const link of [symlinkSync, linkSync]) {
      rmSync(file);
      link(outside, file);
      await expect(provider.get('tenant', 'key', context)).rejects.toThrow();
      await expect(
        provider.set('tenant', 'key', 'bad', context),
      ).rejects.toThrow();
      await expect(provider.delete('tenant', 'key', context)).rejects.toThrow();
      await expect(provider.list('tenant', '', context)).rejects.toThrow();
      await expect(provider.clear('tenant', context)).rejects.toThrow();
      expect(readFileSync(outside, 'utf8')).toBe('unchanged');
      rmSync(file);
      writeFileSync(file, '{"value":"safe","__mcp":{"v":1}}', { mode: 0o600 });
    }
  });

  it('rejects tenant/root link tampering and unsafe permissions after construction', async () => {
    await provider.set('tenant', 'key', 'safe', context);
    const tenantDir = path.dirname(filename('tenant', 'key'));
    renameSync(tenantDir, `${tenantDir}-old`);
    symlinkSync(dir, tenantDir);
    await expect(provider.get('tenant', 'key', context)).rejects.toThrow();
    rmSync(tenantDir);
    renameSync(`${tenantDir}-old`, tenantDir);
    chmodSync(filename('tenant', 'key'), 0o644);
    await expect(provider.get('tenant', 'key', context)).rejects.toThrow();
    chmodSync(filename('tenant', 'key'), 0o600);
    renameSync(root, `${root}-old`);
    symlinkSync(dir, root);
    await expect(provider.get('tenant', 'key', context)).rejects.toThrow();
    expect(() => new FileSystemProvider(root)).toThrow();
    expect(readFileSync(outside, 'utf8')).toBe('unchanged');
  });

  it('expires actual envelopes, handles bulk methods and preserves complete writes', async () => {
    await provider.setMany(
      'tenant',
      new Map([
        ['one', 1],
        ['two', 2],
      ]),
      context,
      { ttl: 60 },
    );
    expect(
      await provider.getMany('tenant', ['one', 'two', 'missing'], context),
    ).toEqual(
      new Map([
        ['one', 1],
        ['two', 2],
      ]),
    );
    const raw = JSON.parse(readFileSync(filename('tenant', 'one'), 'utf8'));
    raw.__mcp.expiresAt = Date.now() - 1;
    writeFileSync(filename('tenant', 'one'), JSON.stringify(raw), {
      mode: 0o600,
    });
    expect(await provider.get('tenant', 'one', context)).toBeNull();
    expect((await provider.list('tenant', '', context)).keys).toEqual(['two']);
    const previous = readFileSync(filename('tenant', 'two'), 'utf8');
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    await expect(
      provider.set('tenant', 'two', cyclic, context),
    ).rejects.toThrow();
    await expect(
      provider.set('tenant', 'two', 'x'.repeat(16 * 1024 * 1024), context),
    ).rejects.toThrow();
    expect(readFileSync(filename('tenant', 'two'), 'utf8')).toBe(previous);
    await Promise.all([
      provider.set('tenant', 'two', { result: 'a' }, context),
      provider.set('tenant', 'two', { result: 'b' }, context),
    ]);
    expect(['a', 'b']).toContain(
      (await provider.get<{ result: string }>('tenant', 'two', context))!
        .result,
    );
    expect(
      readdirSync(path.dirname(filename('tenant', 'two'))).every(
        (name) => !name.startsWith('.tmp-'),
      ),
    ).toBe(true);
    expect(
      await provider.deleteMany('tenant', ['two', 'missing'], context),
    ).toBe(1);
  });

  it.each([
    ['malformed', [0xff]],
    ['truncated', [0xe2, 0x82]],
    ['overlong', [0xc0, 0xaf]],
    ['surrogate', [0xed, 0xa0, 0x80]],
  ] as const)(
    'reports %s UTF-8 corruption without defaulting or mutating storage',
    async (_name, bytes) => {
      await provider.set('tenant', 'key', 'initial', context);
      const file = filename('tenant', 'key');
      const corrupt = Buffer.concat([
        Buffer.from('{"__mcp":{"v":1},"value":"'),
        Buffer.from(bytes),
        Buffer.from('"}'),
      ]);
      writeFileSync(file, corrupt);
      const inode = lstatSync(file).ino;
      const error = { code: JsonRpcErrorCode.SerializationError };
      await expect(
        provider.get('tenant', 'key', context),
      ).rejects.toMatchObject(error);
      await expect(provider.list('tenant', '', context)).rejects.toMatchObject(
        error,
      );
      await expect(
        provider.getMany('tenant', ['key'], context),
      ).rejects.toMatchObject(error);
      expect(readFileSync(file)).toEqual(corrupt);
      expect(lstatSync(file).ino).toBe(inode);
    },
  );

  it.each(['{', '\ufeff{"__mcp":{"v":1},"value":"safe"}'])(
    'does not hide invalid JSON syntax %j from list/get',
    async (text) => {
      await provider.set('tenant', 'key', 'initial', context);
      const file = filename('tenant', 'key');
      writeFileSync(file, text);
      const error = { code: JsonRpcErrorCode.SerializationError };
      await expect(
        provider.get('tenant', 'key', context),
      ).rejects.toMatchObject(error);
      await expect(provider.list('tenant', '', context)).rejects.toMatchObject(
        error,
      );
      expect(readFileSync(file)).toEqual(Buffer.from(text));
    },
  );

  it('preserves valid BOM and literal U+FFFD inside JSON values', async () => {
    const text = '\ufeffvalue-\ufffd';
    await provider.set('tenant', 'key', text, context);
    expect(await provider.get('tenant', 'key', context)).toBe(text);
    expect((await provider.list('tenant', '', context)).keys).toEqual(['key']);
  });

  it.each([
    'null',
    '{}',
    '{"__mcp":null,"value":"safe"}',
    '{"__mcp":{"v":2},"value":"safe"}',
    '{"__mcp":{"v":1}}',
    '{"__mcp":{"v":1,"expiresAt":"old"},"value":"safe"}',
    '{"__mcp":{"v":1,"expiresAt":null},"value":"safe"}',
    '{"__mcp":{"v":1,"expiresAt":1e999},"value":"safe"}',
  ])(
    'rejects invalid v2 envelope %s without fallback, expiry deletion or mutation',
    async (text) => {
      await provider.set('tenant', 'key', 'initial', context);
      const file = filename('tenant', 'key');
      writeFileSync(file, text);
      const inode = lstatSync(file).ino;
      const error = { code: JsonRpcErrorCode.SerializationError };
      await expect(
        provider.get('tenant', 'key', context),
      ).rejects.toMatchObject(error);
      await expect(provider.list('tenant', '', context)).rejects.toMatchObject(
        error,
      );
      await expect(
        provider.getMany('tenant', ['key'], context),
      ).rejects.toMatchObject(error);
      expect(readFileSync(file)).toEqual(Buffer.from(text));
      expect(lstatSync(file).ino).toBe(inode);
    },
  );

  it('does not overwrite a completed value with undefined or nonfinite TTL', async () => {
    await provider.set('tenant', 'key', 'initial', context);
    const file = filename('tenant', 'key');
    const bytes = readFileSync(file);
    await expect(
      provider.set('tenant', 'key', undefined, context),
    ).rejects.toThrow();
    await expect(
      provider.set('tenant', 'key', 'new', context, { ttl: Infinity }),
    ).rejects.toThrow();
    expect(readFileSync(file)).toEqual(bytes);
  });

  it('preserves valid null and falsy envelope values', async () => {
    for (const value of [null, false, 0, '']) {
      await provider.set('tenant', 'key', value, context);
      expect(await provider.get('tenant', 'key', context)).toBe(value);
      expect(
        await provider.getMany('tenant', ['key', 'missing'], context),
      ).toEqual(new Map([['key', value]]));
      expect((await provider.list('tenant', '', context)).keys).toEqual([
        'key',
      ]);
    }
  });

  it('does not read legacy key spaces or accept nonprivate existing storage', async () => {
    mkdirSync(path.join(root, 'tenant'), { mode: 0o700 });
    writeFileSync(path.join(root, 'tenant', 'key'), '"legacy"', {
      mode: 0o600,
    });
    expect(
      await new FileSystemProvider(root).get('tenant', 'key', context),
    ).toBeNull();
    expect((await provider.list('tenant', '', context)).keys).toEqual([]);
    expect(readFileSync(path.join(root, 'tenant', 'key'), 'utf8')).toBe(
      '"legacy"',
    );
    chmodSync(root, 0o755);
    expect(() => new FileSystemProvider(root)).toThrow();
  });
});

describe('filesystem v2 compliance', () => {
  const directories: string[] = [];
  storageProviderTests(() => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'filesystem-compliance-'));
    directories.push(dir);
    return new FileSystemProvider(path.join(dir, 'store'));
  }, 'private filesystem v2');
  afterEach(() => {
    for (const dir of directories.splice(0))
      rmSync(dir, { recursive: true, force: true });
  });
});
