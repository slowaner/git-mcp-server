/**
 * @fileoverview Filesystem storage tampering and atomic replacement sentinels.
 * @module tests/security/private-file-store.test
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  chmodSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PrivateFileStore } from '@/storage/providers/fileSystem/privateFileStore.js';

describe('private atomic file storage', () => {
  let dir: string;
  let root: string;
  let outside: string;
  let store: PrivateFileStore;
  const tenant = 'x74656e616e74';
  const key = 'x6b6579';
  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'private-store-'));
    root = path.join(dir, 'storage');
    outside = path.join(dir, 'sentinel');
    writeFileSync(outside, 'unchanged', { mode: 0o600 });
    store = new PrivateFileStore(root);
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('creates private directories/files and atomically replaces an inode', () => {
    store.write(tenant, key, 'first');
    const filename = path.join(root, tenant, key);
    const first = lstatSync(filename).ino;
    store.write(tenant, key, 'second');
    expect(lstatSync(filename).ino).not.toBe(first);
    expect(store.read(tenant, key)).toBe('second');
    expect(lstatSync(root).mode & 0o777).toBe(0o700);
    expect(lstatSync(path.join(root, tenant)).mode & 0o777).toBe(0o700);
    expect(lstatSync(filename).mode & 0o777).toBe(0o600);
    expect(store.list(tenant)).toEqual([key]);
    expect(store.delete(tenant, key)).toBe(true);
    expect(store.delete(tenant, key)).toBe(false);
    expect(store.read(tenant, key)).toBeNull();
  });

  it('never follows value links for read/write/delete/list', () => {
    mkdirSync(path.join(root, tenant), { mode: 0o700 });
    const filename = path.join(root, tenant, key);
    for (const link of [symlinkSync, linkSync]) {
      link(outside, filename);
      expect(() => store.read(tenant, key)).toThrow();
      expect(() => store.write(tenant, key, 'bad')).toThrow();
      expect(() => store.delete(tenant, key)).toThrow();
      expect(() => store.list(tenant)).toThrow();
      expect(readFileSync(outside, 'utf8')).toBe('unchanged');
      rmSync(filename);
    }
  });

  it('rejects root and tenant symlinks or root identity replacement', () => {
    const foreign = path.join(dir, 'foreign');
    mkdirSync(foreign, { mode: 0o700 });
    symlinkSync(foreign, path.join(root, tenant));
    expect(() => store.write(tenant, key, 'bad')).toThrow();
    rmSync(path.join(root, tenant));
    renameSync(root, path.join(dir, 'old-root'));
    mkdirSync(root, { mode: 0o700 });
    expect(() => store.read(tenant, key)).toThrow();
    rmSync(root, { recursive: true });
    symlinkSync(foreign, root);
    expect(() => new PrivateFileStore(root)).toThrow();
    expect(readFileSync(outside, 'utf8')).toBe('unchanged');
  });

  it('fails closed on nonprivate permissions and component aliases', () => {
    store.write(tenant, key, 'safe');
    chmodSync(path.join(root, tenant, key), 0o644);
    expect(() => store.read(tenant, key)).toThrow();
    chmodSync(path.join(root, tenant, key), 0o600);
    chmodSync(path.join(root, tenant, key), 0o700);
    expect(() => store.read(tenant, key)).toThrow();
    chmodSync(path.join(root, tenant, key), 0o600);
    chmodSync(path.join(root, tenant), 0o755);
    expect(() => store.write(tenant, key, 'bad')).toThrow();
    for (const alias of [
      '../tenant',
      'xFF',
      'x0',
      'x',
      'x00/other',
      'x01'.repeat(241),
    ]) {
      expect(() => store.read(alias, key)).toThrow();
    }
    chmodSync(root, 0o755);
    expect(() => new PrivateFileStore(root)).toThrow();
  });

  it.each([
    ['malformed', [0xff]],
    ['truncated', [0xe2, 0x82]],
    ['overlong', [0xc0, 0xaf]],
    ['surrogate', [0xed, 0xa0, 0x80]],
  ] as const)(
    'rejects %s UTF-8 content without replacing or deleting it',
    (_name, bytes) => {
      store.write(tenant, key, 'initial');
      const filename = path.join(root, tenant, key);
      const content = Buffer.from(bytes);
      writeFileSync(filename, content);
      expect(() => store.read(tenant, key)).toThrow('invalid UTF-8');
      expect(readFileSync(filename)).toEqual(content);
    },
  );

  it('preserves a value BOM and valid literal U+FFFD exactly', () => {
    const text = '\ufeffvalue-\ufffd';
    store.write(tenant, key, text);
    expect(store.read(tenant, key)).toBe(text);
    expect(Buffer.from(store.read(tenant, key)!)).toEqual(
      readFileSync(path.join(root, tenant, key)),
    );
  });

  it('retains completed values while hiding abandoned temp entries', () => {
    store.write(tenant, key, 'complete');
    writeFileSync(path.join(root, tenant, '.tmp-interrupted'), 'partial', {
      mode: 0o600,
    });
    expect(store.read(tenant, key)).toBe('complete');
    expect(store.list(tenant)).toEqual([key]);
  });
});
