/**
 * @fileoverview Collision, prefix and provider-boundary tests for storage keys.
 * @module tests/storage/storageKeyCodec.test
 */
import { describe, expect, it } from 'vitest';

import {
  decodeStorageComponent,
  decodeStorageKey,
  encodeStorageComponent,
  encodeStorageKey,
  encodeStoragePrefix,
  storageTenantPrefix,
} from '@/storage/core/storageKeyCodec.js';

describe('storage key codec', () => {
  it('preserves distinct tenants and keys across delimiter, path and case aliases', () => {
    const pairs = [
      ['a:b', 'c'],
      ['a', 'b:c'],
      ['a/b', 'c'],
      ['a', 'b/c'],
      ['A', 'key'],
      ['a', 'key'],
      ['a', 'KEY'],
      ['a', '../key'],
      ['a', '%2f'],
      ['a', '/'],
      ['a', '\\'],
      ['a', '.'],
      ['é', 'key'],
      ['e\u0301', 'key'],
      ['a ', 'key'],
      ['a', ' key'],
      ['CON', 'NUL'],
      ['a', '😀'],
      ['a', '\ufeffkey'],
    ] as const;
    const encoded = pairs.map(([tenant, key]) => encodeStorageKey(tenant, key));
    expect(new Set(encoded).size).toBe(pairs.length);
    expect(new Set(encoded.map((key) => key.toLowerCase())).size).toBe(
      pairs.length,
    );
    pairs.forEach(([tenant, key], index) => {
      expect(decodeStorageKey(tenant, encoded[index]!)).toBe(key);
      expect(encoded[index]).toMatch(/^v2\/x[0-9a-f]+\/x[0-9a-f]+$/);
    });
  });

  it('preserves logical list prefixes without including other tenant namespaces', () => {
    const keys = ['cwd:one', 'cwd:two', 'other', 'cwd:é', 'cwd:😀'];
    const encoded = keys.map((key) => encodeStorageKey('tenant', key));
    const listed = encoded
      .filter((key) => key.startsWith(encodeStoragePrefix('tenant', 'cwd:')))
      .map((key) => decodeStorageKey('tenant', key));
    expect(listed).toEqual(['cwd:one', 'cwd:two', 'cwd:é', 'cwd:😀']);
    expect(
      encoded.every((key) => key.startsWith(encodeStoragePrefix('tenant'))),
    ).toBe(true);
    expect(
      encodeStorageKey('tenant:child', 'cwd:one').startsWith(
        storageTenantPrefix('tenant'),
      ),
    ).toBe(false);
  });

  it('accepts exact UTF-8 bounds within filesystem and KV limits', () => {
    const tenant = 't'.repeat(120);
    const key = '😀'.repeat(30);
    expect(encodeStorageComponent(tenant)).toHaveLength(241);
    expect(encodeStorageComponent(key)).toHaveLength(241);
    expect(encodeStorageKey(tenant, key).length).toBeLessThanOrEqual(512);
    expect(decodeStorageKey(tenant, encodeStorageKey(tenant, key))).toBe(key);
    expect(() => encodeStorageComponent(`${tenant}t`)).toThrow();
    expect(() => encodeStorageComponent(`${key}x`)).toThrow();
  });

  it.each(['\u0000', '\n', '\u007f', '\u0085', '\ud800', '\udfff'])(
    'rejects invalid Unicode or control input %j',
    (value) => {
      expect(() => encodeStorageComponent(value)).toThrow();
    },
  );

  it.each(['', 'x0', 'xAA', 'xzz', 'xc080', 'xedA080', 'x2f/extra', 'x00'])(
    'rejects noncanonical components %j',
    (value) => {
      expect(() => decodeStorageComponent(value)).toThrow();
    },
  );

  it('rejects foreign, empty and legacy key spaces instead of guessing migration', () => {
    expect(() => encodeStorageKey('', 'key')).toThrow();
    expect(() => encodeStorageKey('tenant', '')).toThrow();
    expect(() =>
      decodeStorageKey('other', encodeStorageKey('tenant', 'key')),
    ).toThrow();
    expect(() => decodeStorageKey('tenant', 'tenant:key')).toThrow();
    expect(() =>
      decodeStorageKey('tenant', `${storageTenantPrefix('tenant')}x`),
    ).toThrow();
  });
});
