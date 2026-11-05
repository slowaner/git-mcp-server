/**
 * @fileoverview Lock inventory retains every version and rejects unauditable entries.
 * @module tests/scripts/security/lock-inventory
 */
import { describe, expect, it } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { createLockInventory } from '../../../scripts/security/lock-inventory.js';

const integrity = `sha512-${Buffer.alloc(64, 1).toString('base64')}`;
function lock(packages: Record<string, unknown>, version = 1) {
  return JSON.stringify({
    lockfileVersion: version,
    configVersion: 1,
    packages,
  });
}

describe('complete lock inventory', () => {
  it('rejects missing config metadata instead of guessing its schema', () => {
    const text = JSON.stringify({
      lockfileVersion: 1,
      packages: { dependency: ['dependency@1.0.0', '', {}, integrity] },
    });
    expect(() => createLockInventory(text)).toThrow();
  });
  it('supports fresh Bun v2 lock output with the same validated npm tuple contract', () => {
    expect(
      createLockInventory(
        lock({ dependency: ['dependency@1.0.0', '', {}, integrity] }, 2),
      ).components,
    ).toHaveLength(1);
  });
  it('covers every supported entry of the actual project lock', async () => {
    const bytes = await readFile(
      new URL('../../../bun.lock', import.meta.url),
      'utf8',
    );
    expect(createLockInventory(bytes).components.length).toBeGreaterThan(0);
  });
  it('retains multiple versions and scoped names, deduplicating identical copies', () => {
    const result = createLockInventory(
      lock({
        dependency: ['dependency@1.0.0', '', {}, integrity],
        'parent/dependency': ['dependency@2.0.0', '', {}, integrity],
        'other/dependency': ['dependency@1.0.0', '', {}, integrity],
        '@scope/dependency': ['@scope/dependency@1.0.0', '', {}, integrity],
      }),
    );
    expect(result.components).toHaveLength(3);
    expect(result.components.map((component) => component.purl)).toContain(
      'pkg:npm/%40scope/dependency@1.0.0',
    );
    expect(result.metadata.properties[0]!.value).toHaveLength(64);
  });

  it('parses Bun JSONC with trailing commas without changing string bytes', () => {
    const text = `{"lockfileVersion":1,"configVersion":1,"packages":{"dependency":["dependency@1.0.0","",{},"${integrity}",],},}`;
    expect(createLockInventory(text).components[0]!.version).toBe('1.0.0');
  });

  it('supports reviewed v3 scoped overrides without losing installed copies', () => {
    const text = JSON.stringify({
      lockfileVersion: 3,
      configVersion: 1,
      overrides: { 'brace-expansion@^2': '2.1.7' },
      packages: {
        'parent/brace-expansion': [
          'brace-expansion@2.1.7',
          '',
          { dependencies: { 'balanced-match': '^1.0.0' } },
          integrity,
        ],
      },
    });
    expect(createLockInventory(text).components[0]!.version).toBe('2.1.7');
  });

  const invalid = [
    '{}',
    '{',
    lock({ dependency: ['dependency@1.0.0', '', {}, integrity] }, 4),
    lock({}),
    lock({ dependency: ['dependency@1.0.0', '', {}] }),
    lock({
      dependency: [
        'dependency@git+ssh://example.invalid/repo',
        '',
        {},
        integrity,
      ],
    }),
    lock({
      dependency: [
        'dependency@1.0.0',
        'https://unapproved.invalid',
        {},
        integrity,
      ],
    }),
    lock({ dependency: ['dependency@1.0.0', '', {}, 'sha512-incomplete'] }),
    lock({
      a: ['dependency@1.0.0', '', {}, integrity],
      b: [
        'dependency@1.0.0',
        '',
        {},
        `sha512-${Buffer.alloc(64, 2).toString('base64')}`,
      ],
    }),
  ];
  for (const [index, value] of invalid.entries()) {
    it(`rejects missing, unsupported or conflicting coverage ${index + 1}`, () => {
      expect(() => createLockInventory(value)).toThrow();
    });
  }
});
