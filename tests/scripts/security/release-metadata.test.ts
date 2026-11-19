/**
 * @fileoverview Offline validation and removal of post-tag bypass paths.
 * @module tests/scripts/security/release-metadata
 */
import { describe, expect, it } from 'bun:test';
import { readFile } from 'node:fs/promises';
import {
  assertMetadataSyncAllowed,
  metadataCommand,
} from '../../../scripts/validate-mcp-publish-schema.js';
import {
  synchronizedMetadata,
  validateReleaseMetadata,
} from '../../../scripts/security/release-metadata.js';

async function fixture() {
  const pkg = JSON.parse(
    await readFile(new URL('../../../package.json', import.meta.url), 'utf8'),
  );
  const server = JSON.parse(
    await readFile(new URL('../../../server.json', import.meta.url), 'utf8'),
  );
  return { pkg, server };
}

describe('release metadata gates', () => {
  it('validates existing metadata without mutating its bytes', async () => {
    const { pkg, server } = await fixture();
    const before = JSON.stringify(server);
    await validateReleaseMetadata(pkg, server);
    expect(JSON.stringify(server)).toBe(before);
  });
  it('requires synchronization before review and preserves input objects', async () => {
    const { pkg, server } = await fixture();
    const changed = { ...pkg, version: '999.1.0' };
    await expect(validateReleaseMetadata(changed, server)).rejects.toThrow(
      'drift',
    );
    const synced = synchronizedMetadata(changed, server);
    await validateReleaseMetadata(changed, synced);
    expect(server.version).not.toBe(synced.version);
  });
  it('blocks invalid schema and changed package identity', async () => {
    const { pkg, server } = await fixture();
    await expect(
      validateReleaseMetadata(pkg, { ...server, name: 'invalid' }),
    ).rejects.toThrow();
    await expect(
      validateReleaseMetadata({ ...pkg, name: '@example/other' }, server),
    ).rejects.toThrow();
  });
  for (const [status, tags] of [
    [1, ''],
    [null, ''],
    [0, 'v1.2.3'],
  ] as const) {
    it(`blocks sync after failed Git inspection or on tagged HEAD ${status}/${tags}`, () => {
      expect(() => assertMetadataSyncAllowed(status, tags)).toThrow();
    });
  }
  it('permits explicit pre-tag preparation after successful inspection', () => {
    expect(() => assertMetadataSyncAllowed(0, '')).not.toThrow();
  });
  for (const args of [
    [],
    ['--publish-only'],
    ['--no-commit'],
    ['--verify-only'],
    ['--validate-only', '--sync-only'],
  ]) {
    it(`rejects implicit publication and bypass flags ${args.join(' ')}`, async () => {
      await expect(metadataCommand('/not-accessed', args)).rejects.toThrow(
        'Use --sync-only',
      );
    });
  }
});
