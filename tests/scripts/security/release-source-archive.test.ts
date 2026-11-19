/**
 * @fileoverview Immutable source archive rejects ambiguous paths, objects and types.
 * @module tests/scripts/security/release-source-archive
 */
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'bun:test';
import {
  completeSourceArchive,
  sourceTreeEntries,
  type SourceBlob,
} from '../../../scripts/security/release-source-archive.js';

function blob(
  path = 'source.txt',
  text = 'reviewed bytes\n',
  mode: SourceBlob['mode'] = '100644',
): SourceBlob {
  const bytes = Buffer.from(text);
  return {
    path,
    mode,
    bytes,
    oid: createHash('sha1')
      .update(`blob ${bytes.length}\0`)
      .update(bytes)
      .digest('hex'),
  };
}

describe('complete immutable source export', () => {
  it('is deterministic across input order and preserves raw substitution markers', () => {
    const a = blob('source.txt', '$Format:%H$\n');
    const b = blob('script.sh', '#!/bin/sh\n', '100755');
    const link = blob('AGENTS.md', 'source.txt', '120000');
    const archive = completeSourceArchive([a, b, link]);
    expect(archive).toEqual(completeSourceArchive([link, b, a]));
    expect(archive.includes(Buffer.from('$Format:%H$'))).toBe(true);
    expect(archive.subarray(-1024)).toEqual(Buffer.alloc(1024));
  });
  for (const path of [
    '../escape',
    '/absolute',
    'a/../b',
    'a//b',
    '.git/config',
    'a\nb',
    'a\\b',
  ]) {
    it(`rejects unsupported source path ${JSON.stringify(path)}`, () => {
      expect(() => completeSourceArchive([blob(path)])).toThrow();
    });
  }
  it('rejects missing, duplicated, prefix-colliding and tampered source objects', () => {
    expect(() => completeSourceArchive([])).toThrow();
    expect(() => completeSourceArchive([blob(), blob()])).toThrow('Duplicate');
    expect(() => completeSourceArchive([blob('a'), blob('a/b')])).toThrow(
      'collision',
    );
    expect(() =>
      completeSourceArchive([{ ...blob(), bytes: Buffer.from('different') }]),
    ).toThrow('immutable');
    expect(() =>
      completeSourceArchive([blob('link', '../outside', '120000')]),
    ).toThrow();
    expect(() => completeSourceArchive([blob('x'.repeat(101))])).toThrow(
      'ustar',
    );
  });
  it('decodes whole Git records only and refuses unsupported submodules/types', () => {
    const a = blob('nested/\uFEFFvalid.txt');
    const bytes = Buffer.from(`${a.mode} blob ${a.oid}\t${a.path}\0`);
    expect(sourceTreeEntries(bytes)).toEqual([
      { path: a.path, mode: a.mode, oid: a.oid },
    ]);
    expect(() => sourceTreeEntries(bytes.subarray(0, -1))).toThrow(
      'Incomplete',
    );
    expect(() =>
      sourceTreeEntries(Buffer.from(`160000 commit ${a.oid}\tmodule\0`)),
    ).toThrow('type');
    expect(() =>
      sourceTreeEntries(Buffer.from(`100644 blob ${a.oid}\t../escape\0`)),
    ).toThrow();
  });
});
