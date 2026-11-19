/**
 * @fileoverview Devdocs exclusion matching and file statistics.
 * @module tests/scripts/security/devdocs-files
 */
import { describe, expect, it } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { analyzeFile, matchesPattern } from '../../../scripts/devdocs.js';

describe('devdocs file selection', () => {
  it('matches single-segment and recursive globs', () => {
    expect(matchesPattern('src/example.ts', ['src/*.ts'])).toBe(true);
    expect(matchesPattern('src/nested/example.ts', ['src/*.ts'])).toBe(false);
    expect(matchesPattern('src/nested/example.ts', ['src/**/*.ts'])).toBe(true);
  });

  it('keeps literal exclude fragments and punctuation', () => {
    expect(matchesPattern('src/generated/example.ts', ['generated/'])).toBe(
      true,
    );
    expect(matchesPattern('docs/notes+(draft).md', ['docs/*+(draft).md'])).toBe(
      true,
    );
    expect(matchesPattern('docs/notes.md', ['docs/*+(draft).md'])).toBe(false);
  });
});

describe('devdocs file statistics', () => {
  it('reports lines and bytes for regular files and skips other paths', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'devdocs-files-'));
    try {
      const file = join(directory, 'notes.txt');
      const content = 'first\nsecond é';
      await writeFile(file, content);
      expect(await analyzeFile(file)).toEqual({
        lines: 2,
        size: Buffer.byteLength(content),
      });
      expect(await analyzeFile(directory)).toBeNull();
      expect(await analyzeFile(join(directory, 'missing'))).toBeNull();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
