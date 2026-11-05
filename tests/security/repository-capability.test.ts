/**
 * @fileoverview Real filesystem oracles for canonical repository capabilities.
 * @module tests/security/repository-capability.test
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  linkSync,
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
import {
  RepositoryPathPolicy,
  localRemotePath,
} from '@/services/git/core/repository-capability.js';

describe('canonical repository filesystem boundary', () => {
  let dir: string;
  let roots: string[];
  let outside: string;
  let policy: RepositoryPathPolicy;
  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'repository-boundary-'));
    roots = [path.join(dir, 'root1'), path.join(dir, 'root2')];
    outside = path.join(dir, 'outside');
    for (const root of [...roots, outside]) mkdirSync(root);
    writeFileSync(path.join(outside, 'sentinel'), 'unchanged');
    policy = new RepositoryPathPolicy(roots);
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('authorizes both roots and nested new leaves without creating them', () => {
    for (const root of roots) {
      const result = policy.resolve(path.join(root, 'nested/new'));
      expect(result.path).toBe(
        path.join(policy.resolve(root).path, 'nested/new'),
      );
      expect(result.existingParent).toBe(policy.resolve(root).path);
    }
    expect(policy.resolve('new').path).toBe(
      path.join(policy.resolve(roots[0]!).path, 'new'),
    );
    expect(policy.resolve('../new', path.join(roots[1]!, 'repo')).path).toBe(
      path.join(policy.resolve(roots[1]!).path, 'new'),
    );
  });

  it('denies outside and sibling prefixes, including empty root overrides', () => {
    for (const target of [
      outside,
      `${roots[0]}-sibling`,
      `${roots[1]}-sibling`,
    ]) {
      expect(() => policy.resolve(target)).toThrow('boundary denied');
    }
    expect(() => new RepositoryPathPolicy([])).toThrow();
  });

  it('denies existing, missing-leaf, dangling and loop symlinks in either root', () => {
    for (const root of roots) {
      symlinkSync(outside, path.join(root, 'escape'));
      symlinkSync(path.join(dir, 'absent'), path.join(root, 'dangling'));
      symlinkSync('loop', path.join(root, 'loop'));
      for (const name of [
        'escape/sentinel',
        'escape/new/leaf',
        'dangling/new',
        'loop',
      ]) {
        expect(() => policy.resolve(path.join(root, name))).toThrow();
      }
    }
    expect(readFileSync(path.join(outside, 'sentinel'), 'utf8')).toBe(
      'unchanged',
    );
  });

  it('pins configured roots and rejects alias roots and replacements', () => {
    const alias = path.join(dir, 'alias');
    symlinkSync(outside, alias);
    expect(() => new RepositoryPathPolicy([alias])).toThrow();
    mkdirSync(path.join(outside, 'nested'));
    expect(
      () => new RepositoryPathPolicy([path.join(alias, 'nested')]),
    ).toThrow();
    renameSync(roots[0]!, path.join(dir, 'old-root'));
    mkdirSync(roots[0]!);
    expect(() => policy.resolve(roots[1]!)).toThrow('configured root changed');
  });

  it('intersects ACL roots, distinguishes absence/empty and preserves relative anchor', () => {
    expect(policy.restrict(undefined)).toBe(policy);
    expect(() => policy.restrict([])).toThrow();
    expect(() => policy.restrict([outside])).toThrow();
    const second = policy.restrict([roots[1]!]);
    expect(second.resolve(roots[1]!).path).toBe(policy.resolve(roots[1]!).path);
    expect(() => second.resolve('new')).toThrow();
    expect(() => second.resolve(roots[0]!)).toThrow();
  });

  it('reads only bounded ordinary metadata, never linked or special files', () => {
    const regular = path.join(roots[0]!, 'config');
    writeFileSync(regular, 'safe');
    expect(policy.readMetadata(regular, 4)).toBe('safe');
    expect(() => policy.readMetadata(regular, 3)).toThrow();
    linkSync(path.join(outside, 'sentinel'), path.join(roots[0]!, 'hardlink'));
    expect(() =>
      policy.readMetadata(path.join(roots[0]!, 'hardlink')),
    ).toThrow();
    expect(() => policy.readMetadata(roots[0]!)).toThrow();
    expect(readFileSync(path.join(outside, 'sentinel'), 'utf8')).toBe(
      'unchanged',
    );
  });

  it.each([
    ['malformed', [0xff]],
    ['truncated', [0xe2, 0x82]],
    ['overlong', [0xc0, 0xaf]],
    ['surrogate', [0xed, 0xa0, 0x80]],
  ] as const)(
    'rejects %s UTF-8 metadata content without changing bytes',
    (_name, bytes) => {
      const filename = path.join(roots[0]!, 'metadata');
      const content = Buffer.from(bytes);
      writeFileSync(filename, content);
      expect(() => policy.readMetadata(filename)).toThrow('valid UTF-8');
      expect(readFileSync(filename)).toEqual(content);
    },
  );

  it('retains metadata BOM and valid literal replacement-character bytes', () => {
    const filename = path.join(roots[0]!, 'metadata');
    const text = '\ufeff[core]\nworktree = repo-\ufffd\n';
    const content = Buffer.from(text);
    writeFileSync(filename, content);
    expect(policy.readMetadata(filename)).toBe(text);
    expect(Buffer.from(policy.readMetadata(filename))).toEqual(content);
  });

  it('normalizes local URL encodings without decoding ordinary path names', () => {
    const target = path.join(roots[1]!, 'with space');
    expect(
      localRemotePath(`FILE://${target.replace(' ', '%20')}`, roots[0]!),
    ).toBe(target);
    expect(localRemotePath('../root2/repo', roots[0]!)).toBe(
      path.join(roots[1]!, 'repo'),
    );
    expect(
      localRemotePath('https://example.test/repo', roots[0]!),
    ).toBeUndefined();
    expect(localRemotePath('git@example.test:repo', roots[0]!)).toBeUndefined();
    for (const url of [
      'file://foreign.test/repo',
      'file:///repo%2fescape',
      'file:///repo?query',
      '-option',
      'C:\\outside',
    ]) {
      expect(() => localRemotePath(url, roots[0]!)).toThrow();
    }
  });
});
