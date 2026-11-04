/**
 * @fileoverview Native Git index and raw filename oracles for literal operands.
 * @module tests/security/git-file-operands
 */
import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'bun:test';
import {
  literalFileArguments,
  literalFileOperand,
  nulFileNames,
} from '@/services/git/providers/cli/utils/git-file-operands.js';

const limits = { maxBytes: 1_048_576, maxFiles: 64 };

function repository(
  run: (
    root: string,
    git: (
      args: string[],
      allowFailure?: boolean,
    ) => { stdout: Buffer; exitCode: number },
  ) => void,
): void {
  const root = mkdtempSync(join(tmpdir(), 'g5-file-operands-'));
  const env = {
    PATH: process.env.PATH ?? '',
    HOME: root,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0',
  };
  const git = (args: string[], allowFailure = false) => {
    const result = spawnSync('git', args, {
      cwd: root,
      env,
      input: '',
      timeout: 10_000,
    });
    if (
      result.error ||
      result.signal ||
      result.status === null ||
      (!allowFailure && result.status !== 0)
    )
      throw new Error('Git filename fixture process failed');
    return { stdout: result.stdout, exitCode: result.status };
  };
  try {
    git(['init', '-b', 'main', '--template=']);
    git(['config', 'core.hooksPath', '/dev/null']);
    git(['config', 'user.name', 'Fixture']);
    git(['config', 'user.email', 'fixture@example.invalid']);
    git(['config', 'commit.gpgSign', 'false']);
    run(root, git);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe('literal Git filename boundaries', () => {
  it('stages exact hostile filenames without option injection or incidental pathspec expansion', () =>
    repository((root, git) => {
      const selected = [
        '-',
        '--',
        '--all',
        ':',
        ':(glob)*',
        '*',
        '?',
        '[ab].txt',
        'line\nname.txt',
        'cr\rname.txt',
        'tab\tname.txt',
        'back\\slash.txt',
        'trailing space ',
        'valid-\ufffd.txt',
        '\ufeffbom.txt',
        '😀.txt',
        'строка.txt',
        'ordinary.txt',
      ];
      const sentinel = 'a.txt';
      for (const name of selected)
        writeFileSync(join(root, name), 'selected\n');
      writeFileSync(join(root, sentinel), 'unchanged-extra-file\n');
      git(['add', ...literalFileArguments(selected, limits)]);
      expect(
        nulFileNames(git(['ls-files', '-z']).stdout, limits).sort(),
      ).toEqual([...selected].sort());
      expect(
        nulFileNames(
          git(['ls-files', '--others', '--exclude-standard', '-z']).stdout,
          limits,
        ),
      ).toEqual([sentinel]);
      expect(readFileSync(join(root, sentinel), 'utf8')).toBe(
        'unchanged-extra-file\n',
      );
    }));

  it('preserves the advertised dot-directory behavior', () =>
    repository((root, git) => {
      mkdirSync(join(root, 'nested'));
      writeFileSync(join(root, 'ordinary.txt'), 'one\n');
      writeFileSync(join(root, 'nested', 'child.txt'), 'two\n');
      git(['add', ...literalFileArguments(['.'], limits)]);
      expect(nulFileNames(git(['ls-files', '-z']).stdout, limits)).toEqual([
        'nested/child.txt',
        'ordinary.txt',
      ]);
    }));

  it('commits only the selected literal filename and leaves the extra index entry intact', () =>
    repository((root, git) => {
      const selected = 'weird?.txt';
      const extra = 'weirdA.txt';
      for (const name of [selected, extra])
        writeFileSync(join(root, name), 'original\n');
      git(['add', ...literalFileArguments(['.'], limits)]);
      git(['commit', '-m', 'Base']);
      writeFileSync(join(root, selected), 'selected change\n');
      writeFileSync(join(root, extra), 'extra remains staged\n');
      git(['add', ...literalFileArguments(['.'], limits)]);
      git([
        'commit',
        '-m',
        'Selected',
        ...literalFileArguments([selected], limits),
      ]);
      expect(
        nulFileNames(
          git([
            'diff-tree',
            '--no-commit-id',
            '--name-only',
            '-z',
            '-r',
            'HEAD',
          ]).stdout,
          limits,
        ),
      ).toEqual([selected]);
      expect(
        nulFileNames(
          git(['diff', '--cached', '--name-only', '-z']).stdout,
          limits,
        ),
      ).toEqual([extra]);
      expect(git(['show', `HEAD:${extra}`]).stdout.toString('utf8')).toBe(
        'original\n',
      );
      expect(readFileSync(join(root, extra), 'utf8')).toBe(
        'extra remains staged\n',
      );
    }));

  it('reads a dash filename as a real no-index diff operand rather than stdin', () =>
    repository((root, git) => {
      for (const file of ['-', '--', 'line\nname.txt']) {
        writeFileSync(join(root, file), 'real operand content\n');
        const result = git(
          [
            'diff',
            '--no-index',
            '--',
            '/dev/null',
            literalFileOperand(file, limits),
          ],
          true,
        );
        expect(result.exitCode).toBe(1);
        expect(result.stdout.toString('utf8')).toContain(
          '+real operand content',
        );
      }
    }));

  it('distinguishes invalid native UTF8 filename bytes from a valid replacement-character filename', () =>
    repository((root, git) => {
      const valid = 'valid-\ufffd.txt';
      writeFileSync(join(root, valid), 'valid\n');
      expect(
        nulFileNames(
          git(['ls-files', '--others', '--exclude-standard', '-z']).stdout,
          limits,
        ),
      ).toEqual([valid]);
      writeFileSync(
        Buffer.concat([Buffer.from(`${root}/invalid-`), Buffer.from([0xff])]),
        'invalid filename bytes\n',
      );
      expect(() =>
        nulFileNames(
          git(['ls-files', '--others', '--exclude-standard', '-z']).stdout,
          limits,
        ),
      ).toThrow(/UTF-8/);
      expect(git(['ls-files', '-z']).stdout.byteLength).toBe(0);
    }));

  it('preserves raw Unicode/BOM and rejects malformed framing, duplicate records and exact byte/item overflow', () => {
    const raw = Buffer.from('\ufefffirst\0valid-\ufffd\0e\u0301\0é\0', 'utf8');
    expect(
      nulFileNames(raw, { maxBytes: raw.byteLength, maxFiles: 4 }),
    ).toEqual(['\ufefffirst', 'valid-\ufffd', 'e\u0301', 'é']);
    expect(() =>
      nulFileNames(raw, { maxBytes: raw.byteLength - 1, maxFiles: 4 }),
    ).toThrow(/byte limit/);
    expect(() =>
      nulFileNames(raw, { maxBytes: raw.byteLength, maxFiles: 3 }),
    ).toThrow(/item limit/);
    for (const data of ['\0', 'a\0\0', 'a\0a\0', 'a\0truncated'])
      expect(() => nulFileNames(Buffer.from(data), limits)).toThrow();
    for (const bytes of [
      [0xc0, 0x80, 0],
      [0xed, 0xa0, 0x80, 0],
      [0xf0, 0x9f, 0],
    ])
      expect(() => nulFileNames(new Uint8Array(bytes), limits)).toThrow(
        /UTF-8/,
      );
    expect(nulFileNames(new Uint8Array(), limits)).toEqual([]);
  });

  it('rejects invalid string operands, decoded-string input and unbounded limits before mutation', () => {
    for (const path of ['', 'embedded\0nul', '\ud800', '\udc00'])
      expect(() => literalFileArguments([path], limits)).toThrow();
    expect(() => nulFileNames('decoded\0' as never, limits)).toThrow(
      /Original/,
    );
    expect(() => literalFileOperand('/absolute', limits)).toThrow(/relative/);
    expect(() =>
      literalFileArguments(['é'], { maxBytes: 2, maxFiles: 1 }),
    ).toThrow(/byte limit/);
    expect(literalFileArguments(['é'], { maxBytes: 3, maxFiles: 1 })).toEqual([
      '--',
      ':(literal)é',
    ]);
    for (const value of [0, -1, Infinity, NaN, 1.5]) {
      expect(() =>
        literalFileArguments(['ordinary'], { maxBytes: value, maxFiles: 1 }),
      ).toThrow();
      expect(() =>
        nulFileNames(Buffer.from('ordinary\0'), {
          maxBytes: 100,
          maxFiles: value,
        }),
      ).toThrow();
    }
  });
});
