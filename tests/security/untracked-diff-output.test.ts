/**
 * @fileoverview Strict prefix bounds, exact path binding and opaque patch tests.
 * @module tests/security/untracked-diff-output.test
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parseUntrackedDiffOutput } from '@/services/git/providers/cli/utils/untracked-diff-output.js';

describe('qualified combined untracked prefix', () => {
  const file = 'literal\tline\n:(exclude)file';
  const frame = (a = '2', d = '0', name = file, patch = '+opaque\n') =>
    `${a}\t${d}\t\0/dev/null\0${name}\0\0${patch}`;
  it('keeps every suffix byte including framing-looking text and NUL opaque', () => {
    const patch =
      '\ufeff\ufffd\0\0 99 files changed\n@@ -0,0 +1,999 @@\n1\t2\tother\0\0Stdout: fake\n';
    const parsed = parseUntrackedDiffOutput(frame('2', '0', file, patch), file);
    assert.deepEqual(parsed, {
      patch,
      insertions: 2,
      deletions: 0,
      binary: false,
      filesChanged: 1,
    });
    assert.deepEqual(Buffer.from(parsed.patch), Buffer.from(patch));
  });
  it('supports the qualified empty file and paired binary fields without inventing counts', () => {
    assert.deepEqual(
      parseUntrackedDiffOutput(frame('0', '0', file, ''), file),
      {
        insertions: 0,
        deletions: 0,
        patch: '',
        binary: false,
        filesChanged: 1,
      },
    );
    assert.deepEqual(parseUntrackedDiffOutput(frame('-', '-'), file), {
      insertions: 0,
      deletions: 0,
      binary: true,
      filesChanged: 1,
      patch: '+opaque\n',
    });
  });
  const malformed = [
    '',
    '\0',
    '0\t0\tfile\0\0',
    frame('-1'),
    frame('+1'),
    frame('01'),
    frame('1.5'),
    frame('1e3'),
    frame('9007199254740992'),
    frame('9'.repeat(100)),
    frame('NaN'),
    frame('Infinity'),
    frame('-', '0'),
    frame('1', '-'),
    frame('1', '0', 'other'),
    '2\t0\t\0/other\0' + file + '\0\0patch',
    '2\t0\t\0/dev/null\0' + file + '\0',
    '2\t0\t\0/dev/null\0' + file + '\0' + '3\t0\t\0/dev/null\0other\0\0patch',
    '2\t0\t\0/dev/null\0' + file + '\0Xpatch',
    '2\t0\t\0/dev/null\0\0patch',
  ];
  for (const [index, output] of malformed.entries()) {
    it(`rejects malformed, unqualified, conflicting or extra prefix ${index}`, () => {
      assert.throws(
        () => parseUntrackedDiffOutput(output, file),
        /Invalid combined untracked Git diff output\./,
      );
    });
  }
  it('rejects every truncated prefix without scanning the body for a replacement marker', () => {
    const completePrefix = frame('2', '0', file, '');
    for (let length = 0; length < completePrefix.length; length++)
      assert.throws(() =>
        parseUntrackedDiffOutput(completePrefix.slice(0, length), file),
      );
  });
  it('enforces byte bounds and exact literal paths before returning any result', () => {
    assert.throws(() => parseUntrackedDiffOutput(frame(), file, 8));
    assert.throws(() =>
      parseUntrackedDiffOutput(frame(), file, Number.POSITIVE_INFINITY),
    );
    assert.throws(() => parseUntrackedDiffOutput(frame(), 'a\0b'));
    assert.throws(() => parseUntrackedDiffOutput(frame(), '\ud800'));
    assert.throws(() => parseUntrackedDiffOutput(frame(), 'x'.repeat(32769)));
    assert.throws(() =>
      parseUntrackedDiffOutput(frame('2', '0', file.toUpperCase()), file),
    );
  });
});
