/**
 * @fileoverview Installed Git byte qualification before combined-producer wiring.
 * @module tests/security/untracked-diff-native-proof.test
 */
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { buildTrustedGitEnvironment } from '@/services/git/providers/cli/utils/execution-policy.js';
import { parseGitDiffStat } from '@/services/git/providers/cli/utils/output-parser.js';
import { parseUntrackedDiffOutput } from '@/services/git/providers/cli/utils/untracked-diff-output.js';

describe('installed Git combined untracked qualification', () => {
  let temporary: string;
  let home: string;
  let repository: string;
  let env: Record<string, string>;
  const native = (args: string[]) => {
    const result = spawnSync('/usr/bin/git', args, {
      cwd: repository,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 1024 * 1024,
    });
    if (result.error) throw result.error;
    assert.equal(result.signal, null);
    assert.ok(result.status === 0 || result.status === 1);
    return { bytes: result.stdout, status: result.status };
  };
  const setting = (key: string, value: string) => {
    const result = native(['config', key, value]);
    assert.equal(result.status, 0);
  };
  const quote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
  const driver = (name: string, output: string) => {
    const log = join(temporary, `${name}.calls`);
    const binary = join(temporary, name);
    writeFileSync(
      binary,
      `#!/bin/sh\nprintf 'call\\n' >> ${quote(log)}\nprintf ${quote(output)}\n`,
      { mode: 0o700 },
    );
    return { log, binary };
  };
  const calls = (log: string) =>
    existsSync(log)
      ? readFileSync(log, 'utf8').split('\n').filter(Boolean).length
      : 0;
  beforeEach(() => {
    temporary = realpathSync(
      mkdtempSync(join(tmpdir(), 'git-untracked-proof-')),
    );
    home = join(temporary, 'home');
    repository = join(temporary, 'repository');
    mkdirSync(home, { mode: 0o700 });
    mkdirSync(repository, { mode: 0o700 });
    env = buildTrustedGitEnvironment(
      {
        profile: 'trusted',
        binaryPath: '/usr/bin/git',
        homeDirectory: home,
        helperPath: '/usr/bin:/bin',
      },
      {},
    );
    assert.equal(native(['init', '-q', '--initial-branch=main']).status, 0);
  });
  afterEach(() => rmSync(temporary, { recursive: true, force: true }));

  // This first native characterization uses the independent old patch length,
  // never a marker search through untrusted patch bytes. Production wiring is
  // held until a bounded prefix parser independently passes the same fixtures.
  const compare = (label: string, file: string, bytes: Buffer) => {
    writeFileSync(join(repository, file), bytes);
    const operand = file.startsWith('-') ? `./${file}` : file;
    const oldPatch = native(['diff', '--no-index', '/dev/null', operand]);
    const oldStat = native([
      'diff',
      '--no-index',
      '--stat',
      '/dev/null',
      operand,
    ]);
    const combined = native([
      'diff',
      '--no-index',
      '--numstat',
      '-z',
      '--patch',
      '--',
      '/dev/null',
      operand,
    ]);
    assert.equal(combined.status, oldPatch.status);
    assert.ok(combined.bytes.length >= oldPatch.bytes.length);
    const prefixLength = combined.bytes.length - oldPatch.bytes.length;
    assert.ok(prefixLength < 4096);
    assert.deepEqual(combined.bytes.subarray(prefixLength), oldPatch.bytes);
    const stats = parseGitDiffStat(
      new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(
        oldStat.bytes,
      ),
    );
    const decoded = new TextDecoder('utf-8', {
      fatal: true,
      ignoreBOM: true,
    }).decode(combined.bytes);
    const parsed = parseUntrackedDiffOutput(decoded, operand);
    assert.deepEqual(Buffer.from(parsed.patch, 'utf8'), oldPatch.bytes);
    assert.equal(parsed.insertions, stats.totalAdditions);
    assert.equal(parsed.deletions, stats.totalDeletions);
    assert.equal(parsed.filesChanged, 1);
    assert.ok(oldStat.bytes.includes(Buffer.from('1 file changed')));
    console.info(
      JSON.stringify({
        label,
        operand,
        prefixHex: combined.bytes.subarray(0, prefixLength).toString('hex'),
        patchBytes: oldPatch.bytes.length,
        additions: stats.totalAdditions,
        deletions: stats.totalDeletions,
        oldStatFiles: stats.files.length,
      }),
    );
    return {
      oldPatch: oldPatch.bytes,
      oldStat: oldStat.bytes,
      combined: combined.bytes,
    };
  };

  for (const [label, file, bytes] of [
    ['plain', 'plain.txt', Buffer.from('line one\nline two\n')],
    ['empty', 'empty.txt', Buffer.alloc(0)],
    ['no-final-newline', 'tail.txt', Buffer.from('unterminated')],
    ['binary', 'binary.dat', Buffer.from([0, 1, 2, 255])],
    [
      'unicode-bom',
      '日本語.txt',
      Buffer.from('\ufeffliteral \ufffd\nстрока\n'),
    ],
    ['tab', 'tab\tname.txt', Buffer.from('tab-name\n')],
    ['newline', 'line\nname.txt', Buffer.from('newline-name\n')],
    ['control', 'control\x01name.txt', Buffer.from('control-name\n')],
    ['magic', ':(literal):(exclude)name', Buffer.from('literal-magic\n')],
    ['flaglike', '-p', Buffer.from('literal-flaglike\n')],
  ] as const) {
    it(`characterizes ${label} exact suffix and old native stats`, () => {
      compare(label, file, bytes);
    });
  }

  it('proves color activation and exact colored suffix preservation', () => {
    setting('color.diff', 'always');
    const result = compare(
      'active-color',
      'color.txt',
      Buffer.from('colored\n'),
    );
    assert.ok(result.oldPatch.includes(Buffer.from('\x1b[')));
  });

  it('proves native prefix activation and exact suffix preservation', () => {
    setting('diff.noprefix', 'true');
    const result = compare(
      'active-noprefix',
      'prefix.txt',
      Buffer.from('prefix\n'),
    );
    assert.ok(result.oldPatch.includes(Buffer.from('+++ prefix.txt\n')));
    assert.ok(!result.oldPatch.includes(Buffer.from('+++ b/prefix.txt\n')));
  });

  it('proves binary attribute activation and native stats equivalence', () => {
    writeFileSync(join(repository, '.gitattributes'), 'attribute.txt -diff\n');
    const result = compare(
      'active-binary-attribute',
      'attribute.txt',
      Buffer.from('ordinary text\n'),
    );
    assert.ok(result.oldPatch.includes(Buffer.from('Binary files')));
  });

  it('qualifies actual configured external-driver activation without adding baseline flags', () => {
    const external = driver('external-driver', 'operator-driver\\0opaque\\n');
    setting('diff.external', external.binary);
    const result = compare(
      'external-config',
      'external.txt',
      Buffer.from('external-source\n'),
    );
    const count = calls(external.log);
    assert.equal(count, 2, 'old patch and combined must activate the driver');
    assert.ok(
      result.oldPatch.includes(Buffer.from('operator-driver\0opaque\n')),
    );
    console.info(
      `external actualInvocations=${count}; ${count ? 'ACTIVE' : 'N/A: unchanged baseline flags did not activate configured driver'}`,
    );
  });

  it('qualifies actual textconv activation without adding baseline flags', () => {
    const converter = driver('textconv-driver', 'CONVERTED\\n');
    setting('diff.qualification.textconv', converter.binary);
    writeFileSync(
      join(repository, '.gitattributes'),
      'converted.txt diff=qualification\n',
    );
    const result = compare(
      'textconv-config',
      'converted.txt',
      Buffer.from('raw one\nraw two\n'),
    );
    const count = calls(converter.log);
    assert.equal(count, 2, 'old patch and combined must activate textconv');
    assert.ok(result.oldPatch.includes(Buffer.from('+CONVERTED\n')));
    console.info(
      `textconv actualInvocations=${count}; ${count ? 'ACTIVE' : 'N/A: unchanged baseline flags did not activate configured converter'}`,
    );
  });

  it('records word-regex applicability without manufacturing a baseline word-diff mode', () => {
    setting('diff.wordRegex', '[A-Z]+');
    const result = compare(
      'word-regex-config',
      'word.txt',
      Buffer.from('WORD one\nWORD two\n'),
    );
    assert.ok(result.oldPatch.includes(Buffer.from('+WORD one\n+WORD two\n')));
    console.info(
      'wordRegex N/A as active word-diff coverage: unchanged baseline requests unified patch, not word-diff',
    );
  });
});
