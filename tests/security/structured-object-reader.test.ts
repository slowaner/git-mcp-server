/**
 * @fileoverview Real Git object and SSH verifier oracles for structured readers.
 * @module tests/security/structured-object-reader
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
import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import { parseObjectIds } from '@/services/git/providers/cli/utils/git-object-reader.js';
import {
  parseTagReferences,
  readCommitRecord,
  readTagRecord,
} from '@/services/git/providers/cli/utils/structured-object-reader.js';
import { verifySignatureStatus } from '@/services/git/providers/cli/utils/signature-verification.js';
import { createWithSigningPolicy } from '@/services/git/providers/cli/utils/signing-policy.js';

describe('native Git identity and verification oracles', () => {
  let root: string;
  let env: Record<string, string>;
  const hostile =
    'Real subject\n\n<<<COMMIT_START>>>\x1f' +
    'f'.repeat(40) +
    '\x1fFake author<<<COMMIT_END>>>\x1e\n\nbody end\n\n';

  function git(
    args: string[],
    allowFailure = false,
  ): { stdout: string; stderr: string; exitCode: number } {
    const result = spawnSync('git', args, {
      cwd: root,
      env,
      encoding: 'utf8',
      timeout: 10_000,
    });
    if (result.error || result.signal || result.status === null)
      throw new Error('Git fixture process failed');
    if (!allowFailure && result.status !== 0)
      throw new Error(
        `Git fixture command failed (${args[0]}, exit ${result.status})`,
      );
    return {
      stdout: result.stdout,
      stderr: result.stderr,
      exitCode: result.status,
    };
  }

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), 'git-record-integrity-'));
    env = {
      PATH: process.env.PATH ?? '',
      HOME: root,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_TERMINAL_PROMPT: '0',
    };
    git(['init', '-b', 'main', '--template=']);
    git(['config', 'user.name', 'Real Author']);
    git(['config', 'user.email', 'real@example.invalid']);
    git(['config', 'core.hooksPath', '/dev/null']);
    git(['config', 'commit.gpgSign', 'false']);
    writeFileSync(join(root, 'message'), hostile);
    git(['commit', '--allow-empty', '--cleanup=verbatim', '-F', 'message']);
    git(['tag', '--cleanup=verbatim', '-a', 'annotated', '-F', 'message']);
    git(['tag', 'lightweight']);
  });

  afterAll(() => {
    if (root) rmSync(root, { recursive: true, force: true });
  });

  it('matches independent rev-list identity/count and preserves exact commit body', async () => {
    const ids = parseObjectIds(git(['rev-list', 'HEAD']).stdout);
    const records = await Promise.all(
      ids.map((id) => readCommitRecord(id, async (args) => git(args))),
    );
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      hash: git(['rev-parse', 'HEAD']).stdout.trim(),
      author: 'Real Author',
      authorEmail: 'real@example.invalid',
      subject: 'Real subject',
      body: hostile.slice('Real subject\n\n'.length),
    });
  });

  it('matches ref identity/count with hostile tag content, alias and lightweight tags', async () => {
    git(['tag', 'alias', 'annotated']);
    const refs = parseTagReferences(
      git([
        'for-each-ref',
        '--format=%(refname)%00%(objectname)%00%(objecttype)',
        'refs/tags',
      ]).stdout,
    );
    const records = await Promise.all(
      refs.map((ref) => readTagRecord(ref, async (args) => git(args))),
    );
    expect(records.map((record) => record.name)).toEqual([
      'alias',
      'annotated',
      'lightweight',
    ]);
    const head = git(['rev-parse', 'HEAD']).stdout.trim();
    for (const record of records) expect(record.commit).toBe(head);
    expect(records[1]).toMatchObject({
      name: 'annotated',
      message: 'Real subject',
      tagger: 'Real Author <real@example.invalid>',
      annotationBody: hostile.slice('Real subject\n\n'.length),
    });
    expect(records[2]?.annotationBody).toBeUndefined();
  });

  it('rejects forged reference fields and duplicate enumeration', () => {
    const id = git(['rev-parse', 'HEAD']).stdout.trim();
    for (const output of [
      `refs/tags/a\0${id}\0commit\0forged\n`,
      `refs/tags/a\0${id}\0commit\nrefs/tags/a\0${id}\0commit\n`,
      `refs/tags/a\nforged\0${id}\0commit\n`,
    ])
      expect(() => parseTagReferences(output)).toThrow();
  });

  it('requires actual SSH verifier success and its configured signer policy', () => {
    const key = join(root, 'synthetic-signing-key');
    const keygen = spawnSync(
      'ssh-keygen',
      ['-q', '-t', 'ed25519', '-N', '', '-C', 'synthetic-fixture', '-f', key],
      { cwd: root, env, encoding: 'utf8', timeout: 10_000 },
    );
    if (keygen.error || keygen.status !== 0)
      throw new Error('SSH verifier fixture unavailable');
    const signers = join(root, 'allowed-signers');
    writeFileSync(
      signers,
      `real@example.invalid ${readFileSync(`${key}.pub`, 'utf8')}`,
    );
    git([
      '-c',
      'gpg.format=ssh',
      '-c',
      'gpg.ssh.program=ssh-keygen',
      '-c',
      `user.signingKey=${key}`,
      'tag',
      '-s',
      '-m',
      'Signed fixture',
      'signed',
    ]);
    const verify = (): ReturnType<typeof git> =>
      git(
        [
          '-c',
          'gpg.format=ssh',
          '-c',
          'gpg.ssh.program=ssh-keygen',
          '-c',
          `gpg.ssh.allowedSignersFile=${signers}`,
          'verify-tag',
          '--raw',
          'signed',
        ],
        true,
      );
    const good = verify();
    expect(good.exitCode).toBe(0);
    expect(
      verifySignatureStatus(good.stderr, good.exitCode, 'ssh'),
    ).toMatchObject({
      verified: true,
      signatureType: 'ssh',
      trust: 'trusted',
    });
    writeFileSync(signers, '');
    const bad = verify();
    expect(bad.exitCode).not.toBe(0);
    expect(
      verifySignatureStatus(bad.stderr, bad.exitCode, 'ssh').verified,
    ).toBe(false);
  });

  it('does not repeat real pre-commit hook effects or create unsigned history on strict signer failure', async () => {
    const hooks = join(root, 'hooks');
    const counter = join(root, 'hook-counter');
    mkdirSync(hooks);
    writeFileSync(
      join(hooks, 'pre-commit'),
      '#!/bin/sh\nprintf "hook\\n" >> "$G5_HOOK_COUNTER"\n',
      { mode: 0o700 },
    );
    const before = git(['rev-parse', 'HEAD']).stdout;
    env.G5_HOOK_COUNTER = counter;
    let inspections = 0;
    await expect(
      createWithSigningPolicy(
        'required',
        async (requireSigning) => {
          expect(requireSigning).toBe(true);
          git([
            '-c',
            `core.hooksPath=${hooks}`,
            '-c',
            'gpg.format=openpgp',
            '-c',
            'gpg.program=/usr/bin/false',
            'commit',
            '--allow-empty',
            '--gpg-sign',
            '-m',
            'Must remain uncreated',
          ]);
        },
        async () => {
          inspections++;
          return { signed: false };
        },
      ),
    ).rejects.toThrow(/fixture command failed/);
    expect(readFileSync(counter, 'utf8')).toBe('hook\n');
    expect(git(['rev-parse', 'HEAD']).stdout).toBe(before);
    expect(inspections).toBe(0);
    delete env.G5_HOOK_COUNTER;
  });
});
