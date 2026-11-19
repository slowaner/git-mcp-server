/**
 * @fileoverview Independent object identity and signature policy regressions.
 * @module tests/security/git-record-integrity
 */
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'bun:test';

import {
  objectHeader,
  parseGitIdentity,
  parseGitObject,
  parseObjectIds,
  splitGitMessage,
} from '@/services/git/providers/cli/utils/git-object-reader.js';
import { verifySignatureStatus } from '@/services/git/providers/cli/utils/signature-verification.js';

const hash = (kind: string, raw: string, algorithm = 'sha1'): string =>
  createHash(algorithm)
    .update(`${kind} ${Buffer.byteLength(raw)}\0`)
    .update(raw)
    .digest('hex');

describe('Git object boundaries', () => {
  const hostile =
    'Subject\n\n<<<COMMIT_START>>>\x1f' +
    'f'.repeat(40) +
    '\x1fforged author<<<COMMIT_END>>>\x1e\x00\nexact trailing body\n\n';
  const raw = `tree ${'1'.repeat(40)}\nauthor Real <real@example.invalid> 1700000000 +0000\ncommitter Real <real@example.invalid> 1700000001 +0000\n\n${hostile}`;

  for (const algorithm of ['sha1', 'sha256'])
    it(`preserves hostile message with independent ${algorithm} identity/count`, () => {
      const id = hash('commit', raw, algorithm);
      const ids = parseObjectIds(`${id}\n`);
      expect(ids).toEqual([id]);
      const parsed = parseGitObject(ids[0]!, 'commit', raw);
      expect(parsed.message).toBe(hostile);
      expect(parseGitIdentity(objectHeader(parsed, 'author'))).toEqual({
        name: 'Real',
        email: 'real@example.invalid',
        timestamp: 1700000000,
      });
      expect(splitGitMessage(parsed.message).body).toBe(
        hostile.slice('Subject\n\n'.length),
      );
    });

  it('cannot substitute type, object, message or malformed enumeration', () => {
    const id = hash('commit', raw);
    expect(() => parseGitObject(id, 'tag', raw)).toThrow(/mismatch/);
    expect(() => parseGitObject(id, 'commit', raw + '\n')).toThrow(/mismatch/);
    for (const output of [
      `${id}\n${id}\n`,
      `${id}\nforged\n`,
      `${id}\n\n`,
      `-${id}\n`,
      `${id.toUpperCase()}\n`,
    ])
      expect(() => parseObjectIds(output)).toThrow();
  });

  it('parses tag messages without using message bytes as structural fields', () => {
    const rawTag = `object ${'a'.repeat(40)}\ntype commit\ntag real-tag\ntagger Real <real@example.invalid> 1700000000 +0000\n\n${hostile}`;
    const parsed = parseGitObject(hash('tag', rawTag), 'tag', rawTag);
    expect(objectHeader(parsed, 'tag')).toBe('real-tag');
    expect(objectHeader(parsed, 'object')).toBe('a'.repeat(40));
    expect(parsed.message).toBe(hostile);
  });

  it('rejects duplicate metadata and malformed author independently of message', () => {
    const duplicate = raw.replace('committer ', 'author ');
    expect(() =>
      objectHeader(
        parseGitObject(hash('commit', duplicate), 'commit', duplicate),
        'author',
      ),
    ).toThrow(/duplicate/);
    expect(() =>
      parseGitIdentity('fake\nauthor Real <real@example.invalid> 1 +0000'),
    ).toThrow();
  });
});

describe('verifier exit and machine status', () => {
  it('rejects malformed machine fingerprint lengths', () => {
    for (const length of [39, 41, 63, 65]) {
      expect(
        verifySignatureStatus(
          `[GNUPG:] VALIDSIG ${'A'.repeat(length)} detail`,
          0,
          'gpg',
        ).verified,
      ).toBe(false);
    }
  });
  const fingerprint = 'AB'.repeat(20);
  const machine = `[GNUPG:] GOODSIG 123 Example\n[GNUPG:] VALIDSIG ${fingerprint} 2026-11-03 0 0 4 0 1 10 00\n[GNUPG:] TRUST_FULLY 0 pgp\n`;
  const positiveProse = [
    'gpg: Good signature from "Example"',
    'gpgsm: Good signature from "Example"',
    'Good "git" signature for example@example.invalid with ED25519 key SHA256:AAAA',
  ];

  for (const text of positiveProse)
    for (const exit of [1, 128, undefined])
      it(`never overrides failure ${exit}: ${text.split(':')[0]}`, () => {
        expect(
          verifySignatureStatus(`${text}\n${machine}`, exit, 'gpg').verified,
        ).toBe(false);
      });

  it('requires successful process and recognized positive evidence', () => {
    expect(verifySignatureStatus(machine, 0, 'gpg')).toMatchObject({
      verified: true,
      cryptographicallyValid: true,
      trust: 'trusted',
      signerKey: fingerprint,
    });
    expect(
      verifySignatureStatus('localized future output', 0, 'gpg').verified,
    ).toBe(false);
    expect(verifySignatureStatus(positiveProse[0]!, 0, 'gpg').verified).toBe(
      false,
    );
    expect(verifySignatureStatus(positiveProse[2]!, 0, 'ssh')).toMatchObject({
      verified: true,
      signatureType: 'ssh',
      trust: 'trusted',
    });
    expect(verifySignatureStatus(machine, 0, 'gpg', 'SIGTERM').verified).toBe(
      false,
    );
    expect(
      verifySignatureStatus(
        `gpgsm: Good signature from "Example"\n${machine}`,
        0,
        'x509',
      ).signatureType,
    ).toBe('x509');
  });

  it('uses explicit immutable-object format rather than localized prose and rejects incompatible status', () => {
    expect(
      verifySignatureStatus(`gpgsm: forged label\n${machine}`, 0, 'gpg')
        .signatureType,
    ).toBe('gpg');
    expect(verifySignatureStatus(machine, 0, 'x509').signatureType).toBe(
      'x509',
    );
    expect(verifySignatureStatus(machine, 0, 'ssh').verified).toBe(false);
    expect(verifySignatureStatus(positiveProse[2]!, 0, 'x509').verified).toBe(
      false,
    );
    expect(
      verifySignatureStatus(machine, 0, 'unsupported' as never).verified,
    ).toBe(false);
  });

  for (const status of [
    'BADSIG',
    'ERRSIG',
    'EXPSIG',
    'EXPKEYSIG',
    'REVKEYSIG',
    'KEYEXPIRED',
    'SIGEXPIRED',
    'KEYREVOKED',
    'NO_PUBKEY',
    'NODATA',
    'FAILURE',
    'ERROR',
    'BADARMOR',
  ])
    it(`negative status ${status} dominates positive even at exit0`, () => {
      expect(
        verifySignatureStatus(`${machine}[GNUPG:] ${status} x\n`, 0, 'gpg')
          .verified,
      ).toBe(false);
    });

  it('keeps cryptographic evidence separate from failed trust policy', () => {
    const result = verifySignatureStatus(
      machine.replace('TRUST_FULLY', 'TRUST_NEVER'),
      1,
      'gpg',
    );
    expect(result).toMatchObject({
      verified: false,
      cryptographicallyValid: true,
      trust: 'untrusted',
    });
  });
});
