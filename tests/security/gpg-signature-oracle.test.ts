/**
 * @fileoverview Native OpenPGP tag verification with isolated ephemeral keyrings.
 * @module tests/security/gpg-signature-oracle
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'bun:test';
import { executeTag } from '@/services/git/providers/cli/operations/tags/tag.js';
import { verifySignatureStatus } from '@/services/git/providers/cli/utils/signature-verification.js';

describe('native OpenPGP verifier policy', () => {
  let root: string;
  let signer: string;
  let imported: string;
  let empty: string;
  let fingerprint: string;
  let env: Record<string, string>;

  function command(
    program: string,
    args: string[],
    home: string,
    input?: string,
    allowFailure = false,
  ) {
    const result = spawnSync(program, args, {
      cwd: root,
      env: { ...env, GNUPGHOME: home },
      input,
      encoding: 'utf8',
      timeout: 15_000,
    });
    if (result.error || result.signal || result.status === null) {
      const reason = /Operation not permitted|Permission denied/.test(
        result.stderr ?? '',
      )
        ? 'permission'
        : result.error &&
            'code' in result.error &&
            result.error.code === 'ETIMEDOUT'
          ? 'deadline'
          : result.signal
            ? 'signal'
            : 'spawn';
      throw new Error(`OpenPGP fixture process failed (${reason})`);
    }
    if (!allowFailure && result.status !== 0)
      throw new Error(
        `OpenPGP fixture command failed (exit ${result.status}): ${result.stderr
          .slice(0, 2048)
          .replaceAll(root, '<fixture>')}`,
      );
    return {
      stdout: result.stdout,
      stderr: result.stderr,
      exitCode: result.status,
    };
  }

  function verify(home: string) {
    return command(
      'git',
      ['-c', 'gpg.format=openpgp', 'verify-tag', '--raw', 'signed'],
      home,
      undefined,
      true,
    );
  }

  // Exercise the real consumer with the same isolated native verifier fixture.
  // Executor confinement/strict decoding are covered separately by its own
  // production profile; this oracle binds immutable framing to native trust.
  function verifyConsumer(home: string, tagName = 'signed') {
    return executeTag(
      { mode: 'verify', tagName },
      {
        workingDirectory: root,
        requestContext: {
          requestId: 'native-verifier-fixture',
          timestamp: new Date().toISOString(),
        },
      },
      async (args) => command('git', args, home, undefined, true),
    );
  }

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), 'g5-gpg-'));
    signer = join(root, 'signer');
    imported = join(root, 'imported');
    empty = join(root, 'empty');
    for (const home of [signer, imported, empty])
      mkdirSync(home, { mode: 0o700 });
    env = {
      PATH: process.env.PATH ?? '',
      HOME: root,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_TERMINAL_PROMPT: '0',
    };
    command(
      'gpg',
      [
        '--batch',
        '--pinentry-mode',
        'loopback',
        '--passphrase',
        '',
        '--quick-generate-key',
        'Ephemeral Fixture <fixture@example.invalid>',
        'ed25519',
        'sign',
        '0',
      ],
      signer,
    );
    fingerprint = command('gpg', ['--with-colons', '--list-keys'], signer)
      .stdout.split('\n')
      .find((line) => line.startsWith('fpr:'))!
      .split(':')[9]!;
    if (!/^[0-9A-F]{40}$/.test(fingerprint))
      throw new Error('OpenPGP fixture fingerprint unavailable');
    command('git', ['init', '-b', 'main', '--template='], signer);
    command('git', ['config', 'user.name', 'Ephemeral Fixture'], signer);
    command('git', ['config', 'user.email', 'fixture@example.invalid'], signer);
    command('git', ['config', 'core.hooksPath', '/dev/null'], signer);
    command('git', ['config', 'commit.gpgSign', 'false'], signer);
    command('git', ['config', 'user.signingKey', fingerprint], signer);
    command('git', ['commit', '--allow-empty', '-m', 'Fixture'], signer);
    command('git', ['tag', '-s', '-m', 'Signed fixture', 'signed'], signer);
    const publicKey = command(
      'gpg',
      ['--armor', '--export', fingerprint],
      signer,
    );
    command('gpg', ['--batch', '--import'], imported, publicKey.stdout);
  }, 30_000);

  afterAll(() => {
    try {
      for (const home of [signer, imported, empty])
        if (home)
          command('gpgconf', ['--homedir', home, '--kill', 'all'], home);
    } finally {
      if (root) rmSync(root, { recursive: true, force: true });
    }
  }, 30_000);

  it('requires native success and reports trusted signer separately', async () => {
    const result = verify(signer);
    expect(result.exitCode).toBe(0);
    expect(
      verifySignatureStatus(result.stderr, result.exitCode, 'gpg'),
    ).toEqual({
      verified: true,
      cryptographicallyValid: true,
      signatureType: 'gpg',
      signerKey: fingerprint,
      trust: 'trusted',
    });
    expect(await verifyConsumer(signer)).toMatchObject({
      verified: true,
      cryptographicallyValid: true,
      trust: 'trusted',
      signatureType: 'gpg',
      signerKey: fingerprint,
    });
  });

  it('preserves native cryptographic acceptance without claiming imported-key trust', async () => {
    const result = verify(imported);
    expect(result.exitCode).toBe(0);
    expect(
      verifySignatureStatus(result.stderr, result.exitCode, 'gpg'),
    ).toEqual({
      verified: true,
      cryptographicallyValid: true,
      signatureType: 'gpg',
      signerKey: fingerprint,
      trust: 'untrusted',
    });
    expect(await verifyConsumer(imported)).toMatchObject({
      verified: true,
      cryptographicallyValid: true,
      trust: 'untrusted',
      signatureType: 'gpg',
    });
  });

  it('rejects an unavailable public key without treating signature presence as verification', async () => {
    const result = verify(empty);
    expect(result.exitCode).not.toBe(0);
    expect(
      verifySignatureStatus(result.stderr, result.exitCode, 'gpg'),
    ).toEqual({
      verified: false,
      cryptographicallyValid: false,
      trust: 'unknown',
    });
    expect((await verifyConsumer(empty)).verified).toBe(false);
  });
});
