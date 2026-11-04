/**
 * @fileoverview Native X.509 verifier oracle with isolated ephemeral certificates.
 * @module tests/security/x509-signature-oracle
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'bun:test';
import { executeTag } from '@/services/git/providers/cli/operations/tags/tag.js';
import { verifySignatureStatus } from '@/services/git/providers/cli/utils/signature-verification.js';

describe('native X.509 verifier policy', () => {
  let root: string;
  let signer: string;
  let rejected: string;
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
    if (result.error || result.signal || result.status === null)
      throw new Error('X.509 fixture process failed');
    if (!allowFailure && result.status !== 0)
      throw new Error(
        `X.509 fixture command failed (exit ${result.status}): ${result.stderr.slice(0, 2048).replaceAll(root, '<fixture>')}`,
      );
    return {
      stdout: result.stdout,
      stderr: result.stderr,
      exitCode: result.status,
    };
  }

  function verify(home: string, object = 'signed') {
    return command(
      'git',
      ['-c', 'gpg.format=x509', 'verify-tag', '--raw', object],
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
    root = mkdtempSync(join(tmpdir(), 'g5-x509-'));
    signer = join(root, 'signer');
    rejected = join(root, 'rejected');
    env = {
      PATH: process.env.PATH ?? '',
      HOME: root,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_TERMINAL_PROMPT: '0',
    };
    for (const home of [signer, rejected]) {
      mkdirSync(home, { mode: 0o700 });
      // Offline fixture policy only: production native verifier config is untouched.
      writeFileSync(
        join(home, 'gpgsm.conf'),
        'disable-dirmngr\ndisable-crl-checks\npinentry-mode loopback\n',
        { mode: 0o600 },
      );
      writeFileSync(join(home, 'gpg-agent.conf'), 'no-allow-mark-trusted\n', {
        mode: 0o600,
      });
    }
    const key = join(root, 'fixture-key.pem');
    const cert = join(root, 'fixture-cert.pem');
    const bundle = join(root, 'fixture.p12');
    command(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-sha256',
        '-noenc',
        '-days',
        '1',
        '-subj',
        '/CN=Ephemeral Fixture/emailAddress=fixture@example.invalid',
        '-addext',
        'basicConstraints=critical,CA:TRUE',
        '-addext',
        'keyUsage=critical,digitalSignature,keyCertSign,cRLSign',
        '-keyout',
        key,
        '-out',
        cert,
      ],
      signer,
    );
    fingerprint = command(
      'openssl',
      ['x509', '-in', cert, '-noout', '-fingerprint', '-sha1'],
      signer,
    )
      .stdout.split('=')[1]!
      .replaceAll(':', '')
      .trim();
    if (!/^[0-9A-F]{40}$/.test(fingerprint))
      throw new Error('X.509 fixture fingerprint unavailable');
    writeFileSync(join(signer, 'trustlist.txt'), `${fingerprint} S\n`, {
      mode: 0o600,
    });
    writeFileSync(join(rejected, 'trustlist.txt'), `!${fingerprint} S\n`, {
      mode: 0o600,
    });
    command(
      'openssl',
      [
        'pkcs12',
        '-export',
        '-inkey',
        key,
        '-in',
        cert,
        '-out',
        bundle,
        '-passout',
        'pass:',
      ],
      signer,
    );
    command(
      'gpgsm',
      [
        '--batch',
        '--pinentry-mode',
        'loopback',
        '--passphrase',
        '',
        '--import',
        bundle,
      ],
      signer,
    );
    command('gpgsm', ['--batch', '--import', cert], rejected);
    command('git', ['init', '-b', 'main', '--template='], signer);
    command('git', ['config', 'user.name', 'Ephemeral Fixture'], signer);
    command('git', ['config', 'user.email', 'fixture@example.invalid'], signer);
    command('git', ['config', 'core.hooksPath', '/dev/null'], signer);
    command('git', ['config', 'commit.gpgSign', 'false'], signer);
    command('git', ['config', 'gpg.format', 'x509'], signer);
    command('git', ['config', 'user.signingKey', fingerprint], signer);
    command('git', ['commit', '--allow-empty', '-m', 'Fixture'], signer);
    command('git', ['tag', '-s', '-m', 'Signed fixture', 'signed'], signer);
  }, 45_000);

  afterAll(() => {
    try {
      for (const home of [signer, rejected])
        if (home)
          command('gpgconf', ['--homedir', home, '--kill', 'all'], home);
    } finally {
      if (root) rmSync(root, { recursive: true, force: true });
    }
  }, 30_000);

  it('requires real successful CMS verification and the explicitly trusted fixture root', async () => {
    const result = verify(signer);
    expect(result.exitCode).toBe(0);
    expect(
      verifySignatureStatus(result.stderr, result.exitCode, 'x509'),
    ).toMatchObject({
      verified: true,
      cryptographicallyValid: true,
      trust: 'trusted',
      signatureType: 'x509',
      signerKey: fingerprint,
    });
    expect(await verifyConsumer(signer)).toMatchObject({
      verified: true,
      cryptographicallyValid: true,
      trust: 'trusted',
      signatureType: 'x509',
      signerKey: fingerprint,
    });
  });

  it('preserves rejection by the native trust policy even when a certificate is present', async () => {
    const result = verify(rejected);
    expect(result.exitCode).not.toBe(0);
    const parsed = verifySignatureStatus(
      result.stderr,
      result.exitCode,
      'x509',
    );
    expect(parsed.verified).toBe(false);
    expect(parsed.trust).not.toBe('trusted');
    expect((await verifyConsumer(rejected)).verified).toBe(false);
  });

  it('rejects a real signed tag whose message bytes were modified', async () => {
    const object = command('git', ['cat-file', 'tag', 'signed'], signer).stdout;
    const modified = object.replace('Signed fixture', 'Tampered fixture');
    expect(modified).not.toBe(object);
    const id = command(
      'git',
      ['hash-object', '-t', 'tag', '-w', '--stdin'],
      signer,
      modified,
    ).stdout.trim();
    command('git', ['update-ref', 'refs/tags/tampered', id], signer);
    const result = verify(signer, id);
    expect(result.exitCode).not.toBe(0);
    expect(
      verifySignatureStatus(result.stderr, result.exitCode, 'x509').verified,
    ).toBe(false);
    expect((await verifyConsumer(signer, 'tampered')).verified).toBe(false);
  });
});
