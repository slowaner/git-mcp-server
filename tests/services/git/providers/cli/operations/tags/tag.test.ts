/**
 * @fileoverview Immutable tag records, native signing and verifier exit policy.
 * @module tests/services/git/providers/cli/operations/tags/tag.test
 */
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { config } from '@/config/index.js';
import { executeTag } from '@/services/git/providers/cli/operations/tags/tag.js';
import { shouldSignCommits } from '@/services/git/providers/cli/utils/index.js';
import {
  commitFixture,
  tagFixture,
} from '../../../../../../security/helpers/git-object-fixture.js';
import type {
  GitOperationContext,
  GitTagOptions,
} from '@/services/git/types.js';
import type { RequestContext } from '@/utils/index.js';

describe('executeTag', () => {
  const context: GitOperationContext = {
    workingDirectory: '/fixture/repository',
    requestContext: { requestId: 'fixture' } as RequestContext,
  };
  const commit = commitFixture();
  let saved: boolean, nativeSigning: boolean, lightweight: boolean;
  let object: ReturnType<typeof tagFixture>,
    verification: { stdout: string; stderr: string; exitCode?: number };
  let configCode: number,
    inspectionMissing: boolean,
    failCommand: string | undefined;
  const calls: { args: string[]; soft?: boolean }[] = [];
  const execute = vi.fn(
    async (
      args: string[],
      _cwd: string,
      _ctx: RequestContext,
      options?: { allowNonZeroExit?: boolean },
    ) => {
      calls.push({
        args,
        ...(options?.allowNonZeroExit ? { soft: true } : {}),
      });
      if (args[0] === failCommand) throw new Error('fixture operation failed');
      if (args[0] === 'config')
        return {
          stdout: nativeSigning ? 'true\n' : '',
          stderr: '',
          exitCode: configCode,
        };
      if (args[0] === 'for-each-ref')
        return {
          stdout: inspectionMissing
            ? ''
            : 'refs/tags/v1\0' +
              (lightweight ? commit.id : object.id) +
              '\0' +
              (lightweight ? 'commit' : 'tag') +
              '\n',
          stderr: '',
          exitCode: 0,
        };
      if (args[0] === 'cat-file')
        return { stdout: object.raw, stderr: '', exitCode: 0 };
      if (args[0] === 'verify-tag') return verification;
      return { stdout: '', stderr: '', exitCode: 0 };
    },
  );
  const run = (options: GitTagOptions) => executeTag(options, context, execute);
  beforeEach(() => {
    saved = config.git.signCommits;
    config.git.signCommits = false;
    nativeSigning = false;
    lightweight = false;
    configCode = 1;
    inspectionMissing = false;
    failCommand = undefined;
    calls.length = 0;
    execute.mockClear();
    object = tagFixture(commit.id, 'subject\n\nannotation\n');
    verification = { stdout: '', stderr: '', exitCode: 1 };
  });
  afterEach(() => {
    config.git.signCommits = saved;
  });

  it('lists complete identities without message-delimited records', async () => {
    const result = await run({ mode: 'list' });
    expect(result.tags).toEqual([
      {
        name: 'v1',
        commit: commit.id,
        message: 'subject',
        annotationBody: 'annotation\n',
        tagger: 'Tag Fixture <tag@example.invalid>',
        timestamp: 1700000000,
      },
    ]);
    expect(calls[0]!.args).toContain(
      '--format=%(refname)%00%(objectname)%00%(objecttype)',
    );
    expect(calls[0]!.args.indexOf('--sort=-version:refname')).toBeLessThan(
      calls[0]!.args.indexOf('--sort=-creatordate'),
    );
  });
  it('returns an empty array without object reads when no tags exist', async () => {
    inspectionMissing = true;
    expect(await run({ mode: 'list' })).toEqual({ mode: 'list', tags: [] });
    expect(calls).toHaveLength(1);
  });
  it('applies the bounded list limit at native enumeration', async () => {
    await run({ mode: 'list', limit: 2 });
    expect(calls[0]!.args).toContain('--count=2');
  });
  for (const limit of [0, -1, 1001])
    it('rejects unsupported list limit ' + limit, async () => {
      await expect(run({ mode: 'list', limit })).rejects.toThrow();
      expect(calls).toHaveLength(0);
    });
  it('preserves annotation body markers and trailing newlines exactly', async () => {
    const body = 'line one\n\x1f\x1e<<<COMMIT_START>>>\nline two\n';
    object = tagFixture(commit.id, 'subject\n\n' + body);
    const result = await run({ mode: 'list' });
    expect(result.tags).toHaveLength(1);
    expect(result.tags![0]!.annotationBody).toBe(body);
  });
  it('leaves a plain native tag lightweight', async () => {
    lightweight = true;
    const result = await run({ mode: 'create', tagName: 'v1' });
    expect(result).toEqual({ mode: 'create', created: 'v1', signed: false });
    expect(calls.find((call) => call.args[0] === 'tag')!.args).toEqual([
      'tag',
      '--',
      'v1',
    ]);
  });
  it('supplies a default message for configured native signing', async () => {
    nativeSigning = true;
    configCode = 0;
    await run({ mode: 'create', tagName: 'v1' });
    expect(calls.find((call) => call.args[0] === 'tag')!.args).toContain(
      '--message=Tag v1',
    );
  });
  for (const options of [{ message: '-release' }, { annotated: true }])
    it('preserves annotation intent ' + JSON.stringify(options), async () => {
      await run({ mode: 'create', tagName: 'v1', ...options });
      const args = calls.find((call) => call.args[0] === 'tag')!.args;
      expect(args).toContain(
        '--message=' + ('message' in options ? options.message : 'Tag v1'),
      );
      expect(args).not.toContain('-a');
    });
  it('preserves target and force before the option boundary', async () => {
    await run({ mode: 'create', tagName: 'v1', commit: 'HEAD~1', force: true });
    expect(calls.find((call) => call.args[0] === 'tag')!.args).toEqual([
      'tag',
      '--force',
      '--',
      'v1',
      'HEAD~1',
    ]);
  });
  for (const message of [undefined, 'custom message'])
    it('requires one explicitly signed creation ' + message, async () => {
      config.git.signCommits = true;
      expect(shouldSignCommits()).toBe(true);
      object = tagFixture(
        commit.id,
        'subject\n-----BEGIN SSH SIGNATURE-----\nbody\n-----END SSH SIGNATURE-----\n',
      );
      const result = await run({
        mode: 'create',
        tagName: 'v1',
        ...(message ? { message } : {}),
      });
      const args = calls.find((call) => call.args[0] === 'tag')!.args;
      expect(args).toContain('-s');
      expect(args).toContain('--message=' + (message ?? 'Tag v1'));
      expect(result.signed).toBe(true);
      expect(result.signingWarning).toBeUndefined();
    });
  it('does not count a lightweight target commit signature as a tag signature', async () => {
    lightweight = true;
    expect((await run({ mode: 'create', tagName: 'v1' })).signed).toBe(false);
  });
  for (const required of [true, false])
    it('never retries creation under policy ' + required, async () => {
      config.git.signCommits = required;
      failCommand = 'tag';
      await expect(
        run({ mode: 'create', tagName: 'v1', message: 'annotation' }),
      ).rejects.toThrow();
      expect(calls.filter((call) => call.args[0] === 'tag')).toHaveLength(1);
    });
  it('rejects a missing signature after strict creation without retry', async () => {
    config.git.signCommits = true;
    expect(shouldSignCommits()).toBe(true);
    await expect(
      run({ mode: 'create', tagName: 'v1', message: 'annotation' }),
    ).rejects.toThrow();
    expect(calls.filter((call) => call.args[0] === 'tag')).toHaveLength(1);
  });
  it('rejects malformed native signing configuration before creation', async () => {
    configCode = 3;
    await expect(run({ mode: 'create', tagName: 'v1' })).rejects.toThrow();
    expect(calls.filter((call) => call.args[0] === 'tag')).toHaveLength(0);
  });
  for (const failure of ['missing', 'read'])
    it(
      'does not retry creation after inspection failure ' + failure,
      async () => {
        if (failure === 'missing') inspectionMissing = true;
        else failCommand = 'cat-file';
        await expect(
          run({ mode: 'create', tagName: 'v1', message: 'annotation' }),
        ).rejects.toThrow();
        expect(calls.filter((call) => call.args[0] === 'tag')).toHaveLength(1);
      },
    );
  it('deletes only the validated tag name after an option boundary', async () => {
    expect(await run({ mode: 'delete', tagName: 'v1' })).toEqual({
      mode: 'delete',
      deleted: 'v1',
    });
    expect(calls.at(-1)!.args).toEqual(['tag', '-d', '--', 'v1']);
  });
  for (const mode of ['create', 'delete', 'verify'] as const)
    it('requires a name for ' + mode, async () => {
      await expect(run({ mode })).rejects.toThrow();
      expect(calls).toHaveLength(0);
    });
  it('reports unsigned tags without claiming verification', async () => {
    const result = await run({ mode: 'verify', tagName: 'v1' });
    expect(result.verified).toBe(false);
    expect(result.warning).toMatch(/no supported signature/);
    expect(calls.filter((call) => call.args[0] === 'verify-tag')).toHaveLength(
      0,
    );
  });
  const fingerprint = 'A'.repeat(40);
  for (const [format, armor, positive] of [
    [
      'gpg',
      'PGP SIGNATURE',
      '[GNUPG:] VALIDSIG ' + fingerprint + ' 0 0\n[GNUPG:] TRUST_ULTIMATE 0\n',
    ],
    [
      'x509',
      'SIGNED MESSAGE',
      '[GNUPG:] VALIDSIG ' + fingerprint + ' 0 0\n[GNUPG:] TRUST_FULLY 0\n',
    ],
    [
      'ssh',
      'SSH SIGNATURE',
      'Good "git" signature for fixture@example.invalid with ED25519 key SHA256:AAAA\n',
    ],
  ] as const) {
    for (const exitCode of [0, 1, 2, undefined])
      it('honors ' + format + ' status with exit ' + exitCode, async () => {
        object = tagFixture(
          commit.id,
          'annotation\n-----BEGIN ' + armor + '-----\nbody\n',
        );
        verification = {
          stdout: '',
          stderr: positive,
          ...(exitCode !== undefined ? { exitCode } : {}),
        };
        const result = await run({ mode: 'verify', tagName: 'v1' });
        expect(result.verified).toBe(exitCode === 0);
        expect(result.cryptographicallyValid).toBe(true);
        expect(result.signatureType).toBe(format);
        const call = calls.at(-1)!;
        expect(call.args).toEqual(['verify-tag', '--raw', object.id]);
        expect(call.soft).toBe(true);
      });
  }
  for (const text of [
    'gpg: Good signature from "Fixture"\n',
    'future verifier output\n',
    '',
  ])
    it(
      'never accepts prose-only or unknown exit0 output ' +
        JSON.stringify(text),
      async () => {
        object = tagFixture(
          commit.id,
          'annotation\n-----BEGIN PGP SIGNATURE-----\nbody\n',
        );
        verification = { stdout: '', stderr: text, exitCode: 0 };
        expect((await run({ mode: 'verify', tagName: 'v1' })).verified).toBe(
          false,
        );
      },
    );
  for (const status of ['BADSIG', 'NO_PUBKEY', 'REVKEYSIG', 'EXPKEYSIG'])
    it('rejects explicit machine failure ' + status, async () => {
      object = tagFixture(
        commit.id,
        'annotation\n-----BEGIN PGP SIGNATURE-----\nbody\n',
      );
      verification = {
        stdout: '',
        stderr:
          '[GNUPG:] VALIDSIG ' +
          fingerprint +
          ' 0\n[GNUPG:] ' +
          status +
          ' key\n',
        exitCode: 0,
      };
      expect((await run({ mode: 'verify', tagName: 'v1' })).verified).toBe(
        false,
      );
    });
  it('preserves valid cryptography separately from undefined native trust', async () => {
    object = tagFixture(
      commit.id,
      'annotation\n-----BEGIN PGP SIGNATURE-----\nbody\n',
    );
    verification = {
      stdout: '',
      stderr:
        '[GNUPG:] VALIDSIG ' + fingerprint + ' 0\n[GNUPG:] TRUST_UNDEFINED 0\n',
      exitCode: 0,
    };
    const result = await run({ mode: 'verify', tagName: 'v1' });
    expect(result.verified).toBe(true);
    expect(result.trust).toBe('untrusted');
  });
  it('rejects absent or ambiguous named refs instead of verifying another object', async () => {
    inspectionMissing = true;
    await expect(run({ mode: 'verify', tagName: 'v1' })).rejects.toThrow();
  });
});
