/**
 * @fileoverview Unit tests for git tag operation
 * @module tests/services/git/providers/cli/operations/tags/tag.test
 */
import { describe, expect, it, vi, beforeEach } from 'vitest';

import { executeTag } from '@/services/git/providers/cli/operations/tags/tag.js';
import { shouldSignCommits } from '@/services/git/providers/cli/utils/config-helper.js';
import type { GitOperationContext } from '@/services/git/types.js';
import type { RequestContext } from '@/utils/index.js';

// Mock shouldSignCommits to return false by default. Tests that exercise
// signing behavior flip it per-case via the `mockReturnValueOnce` cast
// below — bun's test runner doesn't expose vi.mocked, so we use a direct
// cast on the imported function.
vi.mock('@/services/git/providers/cli/utils/config-helper.js', () => ({
  shouldSignCommits: vi.fn(() => false),
  loadConfig: vi.fn(() => null),
}));

type ExecGitFn = (
  args: string[],
  cwd: string,
  ctx: RequestContext,
  options?: { allowNonZeroExit?: boolean },
) => Promise<{ stdout: string; stderr: string; exitCode?: number }>;

describe('executeTag', () => {
  const mockContext: GitOperationContext = {
    workingDirectory: '/test/repo',
    requestContext: {
      requestId: 'test-request-id',
    } as RequestContext,
    tenantId: 'test-tenant',
  };

  let mockExecGit: ReturnType<typeof vi.fn<ExecGitFn>>;

  beforeEach(() => {
    mockExecGit = vi.fn<ExecGitFn>();
  });

  describe('list mode', () => {
    it('lists tags via for-each-ref with field + record delimiters', async () => {
      // Fields separated by \x1F, records terminated by \x1E. Body field is last
      // and may contain newlines — the record delimiter is what terminates.
      const stdout =
        [
          `v2.0.0\x1Fabc1234\x1FRelease 2.0\x1FTagger <t@e.com>\x1F1700000000\x1FFirst body line\nSecond body line`,
          `v1.1.0\x1Fdef5678\x1F\x1F\x1F\x1F`,
          `v1.0.0\x1F9876543\x1FInitial\x1F\x1F1690000000\x1F`,
        ].join('\x1E\n') + '\x1E\n';

      mockExecGit.mockResolvedValueOnce({ stdout, stderr: '' });

      const result = await executeTag(
        { mode: 'list' },
        mockContext,
        mockExecGit,
      );

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).toContain('for-each-ref');
      expect(args).toContain('refs/tags');
      expect(result.mode).toBe('list');
      expect(result.tags).toHaveLength(3);
      expect(result.tags![0]!.name).toBe('v2.0.0');
      expect(result.tags![0]!.commit).toBe('abc1234');
      expect(result.tags![0]!.message).toBe('Release 2.0');
      expect(result.tags![0]!.annotationBody).toBe(
        'First body line\nSecond body line',
      );
      expect(result.tags![1]!.name).toBe('v1.1.0');
      expect(result.tags![1]!.commit).toBe('def5678');
      expect(result.tags![1]!.annotationBody).toBeUndefined();
      expect(result.tags![2]!.name).toBe('v1.0.0');
      expect(result.tags![2]!.annotationBody).toBeUndefined();
    });

    it('returns empty tags array for no tags', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: '',
      });

      const result = await executeTag(
        { mode: 'list' },
        mockContext,
        mockExecGit,
      );

      expect(result.tags).toHaveLength(0);
    });

    it('passes --count=N to for-each-ref when limit is set', async () => {
      mockExecGit.mockResolvedValueOnce({ stdout: '', stderr: '' });

      await executeTag({ mode: 'list', limit: 3 }, mockContext, mockExecGit);

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).toContain('--count=3');
    });

    it('omits --count when limit is zero or negative', async () => {
      mockExecGit.mockResolvedValueOnce({ stdout: '', stderr: '' });

      await executeTag({ mode: 'list', limit: 0 }, mockContext, mockExecGit);

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args.some((arg) => arg.startsWith('--count='))).toBe(false);
    });

    it('parses annotation body with embedded newlines as a single field', async () => {
      // Body spanning multiple lines must round-trip cleanly because the record
      // delimiter (\x1E) — not newline — is what terminates the record.
      const stdout = `v3.0.0\x1Faaa1111\x1FBig release\x1FT <t@e.com>\x1F1700000000\x1FLine one\nLine two\n\nLine four\x1E\n`;

      mockExecGit.mockResolvedValueOnce({ stdout, stderr: '' });

      const result = await executeTag(
        { mode: 'list' },
        mockContext,
        mockExecGit,
      );

      expect(result.tags).toHaveLength(1);
      expect(result.tags![0]!.annotationBody).toBe(
        'Line one\nLine two\n\nLine four',
      );
    });
  });

  describe('create mode', () => {
    let nativeSigning: boolean;
    let signature: string;
    let objectType: string;

    beforeEach(() => {
      nativeSigning = false;
      signature = '';
      objectType = 'tag';
      mockExecGit.mockImplementation(async (args) => {
        if (args[0] === 'config') {
          return {
            stdout: nativeSigning ? 'true\n' : '',
            stderr: '',
            exitCode: nativeSigning ? 0 : 1,
          };
        }
        if (args[0] === 'for-each-ref') {
          return { stdout: `${objectType}\x1F${signature}\n`, stderr: '' };
        }
        return { stdout: '', stderr: '' };
      });
    });

    function creationCalls(): string[][] {
      return mockExecGit.mock.calls
        .filter(([args]) => args[0] === 'tag')
        .map(([args]) => args);
    }

    function forceSigning(): void {
      (
        shouldSignCommits as unknown as {
          mockReturnValueOnce: (v: boolean) => void;
        }
      ).mockReturnValueOnce(true);
    }

    it('leaves a plain tag lightweight when native signing is unset', async () => {
      objectType = 'commit';
      const result = await executeTag(
        { mode: 'create', tagName: 'v1' },
        mockContext,
        mockExecGit,
      );
      expect(creationCalls()).toEqual([['tag', 'v1']]);
      expect(mockExecGit.mock.calls[0]![0]).toEqual([
        'config',
        '--type=bool',
        '--get',
        'tag.gpgSign',
      ]);
      expect(mockExecGit.mock.calls[0]![3]).toEqual({ allowNonZeroExit: true });
      expect(result.created).toBe('v1');
      expect(result.signed).toBe(false);
    });

    it('supplies a default message for native signing without disabling config', async () => {
      nativeSigning = true;
      signature = '-----BEGIN SSH SIGNATURE-----\nbody';
      const result = await executeTag(
        { mode: 'create', tagName: 'v1' },
        mockContext,
        mockExecGit,
      );
      expect(creationCalls()).toEqual([['tag', 'v1', '--message=Tag v1']]);
      expect(result.signed).toBe(true);
      expect(result.signingWarning).toBeUndefined();
    });

    for (const options of [
      { message: '-release message' },
      { annotated: true },
    ]) {
      it(`implies annotation using a message: ${JSON.stringify(options)}`, async () => {
        const result = await executeTag(
          { mode: 'create', tagName: 'v1', ...options },
          mockContext,
          mockExecGit,
        );
        expect(creationCalls()[0]).toContain(
          `--message=${options.message || 'Tag v1'}`,
        );
        expect(creationCalls()[0]).not.toContain('-a');
        expect(creationCalls()[0]).not.toContain('-s');
        expect(
          mockExecGit.mock.calls.some(([args]) => args[0] === 'config'),
        ).toBe(false);
        expect(result.signed).toBe(false);
      });
    }

    it('preserves target commit and force options', async () => {
      await executeTag(
        { mode: 'create', tagName: 'v1', commit: 'abc123', force: true },
        mockContext,
        mockExecGit,
      );
      expect(creationCalls()[0]).toEqual(['tag', 'v1', 'abc123', '--force']);
    });

    it('requests signing explicitly and reports actual signature presence', async () => {
      forceSigning();
      signature = '-----BEGIN PGP SIGNATURE-----\nbody';
      const result = await executeTag(
        { mode: 'create', tagName: 'v1' },
        mockContext,
        mockExecGit,
      );
      expect(creationCalls()[0]).toEqual([
        'tag',
        'v1',
        '-s',
        '--message=Tag v1',
      ]);
      expect(result.signed).toBe(true);
    });

    it('uses custom message when signing explicitly', async () => {
      forceSigning();
      await executeTag(
        { mode: 'create', tagName: 'v1', message: 'custom' },
        mockContext,
        mockExecGit,
      );
      expect(creationCalls()[0]).toEqual([
        'tag',
        'v1',
        '-s',
        '--message=custom',
      ]);
    });

    it('does not count a lightweight tag pointing at a signed commit', async () => {
      objectType = 'commit';
      signature = 'signature-like commit message';
      expect(
        (
          await executeTag(
            { mode: 'create', tagName: 'v1' },
            mockContext,
            mockExecGit,
          )
        ).signed,
      ).toBe(false);
    });

    for (const signedOnRetry of [false, true]) {
      it(`retries using native config and reports signed=${signedOnRetry}`, async () => {
        forceSigning();
        nativeSigning = signedOnRetry;
        signature = signedOnRetry ? '-----BEGIN SSH SIGNATURE-----\nbody' : '';
        const implementation = mockExecGit.getMockImplementation()!;
        let first = true;
        mockExecGit.mockImplementation(async (...args) => {
          if (args[0][0] === 'tag' && first) {
            first = false;
            throw new Error('gpg failed to sign');
          }
          return implementation(...args);
        });
        const result = await executeTag(
          { mode: 'create', tagName: 'v1' },
          mockContext,
          mockExecGit,
        );
        expect(creationCalls()).toHaveLength(2);
        expect(creationCalls()[1]).not.toContain('-s');
        expect(creationCalls()[1]).not.toContain('-c');
        expect(creationCalls()[1]).not.toContain('tag.gpgSign=false');
        if (signedOnRetry)
          expect(creationCalls()[1]).toContain('--message=Tag v1');
        expect(result.signed).toBe(signedOnRetry);
        expect(result.signingWarning).toContain('native Git configuration');
        expect(result.signingWarning).toContain('gpg failed to sign');
      });
    }

    it('propagates native signing failures without retry', async () => {
      const implementation = mockExecGit.getMockImplementation()!;
      mockExecGit.mockImplementation(async (...args) => {
        if (args[0][0] === 'tag') throw new Error('native signing failed');
        return implementation(...args);
      });
      await expect(
        executeTag(
          {
            mode: 'create',
            tagName: 'v1',
          },
          mockContext,
          mockExecGit,
        ),
      ).rejects.toThrow(/native signing failed/);
      expect(creationCalls()).toHaveLength(1);
    });

    it('propagates failed retry when native signing remains required', async () => {
      forceSigning();
      const implementation = mockExecGit.getMockImplementation()!;
      mockExecGit.mockImplementation(async (...args) => {
        if (args[0][0] === 'tag') throw new Error('native signing required');
        return implementation(...args);
      });
      await expect(
        executeTag(
          {
            mode: 'create',
            tagName: 'v1',
          },
          mockContext,
          mockExecGit,
        ),
      ).rejects.toThrow(/native signing required/);
      expect(creationCalls()).toHaveLength(2);
    });

    it('propagates malformed config before attempting creation', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: 'bad boolean config',
        exitCode: 128,
      });
      await expect(
        executeTag(
          {
            mode: 'create',
            tagName: 'v1',
          },
          mockContext,
          mockExecGit,
        ),
      ).rejects.toThrow(/bad boolean config/);
      expect(creationCalls()).toHaveLength(0);
    });

    it('does not retry creation when inspection fails', async () => {
      forceSigning();
      const implementation = mockExecGit.getMockImplementation()!;
      mockExecGit.mockImplementation(async (...args) => {
        if (args[0][0] === 'for-each-ref') throw new Error('inspection failed');
        return implementation(...args);
      });
      await expect(
        executeTag(
          {
            mode: 'create',
            tagName: 'v1',
          },
          mockContext,
          mockExecGit,
        ),
      ).rejects.toThrow(/inspection failed/);
      expect(creationCalls()).toHaveLength(1);
    });

    it('reports missing inspection data as an error', async () => {
      objectType = '';
      await expect(
        executeTag(
          {
            mode: 'create',
            tagName: 'v1',
          },
          mockContext,
          mockExecGit,
        ),
      ).rejects.toThrow(/Could not inspect/);
      expect(creationCalls()).toHaveLength(1);
    });

    it('requires a tag name', async () => {
      await expect(
        executeTag({ mode: 'create' }, mockContext, mockExecGit),
      ).rejects.toThrow();
      expect(mockExecGit).not.toHaveBeenCalled();
    });
  });

  describe('delete mode', () => {
    it('deletes a tag with -d flag', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: "Deleted tag 'v1.0.0' (was abc123)\n",
        stderr: '',
      });

      const result = await executeTag(
        { mode: 'delete', tagName: 'v1.0.0' },
        mockContext,
        mockExecGit,
      );

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).toContain('tag');
      expect(args).toContain('-d');
      expect(args).toContain('v1.0.0');
      expect(result.mode).toBe('delete');
      expect(result.deleted).toBe('v1.0.0');
    });

    it('throws error when tagName is missing for delete', async () => {
      await expect(
        executeTag({ mode: 'delete' } as any, mockContext, mockExecGit),
      ).rejects.toThrow();
    });
  });

  describe('verify mode', () => {
    it('invokes `git tag -v <name>` with allowNonZeroExit', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: 'gpg: Good signature from "Test <t@e.com>"',
        exitCode: 0,
      });

      await executeTag(
        { mode: 'verify', tagName: 'v1.0.0' },
        mockContext,
        mockExecGit,
      );

      const [args, , , options] = mockExecGit.mock.calls[0]!;
      expect(args).toContain('tag');
      expect(args).toContain('-v');
      expect(args).toContain('v1.0.0');
      expect(options?.allowNonZeroExit).toBe(true);
    });

    it('parses a valid GPG signature: type, identity, and key fingerprint', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr:
          'gpg: Signature made Tue Jun  1 12:34:56 2021 UTC\n' +
          'gpg:                using RSA key 0123456789ABCDEF\n' +
          'gpg: Good signature from "Casey Hand <casey@example.com>" [ultimate]',
        exitCode: 0,
      });

      const result = await executeTag(
        { mode: 'verify', tagName: 'v2.0.0' },
        mockContext,
        mockExecGit,
      );

      expect(result.mode).toBe('verify');
      expect(result.verifiedTag).toBe('v2.0.0');
      expect(result.verified).toBe(true);
      expect(result.signatureType).toBe('gpg');
      expect(result.signerIdentity).toBe('Casey Hand <casey@example.com>');
      expect(result.signerKey).toBe('0123456789ABCDEF');
      expect(result.warning).toBeUndefined();
    });

    it('parses a valid SSH signature: type, identity, and SHA256 fingerprint', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr:
          'Good "git" signature for casey@example.com with ED25519 key SHA256:abc123xyz',
        exitCode: 0,
      });

      const result = await executeTag(
        { mode: 'verify', tagName: 'v1.0.0' },
        mockContext,
        mockExecGit,
      );

      expect(result.verified).toBe(true);
      expect(result.signatureType).toBe('ssh');
      expect(result.signerIdentity).toBe('casey@example.com');
      expect(result.signerKey).toBe('SHA256:abc123xyz');
    });

    it('flags unsigned tags without throwing', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: 'object abc\ntype commit\ntag v1.0.0\n',
        stderr: 'error: no signature found',
        exitCode: 1,
      });

      const result = await executeTag(
        { mode: 'verify', tagName: 'v1.0.0' },
        mockContext,
        mockExecGit,
      );

      expect(result.verified).toBe(false);
      expect(result.warning).toContain('no signature');
      expect(result.signatureType).toBeUndefined();
      expect(result.rawOutput).toContain('no signature found');
    });

    it('distinguishes missing SSH trust config from a real failure', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: 'object abc\n',
        stderr:
          'error: gpg.ssh.allowedSignersFile needs to be configured and exist for ssh signature verification',
        exitCode: 1,
      });

      const result = await executeTag(
        { mode: 'verify', tagName: 'v1.0.0' },
        mockContext,
        mockExecGit,
      );

      expect(result.verified).toBe(false);
      expect(result.signatureType).toBe('ssh');
      expect(result.warning).toContain('allowedSignersFile');
      expect(result.warning).toContain('may be validly signed');
    });

    it('surfaces bad GPG signatures with identity preserved', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: 'gpg: BAD signature from "Impostor <fake@example.com>"',
        exitCode: 1,
      });

      const result = await executeTag(
        { mode: 'verify', tagName: 'v1.0.0' },
        mockContext,
        mockExecGit,
      );

      expect(result.verified).toBe(false);
      expect(result.signatureType).toBe('gpg');
      expect(result.signerIdentity).toBe('Impostor <fake@example.com>');
      expect(result.warning).toContain('BAD signature');
    });

    it('throws McpError when the tag does not exist', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: "error: tag 'nonexistent' not found.",
        exitCode: 128,
      });

      await expect(
        executeTag(
          { mode: 'verify', tagName: 'nonexistent' },
          mockContext,
          mockExecGit,
        ),
      ).rejects.toThrow(/tag not found/i);
    });

    it('throws when tagName is missing', async () => {
      await expect(
        executeTag({ mode: 'verify' } as any, mockContext, mockExecGit),
      ).rejects.toThrow();
    });

    it('trusts git exit 0 even when output pattern is unrecognized', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: "some future success format we haven't seen",
        exitCode: 0,
      });

      const result = await executeTag(
        { mode: 'verify', tagName: 'v1.0.0' },
        mockContext,
        mockExecGit,
      );

      expect(result.verified).toBe(true);
    });
  });

  describe('result structure', () => {
    it('returns correct structure for list', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: 'v1.0.0\x1F\x1F\x1F\x1F\x1F\x1E\n',
        stderr: '',
      });

      const result = await executeTag(
        { mode: 'list' },
        mockContext,
        mockExecGit,
      );

      expect(result).toHaveProperty('mode', 'list');
      expect(result).toHaveProperty('tags');
    });

    it('returns correct structure for create', async () => {
      mockExecGit
        .mockResolvedValueOnce({ stdout: '', stderr: '', exitCode: 1 })
        .mockResolvedValueOnce({ stdout: '', stderr: '' })
        .mockResolvedValueOnce({ stdout: 'commit\x1F\n', stderr: '' });

      const result = await executeTag(
        { mode: 'create', tagName: 'v1.0.0' },
        mockContext,
        mockExecGit,
      );

      expect(result).toHaveProperty('mode', 'create');
      expect(result).toHaveProperty('created', 'v1.0.0');
    });

    it('returns correct structure for delete', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: '',
      });

      const result = await executeTag(
        { mode: 'delete', tagName: 'v1.0.0' },
        mockContext,
        mockExecGit,
      );

      expect(result).toHaveProperty('mode', 'delete');
      expect(result).toHaveProperty('deleted', 'v1.0.0');
    });
  });
});
