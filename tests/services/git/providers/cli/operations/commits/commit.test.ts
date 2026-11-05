/**
 * @fileoverview Commit options and immutable inspection without unsigned retries.
 * @module tests/services/git/providers/cli/operations/commits/commit.test
 */
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { config } from '@/config/index.js';
import { executeCommit } from '@/services/git/providers/cli/operations/commits/commit.js';
import { commitFixture } from '../../../../../../security/helpers/git-object-fixture.js';
import type {
  GitCommitOptions,
  GitOperationContext,
} from '@/services/git/types.js';
import type { RequestContext } from '@/utils/index.js';

describe('executeCommit', () => {
  const context: GitOperationContext = {
    workingDirectory: '/fixture/repository',
    requestContext: { requestId: 'fixture' } as RequestContext,
  };
  let saved: boolean;
  let object: ReturnType<typeof commitFixture>;
  let names: string;
  let failCommand: string | undefined;
  const calls: string[][] = [];
  const execute = vi.fn(async (args: string[]) => {
    calls.push(args);
    if (args[0] === failCommand) throw new Error('fixture operation failed');
    if (args[0] === 'rev-parse')
      return { stdout: object.id + '\n', stderr: '' };
    if (args[0] === 'cat-file') return { stdout: object.raw, stderr: '' };
    if (args[0] === 'show') return { stdout: names, stderr: '' };
    return { stdout: '', stderr: '' };
  });
  const run = (options: Partial<GitCommitOptions> = {}) =>
    executeCommit(
      { message: 'requested message', ...options },
      context,
      execute,
    );
  beforeEach(() => {
    saved = config.git.signCommits;
    config.git.signCommits = false;
    object = commitFixture();
    names = 'src/index.ts\0README.md\0';
    calls.length = 0;
    failCommand = undefined;
    execute.mockClear();
  });
  afterEach(() => {
    config.git.signCommits = saved;
  });

  it('returns the exact created identity, author, timestamp and complete file list', async () => {
    const result = await run();
    expect(result).toEqual({
      success: true,
      commitHash: object.id,
      message: 'requested message',
      author: 'Fixture Author',
      timestamp: 1700000000,
      filesChanged: ['src/index.ts', 'README.md'],
      signed: false,
    });
  });
  it('attaches a dash-leading message instead of passing another option', async () => {
    await run({ message: '--amend' });
    expect(calls[0]).toContain('--message=--amend');
  });
  it('stages only explicit literal files before creation', async () => {
    await run({ filesToStage: ['src/a.ts', ':(glob)*'] });
    expect(calls[0]).toEqual([
      'add',
      '--',
      ':(literal)src/a.ts',
      ':(literal):(glob)*',
    ]);
    expect(calls[1]![0]).toBe('commit');
    expect(calls).toHaveLength(5);
  });
  for (const files of [undefined, []])
    it(
      'omits staging for absent or empty file selections ' + String(files),
      async () => {
        await run(files ? { filesToStage: files } : {});
        expect(calls[0]![0]).toBe('commit');
        expect(calls).toHaveLength(4);
      },
    );
  for (const [option, flag] of [
    ['amend', '--amend'],
    ['allowEmpty', '--allow-empty'],
    ['noVerify', '--no-verify'],
  ] as const) {
    it('preserves enabled ' + option, async () => {
      await run({ [option]: true });
      expect(calls[0]).toContain(flag);
    });
    it('omits disabled ' + option, async () => {
      await run({ [option]: false });
      expect(calls[0]).not.toContain(flag);
    });
  }
  it('preserves explicit author metadata and combined flags', async () => {
    await run({
      amend: true,
      noVerify: true,
      author: { name: 'Another Fixture', email: 'another@example.invalid' },
    });
    expect(calls[0]).toContain(
      '--author=Another Fixture <another@example.invalid>',
    );
    expect(calls[0]).toContain('--amend');
    expect(calls[0]).toContain('--no-verify');
  });
  for (const header of ['gpgsig', 'gpgsig-sha256'])
    it(
      'reports native signature header ' + header + ' without forcing signing',
      async () => {
        object = commitFixture({ signatureHeader: header });
        const result = await run();
        expect(result.signed).toBe(true);
        expect(calls[0]).not.toContain('--gpg-sign');
        expect(result.signingWarning).toBeUndefined();
      },
    );
  it('strict signing requests a signature and checks its actual presence', async () => {
    config.git.signCommits = true;
    object = commitFixture({ signatureHeader: 'gpgsig' });
    expect((await run()).signed).toBe(true);
    expect(calls[0]).toContain('--gpg-sign');
  });
  it('rejects an absent strict signature without another creation', async () => {
    config.git.signCommits = true;
    await expect(run()).rejects.toThrow(/Required signature/);
    expect(calls.filter((args) => args[0] === 'commit')).toHaveLength(1);
  });
  for (const required of [true, false])
    it(
      'propagates creation failure once under policy ' + required,
      async () => {
        config.git.signCommits = required;
        failCommand = 'commit';
        await expect(run()).rejects.toThrow(/fixture operation failed/);
        expect(calls).toHaveLength(1);
        expect(calls[0]!.includes('--gpg-sign')).toBe(required);
      },
    );
  it('does not count signature-looking message text as a header', async () => {
    object = commitFixture({ message: 'subject\n\ngpgsig forged\n' });
    expect((await run()).signed).toBe(false);
  });
  it('does not retry a creation after an object read failure', async () => {
    failCommand = 'cat-file';
    await expect(run()).rejects.toThrow(/fixture operation failed/);
    expect(calls.filter((args) => args[0] === 'commit')).toHaveLength(1);
  });
  it('preserves newline/control/Unicode filenames using NUL records', async () => {
    names = 'line\nname\0\ufeff\ufffd\0';
    expect((await run()).filesChanged).toEqual(['line\nname', '\ufeff\ufffd']);
  });
  it('accepts an empty changed-file list', async () => {
    names = '';
    expect((await run()).filesChanged).toEqual([]);
  });
  it('rejects truncated filename records rather than returning partial success', async () => {
    names = 'one\0truncated';
    await expect(run()).rejects.toMatchObject({
      data: { reason: 'INVALID_OUTPUT_FORMAT' },
    });
  });
  it('pins both object and filename inspection to the complete created OID', async () => {
    await run();
    expect(calls.map((args) => args[0])).toEqual([
      'commit',
      'rev-parse',
      'cat-file',
      'show',
    ]);
    expect(calls[2]).toEqual(['cat-file', 'commit', object.id]);
    expect(calls[3]).toContain(object.id);
    expect(calls[3]).toContain('-z');
    expect(calls[3]).toContain('--format=');
  });
  it('rejects incomplete hashes and object identity mismatches', async () => {
    execute
      .mockResolvedValueOnce({ stdout: '', stderr: '' })
      .mockResolvedValueOnce({ stdout: 'abc123\n', stderr: '' });
    await expect(run()).rejects.toThrow(/identity/);
    expect(
      calls.filter((args) => args[0] === 'commit').length,
    ).toBeLessThanOrEqual(1);
  });
});
