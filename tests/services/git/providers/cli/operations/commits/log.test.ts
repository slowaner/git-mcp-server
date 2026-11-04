/**
 * @fileoverview History options and immutable record-boundary regressions.
 * @module tests/services/git/providers/cli/operations/commits/log.test
 */
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { executeLog } from '@/services/git/providers/cli/operations/commits/log.js';
import { commitFixture } from '../../../../../../security/helpers/git-object-fixture.js';
import type {
  GitLogOptions,
  GitOperationContext,
} from '@/services/git/types.js';
import type { RequestContext } from '@/utils/index.js';

describe('executeLog', () => {
  const context: GitOperationContext = {
    workingDirectory: '/fixture/repository',
    requestContext: { requestId: 'fixture' } as RequestContext,
  };
  let objects: ReturnType<typeof commitFixture>[];
  let stat: string, patch: string;
  const calls: string[][] = [];
  const execute = vi.fn(async (args: string[]) => {
    calls.push(args);
    if (args[0] === 'log')
      return {
        stdout: objects.map((object) => object.id + '\n').join(''),
        stderr: '',
      };
    if (args[0] === 'cat-file') {
      const object = objects.find((object) => object.id === args[2]);
      if (!object) throw new Error('Unknown fixture object');
      return { stdout: object.raw, stderr: '' };
    }
    return { stdout: args.includes('--stat') ? stat : patch, stderr: '' };
  });
  const run = (options: GitLogOptions = {}) =>
    executeLog(options, context, execute);
  beforeEach(() => {
    objects = [commitFixture()];
    calls.length = 0;
    execute.mockClear();
    stat = ' one | 1 +\n 1 file changed, 1 insertion(+)\n';
    patch = 'diff --git a/one b/one\n+<<<COMMIT_START>>>\0<<<COMMIT_END>>>\n';
  });

  it('returns empty history without object reads', async () => {
    objects = [];
    expect(await run()).toEqual({ commits: [], totalCount: 0 });
    expect(calls).toHaveLength(1);
  });
  it('preserves hash, short hash, author, email, timestamp, subject, body and parents', async () => {
    const result = await run();
    expect(result.totalCount).toBe(1);
    expect(result.commits[0]).toEqual({
      hash: objects[0]!.id,
      shortHash: objects[0]!.id.slice(0, 7),
      author: 'Fixture Author',
      authorEmail: 'fixture@example.invalid',
      timestamp: 1700000000,
      subject: 'subject',
      body: 'body\n',
      parents: [],
    });
  });
  it('preserves multiple records in native enumeration order', async () => {
    objects.push(commitFixture({ message: 'second\n', timestamp: 1700000001 }));
    expect((await run()).commits.map((commit) => commit.hash)).toEqual(
      objects.map((object) => object.id),
    );
  });
  it('preserves both independently validated merge parent identities', async () => {
    objects = [commitFixture({ parents: ['1'.repeat(40), '2'.repeat(40)] })];
    expect((await run()).commits[0]!.parents).toEqual([
      '1'.repeat(40),
      '2'.repeat(40),
    ]);
  });
  for (const [options, flags] of [
    [{ maxCount: 10 }, ['-n10']],
    [{ maxCount: 1 }, ['-n1']],
    [{ skip: 5 }, ['--skip=5']],
    [{ skip: 10, maxCount: 5 }, ['--skip=10', '-n5']],
    [{ since: '2024-01-01' }, ['--since=2024-01-01']],
    [{ until: '2024-12-31' }, ['--until=2024-12-31']],
    [
      { since: '2024-01-01', until: '2024-12-31' },
      ['--since=2024-01-01', '--until=2024-12-31'],
    ],
    [{ author: 'Fixture Author' }, ['--author=Fixture Author']],
    [{ author: '@example.invalid' }, ['--author=@example.invalid']],
    [{ grep: 'fix:' }, ['--grep=fix:']],
    [{ branch: 'develop' }, ['--end-of-options', 'develop']],
  ] as [GitLogOptions, string[]][])
    it('preserves filters ' + JSON.stringify(options), async () => {
      await run(options);
      for (const flag of flags) expect(calls[0]).toContain(flag);
      expect(calls[0]).toContain('--format=%H');
    });
  it('uses literal option-separated paths, including native-magic-looking names', async () => {
    await run({ path: ':(glob)*' });
    expect(calls[0]!.slice(-2)).toEqual(['--', ':(literal):(glob)*']);
  });
  it('pins stat to the enumerated immutable commit and preserves it opaquely', async () => {
    const result = await run({ stat: true });
    expect(result.commits[0]!.stat).toBe(stat);
    expect(calls[2]).toEqual(['show', '--format=', '--stat', objects[0]!.id]);
  });
  it('omits empty stat content for commits without changed files', async () => {
    stat = '';
    expect((await run({ stat: true })).commits[0]!.stat).toBeUndefined();
  });
  it('pins patch to one immutable commit without marker parsing', async () => {
    const result = await run({ patch: true });
    expect(result.commits[0]!.patch).toBe(patch);
    expect(calls[2]).toEqual(['show', '--format=', '-p', objects[0]!.id]);
  });
  it('returns stat and patch separately without searching a diff header', async () => {
    const result = await run({ stat: true, patch: true });
    expect(result.commits[0]!.stat).toBe(stat);
    expect(result.commits[0]!.patch).toBe(patch);
    expect(calls[2]).toContain('--stat');
    expect(calls[3]).toContain('-p');
  });
  for (const message of [
    'subject\n\nline one\nline two\n',
    'feat: "quotes" & <special> $var\n\n<<<COMMIT_START>>>\x1f\x1e<<<COMMIT_END>>>\n',
  ])
    it(
      'preserves exact body bytes and cannot create records from message ' +
        JSON.stringify(message),
      async () => {
        objects = [commitFixture({ message })];
        const result = await run();
        expect(result.totalCount).toBe(1);
        expect(result.commits[0]!.body).toBe(
          message.split('\n\n').slice(1).join('\n\n'),
        );
        expect(result.commits[0]!.hash).toBe(objects[0]!.id);
      },
    );
  it('omits an empty body', async () => {
    objects = [commitFixture({ message: 'No body\n' })];
    expect((await run()).commits[0]!.body).toBeUndefined();
  });
  it('oneline keeps only authenticated identity and subject', async () => {
    const result = await run({ oneline: true });
    expect(result.commits[0]).toEqual({
      hash: objects[0]!.id,
      shortHash: objects[0]!.id.slice(0, 7),
      subject: 'subject',
    });
    expect(calls[0]).toContain('--format=%H');
    expect(calls[0]!.some((flag) => /%[asbP]/.test(flag))).toBe(false);
  });
  it('full mode retains independently authenticated metadata', async () => {
    objects = [
      commitFixture({
        author: 'Another Fixture',
        email: 'another@example.invalid',
        timestamp: 1700000002,
      }),
    ];
    expect((await run()).commits[0]).toMatchObject({
      author: 'Another Fixture',
      authorEmail: 'another@example.invalid',
      timestamp: 1700000002,
    });
  });
  for (const output of [
    'abc123\n',
    'f'.repeat(40) + '\n' + 'f'.repeat(40) + '\n',
    '<<<COMMIT_START>>>fake',
  ]) {
    it(
      'rejects malformed or duplicate enumeration ' + JSON.stringify(output),
      async () => {
        execute.mockResolvedValueOnce({ stdout: output, stderr: '' });
        await expect(run()).rejects.toThrow();
      },
    );
  }
  it('rejects object substitution instead of returning partial records', async () => {
    execute
      .mockResolvedValueOnce({ stdout: objects[0]!.id + '\n', stderr: '' })
      .mockResolvedValueOnce({
        stdout: commitFixture({ message: 'other' }).raw,
        stderr: '',
      });
    await expect(run()).rejects.toThrow();
  });
  for (const maxCount of [0, -1, 1001])
    it('rejects unsupported record limit ' + maxCount, async () => {
      await expect(run({ maxCount })).rejects.toThrow();
      expect(calls).toHaveLength(0);
    });
});
