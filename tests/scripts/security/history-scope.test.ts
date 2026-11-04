/**
 * @fileoverview History scope must be proven before a scanner can be invoked.
 * @module tests/scripts/security/history-scope
 */
import { describe, expect, it } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  proveHistoryScope,
  readHistoryGit,
  type HistoryGitReader,
} from '../../../scripts/security/history-scope.js';
import {
  HISTORY_POLICY_ANCHOR,
  historyLogOptions,
} from '../../../scripts/security/history-result.js';

const ref = 'a'.repeat(40);
function reader(
  overrides: Record<string, string> = {},
  calls: string[][] = [],
): HistoryGitReader {
  return (args) => {
    calls.push(args);
    const key = args.join(' ');
    if (key in overrides) return overrides[key]!;
    if (args[0] === 'rev-parse' && args[1] === '--verify') return ref;
    if (args[1] === '--is-shallow-repository') return 'false';
    if (args[0] === 'for-each-ref') return '';
    if (args[1] === '--path-format=absolute')
      return '/definitely-absent-g6-grafts';
    if (args[0] === 'merge-base') return '';
    if (args[0] === 'rev-list') return '427';
    throw new Error('Unexpected metadata command.');
  };
}

describe('history traversal scope', () => {
  it('proves actual current checkout ancestry through read-only native Git metadata', async () => {
    const root = fileURLToPath(new URL('../../../', import.meta.url));
    const head = readHistoryGit(
      ['rev-parse', '--verify', 'HEAD^{commit}'],
      root,
    );
    const proof = await proveHistoryScope(root, head);
    expect(proof.before).toBe(head);
    expect(proof.reachableCommits).toBeGreaterThanOrEqual(427);
    expect(proof.logOptions).toBe(historyLogOptions(head));
  });
  it('rejects an actual graft marker without reading its contents', async () => {
    const scratch = await mkdtemp(join(tmpdir(), 'g6-grafts-'));
    const path = join(scratch, 'grafts');
    try {
      await writeFile(path, 'fixture');
      await expect(
        proveHistoryScope(
          '.',
          ref,
          reader({
            'rev-parse --path-format=absolute --git-path info/grafts': path,
          }),
        ),
      ).rejects.toThrow('Grafted');
    } finally {
      await rm(scratch, { recursive: true, force: true });
    }
  });
  it('constructs full reachable merge-diff scope from an exact descendant', async () => {
    const calls: string[][] = [];
    const proof = await proveHistoryScope('.', ref, reader({}, calls));
    expect(proof.logOptions).toBe(
      `--full-history --diff-merges=first-parent ${ref} --`,
    );
    expect(proof).toMatchObject({
      anchor: HISTORY_POLICY_ANCHOR,
      anchorReachable: true,
      shallow: false,
      reachableCommits: 427,
      alteredHistory: false,
    });
    expect(calls).toContainEqual([
      'merge-base',
      '--is-ancestor',
      HISTORY_POLICY_ANCHOR,
      ref,
    ]);
  });
  for (const [key, value] of [
    ['rev-parse --verify HEAD^{commit}', 'b'.repeat(40)],
    [`rev-parse --verify ${ref}^{commit}`, 'b'.repeat(40)],
    ['rev-parse --is-shallow-repository', 'true'],
    ['for-each-ref --format=%(refname) refs/replace/', 'refs/replace/unknown'],
    [`rev-list --count ${ref}`, '421'],
    [`rev-list --count ${ref}`, 'unknown'],
  ])
    it(`rejects unproved scope ${key} ${value}`, async () => {
      await expect(
        proveHistoryScope('.', ref, reader({ [key!]: value! })),
      ).rejects.toThrow();
    });
  it('keeps failed ancestry metadata terminal', async () => {
    const normal = reader();
    await expect(
      proveHistoryScope('.', ref, (args, root) => {
        if (args[0] === 'merge-base') throw new Error('Missing ancestor.');
        return normal(args, root);
      }),
    ).rejects.toThrow('Missing ancestor');
    expect(() => historyLogOptions('HEAD')).toThrow('Exact');
  });
});
