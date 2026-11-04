/**
 * @fileoverview Prove immutable full-reachable history scope before starting a scanner.
 * @module scripts/security/history-scope
 */
import { spawnSync } from 'node:child_process';
import { lstat } from 'node:fs/promises';
import { HISTORY_POLICY_ANCHOR, historyLogOptions } from './history-result.js';

/** Read-only Git metadata adapter; never accepts a shell command. */
export type HistoryGitReader = (args: string[], root: string) => string;

/** Bound metadata reads; a signal, diagnostic or missing object cannot prove scope. */
export const readHistoryGit: HistoryGitReader = (args, root) => {
  const result = spawnSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    timeout: 10_000,
    maxBuffer: 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (
    result.error ||
    result.signal ||
    result.status !== 0 ||
    result.stderr.trim()
  )
    throw new Error('Cannot prove complete immutable history scope.');
  return result.stdout.trim();
};

/** A known descendant closure cannot legitimately produce a zero-fixture report. */
export async function proveHistoryScope(
  root: string,
  ref: string,
  read: HistoryGitReader = readHistoryGit,
) {
  const logOptions = historyLogOptions(ref);
  for (const key of [
    'GIT_DIR',
    'GIT_WORK_TREE',
    'GIT_COMMON_DIR',
    'GIT_SHALLOW_FILE',
    'GIT_REPLACE_REF_BASE',
    'GIT_OBJECT_DIRECTORY',
    'GIT_ALTERNATE_OBJECT_DIRECTORIES',
  ])
    if (process.env[key] !== undefined)
      throw new Error(
        'Repository environment overrides leave history scope unproved.',
      );
  const before = read(['rev-parse', '--verify', 'HEAD^{commit}'], root);
  if (
    before !== ref ||
    read(['rev-parse', '--verify', `${ref}^{commit}`], root) !== ref
  )
    throw new Error('History ref differs from exact checkout commit.');
  if (read(['rev-parse', '--is-shallow-repository'], root) !== 'false')
    throw new Error('Shallow history is incomplete.');
  if (read(['for-each-ref', '--format=%(refname)', 'refs/replace/'], root))
    throw new Error('Replacement history is unsupported.');
  const grafts = read(
    ['rev-parse', '--path-format=absolute', '--git-path', 'info/grafts'],
    root,
  );
  try {
    await lstat(grafts);
    throw new Error('Grafted history is unsupported.');
  } catch (error) {
    if (!(
      error &&
      typeof error === 'object' &&
      'code' in error &&
      error.code === 'ENOENT'
    ))
      throw error;
  }
  read(['merge-base', '--is-ancestor', HISTORY_POLICY_ANCHOR, ref], root);
  const count = read(['rev-list', '--count', ref], root);
  if (
    !/^\d+$/.test(count) ||
    !Number.isSafeInteger(Number(count)) ||
    Number(count) < 422
  )
    throw new Error('Complete known history closure was not proved.');
  return {
    before,
    logOptions,
    shallow: false,
    anchor: HISTORY_POLICY_ANCHOR,
    anchorReachable: true,
    reachableCommits: Number(count),
    alteredHistory: false,
  };
}
