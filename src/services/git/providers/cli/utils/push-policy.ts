/**
 * @fileoverview Explicit destructive push policy and normalized destination refs.
 * @module services/git/providers/cli/utils/push-policy
 */

/** Policy input deliberately independent of tool schemas and provider state. */
export interface PushPolicyInput {
  force?: boolean;
  forceWithLease?: boolean;
  delete?: boolean;
  confirmed?: boolean;
  tags?: boolean;
  branch?: string;
  remoteBranch?: string;
}

/** Reject revision/refspec syntax; only one concrete branch or tag is a target. */
export function normalizePushRef(value: string): string {
  for (const character of value) {
    const point = character.codePointAt(0)!;
    if (point >= 0xd800 && point <= 0xdfff)
      throw new Error('Invalid push destination Unicode');
  }
  if (
    value === 'HEAD' ||
    value === '@' ||
    value.startsWith('-') ||
    value.startsWith('+') ||
    value.includes('..') ||
    value.includes('@{') ||
    /[\x00-\x20\x7f~^:?*\[\\]/.test(value)
  )
    throw new Error('Push requires a concrete destination ref');
  const ref = value.startsWith('refs/') ? value : `refs/heads/${value}`;
  if (
    !/^refs\/(?:heads|tags)\/.+/.test(ref) ||
    ref.endsWith('/') ||
    ref.includes('//') ||
    ref
      .split('/')
      .some(
        (part) =>
          !part ||
          part.startsWith('.') ||
          part.endsWith('.') ||
          part.endsWith('.lock'),
      )
  )
    throw new Error('Invalid push destination ref');
  return ref;
}

/**
 * Confirmation is a caller assertion, never independent human consent. Require
 * it on every destructive operation, including detached/default/custom refs.
 * Host approval and provider protection remain independent enforcement layers.
 */
export function assertPushPolicy(options: PushPolicyInput): void {
  if (
    (options.force || options.forceWithLease || options.delete) &&
    options.confirmed !== true
  )
    throw new Error(
      'Explicit caller confirmation required for every force, lease or delete push',
    );
  if (options.force && options.forceWithLease)
    throw new Error('Choose force or forceWithLease');
  if (
    options.delete &&
    (options.force || options.forceWithLease || options.tags)
  )
    throw new Error('Delete push cannot combine force, lease or all tags');
  if (options.remoteBranch) normalizePushRef(options.remoteBranch);
  if (options.branch && options.branch !== 'HEAD')
    normalizePushRef(options.branch);
  if (options.delete && !options.remoteBranch && !options.branch)
    throw new Error('Delete push requires an explicit destination ref');
}
