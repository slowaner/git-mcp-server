/**
 * @fileoverview Independent Git object hashing for consumer fixtures.
 * @module tests/security/helpers/git-object-fixture
 */
import { createHash } from 'node:crypto';

/** Hash exact stored bytes independently from production parsers. */
export function objectFixture(type: 'commit' | 'tag', raw: string) {
  const id = createHash('sha1')
    .update(type + ' ' + Buffer.byteLength(raw) + '\0')
    .update(raw)
    .digest('hex');
  return { id, raw };
}

/** Construct a stored commit, preserving caller-provided message bytes. */
export function commitFixture(
  options: {
    message?: string;
    author?: string;
    email?: string;
    timestamp?: number;
    parents?: string[];
    signatureHeader?: string;
  } = {},
) {
  const identity =
    (options.author ?? 'Fixture Author') +
    ' <' +
    (options.email ?? 'fixture@example.invalid') +
    '> ' +
    (options.timestamp ?? 1700000000) +
    ' +0000';
  return objectFixture(
    'commit',
    'tree ' +
      '0'.repeat(40) +
      '\n' +
      (options.parents ?? []).map((id) => 'parent ' + id + '\n').join('') +
      'author ' +
      identity +
      '\ncommitter ' +
      identity +
      '\n' +
      (options.signatureHeader
        ? options.signatureHeader + ' signature\n'
        : '') +
      '\n' +
      (options.message ?? 'subject\n\nbody\n'),
  );
}

/** Construct an annotated tag pointing at an exact immutable commit. */
export function tagFixture(commit: string, message = 'annotation\n') {
  return objectFixture(
    'tag',
    'object ' +
      commit +
      '\ntype commit\ntag v1\ntagger Tag Fixture <tag@example.invalid> 1700000000 +0000\n\n' +
      message,
  );
}
