/**
 * @fileoverview Identity-checked Git object parsing without message delimiters.
 * @module services/git/providers/cli/utils/git-object-reader
 */
import { createHash } from 'node:crypto';

import { recordGitExecutionFailure } from './execution-context.js';
import { GitExecutionError } from './execution-errors.js';

function invalidObject(message: string): GitExecutionError {
  return recordGitExecutionFailure(
    new GitExecutionError('INVALID_OUTPUT_FORMAT', message),
  );
}

/** Only complete SHA-1 or SHA-256 object IDs can be structural identities. */
export function validateObjectId(id: string): string {
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(id))
    throw invalidObject('Invalid Git object identity');
  return id;
}

/** Parse identity-only enumeration; repository messages cannot add records. */
export function parseObjectIds(output: string): string[] {
  if (output === '') return [];
  const lines = output.endsWith('\n')
    ? output.slice(0, -1).split('\n')
    : output.split('\n');
  const ids = lines.map(validateObjectId);
  if (new Set(ids).size !== ids.length)
    throw invalidObject('Duplicate Git object identity');
  return ids;
}

/** Decoded object with exact message bytes for supported UTF-8 Git objects. */
export interface GitObjectRecord {
  headers: ReadonlyMap<string, readonly string[]>;
  message: string;
}

/**
 * Authenticate framing against the object ID before reading headers or message.
 * Non-UTF-8 objects fail closed when a string executor cannot round-trip bytes.
 */
export function parseGitObject(
  id: string,
  type: 'commit' | 'tag',
  raw: string,
): GitObjectRecord {
  validateObjectId(id);
  const bytes = Buffer.from(raw, 'utf8');
  const actual = createHash(id.length === 40 ? 'sha1' : 'sha256')
    .update(`${type} ${bytes.length}\0`)
    .update(bytes)
    .digest('hex');
  if (actual !== id)
    throw invalidObject('Git object identity or encoding mismatch');
  const boundary = raw.indexOf('\n\n');
  if (boundary < 0) throw invalidObject('Malformed Git object headers');
  const headers = new Map<string, string[]>();
  let previous: string | undefined;
  for (const line of raw.slice(0, boundary).split('\n')) {
    if (line.startsWith(' ')) {
      if (!previous) throw invalidObject('Malformed Git continuation header');
      const values = headers.get(previous)!;
      values[values.length - 1] += `\n${line.slice(1)}`;
      continue;
    }
    const match = /^([a-z][a-z0-9-]*) (.*)$/.exec(line);
    if (!match) throw invalidObject('Malformed Git object header');
    previous = match[1]!;
    const values = headers.get(previous) ?? [];
    values.push(match[2]!);
    headers.set(previous, values);
  }
  return { headers, message: raw.slice(boundary + 2) };
}

/** Require one structural field; duplicate headers cannot override identity. */
export function objectHeader(object: GitObjectRecord, name: string): string {
  const values = object.headers.get(name);
  if (values?.length !== 1)
    throw invalidObject('Missing or duplicate Git object header');
  return values[0]!;
}

/** Native Git identity header, parsed separately from all message content. */
export function parseGitIdentity(value: string): {
  name: string;
  email: string;
  timestamp: number;
} {
  const match = /^(.*) <([^<>\n]*)> ([0-9]+) [+-][0-9]{4}$/.exec(value);
  if (!match || !Number.isSafeInteger(Number(match[3])))
    throw invalidObject('Malformed Git identity header');
  return { name: match[1]!, email: match[2]!, timestamp: Number(match[3]) };
}

/** Preserve exact body including control characters and trailing newlines. */
export function splitGitMessage(message: string): {
  subject: string;
  body: string;
} {
  const boundary = message.indexOf('\n\n');
  const subject =
    boundary < 0 ? message.replace(/\n$/, '') : message.slice(0, boundary);
  return {
    subject: subject.replace(/\n/g, ' '),
    body: boundary < 0 ? '' : message.slice(boundary + 2),
  };
}
