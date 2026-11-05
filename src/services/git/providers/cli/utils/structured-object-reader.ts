/**
 * @fileoverview Read Git records by independent object identity, never message framing.
 * @module services/git/providers/cli/utils/structured-object-reader
 */
import type { GitCommitInfo, GitTagInfo } from '../../../types.js';
import {
  objectHeader,
  parseGitIdentity,
  parseGitObject,
  splitGitMessage,
  validateObjectId,
} from './git-object-reader.js';

import { recordGitExecutionFailure } from './execution-context.js';
import { GitExecutionError } from './execution-errors.js';

function invalidObject(message: string): GitExecutionError {
  return recordGitExecutionFailure(
    new GitExecutionError('INVALID_OUTPUT_FORMAT', message),
  );
}

/** Scoped executor supplied by the provider, including its policy and budgets. */
export type ReadObjectCommand = (
  args: string[],
) => Promise<{ stdout: string; stderr: string }>;

/** Read a single authenticated commit object; message contents cannot add records. */
export async function readCommitRecord(
  id: string,
  read: ReadObjectCommand,
  oneline = false,
): Promise<GitCommitInfo> {
  validateObjectId(id);
  const result = await read(['cat-file', 'commit', id]);
  const object = parseGitObject(id, 'commit', result.stdout);
  validateObjectId(objectHeader(object, 'tree'));
  const author = parseGitIdentity(objectHeader(object, 'author'));
  parseGitIdentity(objectHeader(object, 'committer'));
  const parents = (object.headers.get('parent') ?? []).map(validateObjectId);
  const { subject, body } = splitGitMessage(object.message);
  const record: GitCommitInfo = {
    hash: id,
    shortHash: id.slice(0, 7),
    subject,
  };
  if (!oneline) {
    Object.assign(record, {
      author: author.name,
      authorEmail: author.email,
      timestamp: author.timestamp,
      parents,
    });
    if (body) record.body = body;
  }
  return record;
}

/** Structural tag enumeration tuple, produced without contents or tagger fields. */
export interface GitTagReference {
  name: string;
  objectId: string;
  objectType: 'commit' | 'tag' | 'tree' | 'blob';
}

/** Parse only refnames/types/OIDs: none can contain the field/newline delimiters. */
export function parseTagReferences(output: string): GitTagReference[] {
  if (!output) return [];
  const rows = output.endsWith('\n')
    ? output.slice(0, -1).split('\n')
    : output.split('\n');
  const refs: GitTagReference[] = [];
  const seen = new Set<string>();
  for (const row of rows) {
    const fields = row.split('\0');
    if (fields.length !== 3) throw invalidObject('Malformed Git tag reference');
    const [ref, id, type] = fields;
    if (
      !ref?.startsWith('refs/tags/') ||
      /[\x00-\x20\x7f~^:?*\[\\]/.test(ref) ||
      ref.includes('..') ||
      ref.includes('@{') ||
      ref.endsWith('/') ||
      ref.includes('//') ||
      ref
        .split('/')
        .some(
          (part) =>
            part.startsWith('.') ||
            part.endsWith('.') ||
            part.endsWith('.lock'),
        )
    )
      throw invalidObject('Invalid Git tag reference');
    if (seen.has(ref)) throw invalidObject('Duplicate Git tag reference');
    if (!id || !['commit', 'tag', 'tree', 'blob'].includes(type ?? ''))
      throw invalidObject('Invalid Git tag object');
    seen.add(ref);
    refs.push({
      name: ref.slice('refs/tags/'.length),
      objectId: validateObjectId(id),
      objectType: type as GitTagReference['objectType'],
    });
  }
  return refs;
}

/**
 * Resolve annotated/nested tags by immutable IDs with a cycle/depth guard.
 * The named outer tag owns its annotation; nested content cannot forge tag rows.
 */
export async function readTagRecord(
  ref: GitTagReference,
  read: ReadObjectCommand,
): Promise<GitTagInfo> {
  let id = validateObjectId(ref.objectId);
  let type = ref.objectType;
  const tag: GitTagInfo = { name: ref.name, commit: id };
  const seen = new Set<string>();
  while (type === 'tag') {
    if (seen.has(id) || seen.size >= 16)
      throw invalidObject('Git tag chain exceeds supported depth');
    seen.add(id);
    const result = await read(['cat-file', 'tag', id]);
    const object = parseGitObject(id, 'tag', result.stdout);
    // The stored tag name may differ from a ref alias; never treat it as a row identity.
    objectHeader(object, 'tag');
    if (seen.size === 1) {
      const { subject, body } = splitGitMessage(object.message);
      if (subject) tag.message = subject;
      if (body) tag.annotationBody = body;
      const taggerValues = object.headers.get('tagger');
      if (taggerValues) {
        const identity = parseGitIdentity(objectHeader(object, 'tagger'));
        tag.tagger = `${identity.name} <${identity.email}>`;
        tag.timestamp = identity.timestamp;
      }
    }
    id = validateObjectId(objectHeader(object, 'object'));
    const targetType = objectHeader(object, 'type');
    if (!['commit', 'tag', 'tree', 'blob'].includes(targetType))
      throw invalidObject('Invalid tag target type');
    type = targetType as GitTagReference['objectType'];
  }
  tag.commit = id;
  return tag;
}
