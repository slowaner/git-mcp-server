/**
 * @fileoverview Identity-bound tag records, strict signing and native verification.
 * @module services/git/providers/cli/operations/tags/tag
 */
import type { RequestContext } from '@/utils/index.js';
import type {
  GitOperationContext,
  GitTagInfo,
  GitTagOptions,
  GitTagResult,
} from '../../../../types.js';
import { mapGitError, shouldSignCommits } from '../../utils/index.js';
import { objectReadBudget } from '../../utils/object-read-budget.js';
import {
  parseTagReferences,
  readTagRecord,
} from '../../utils/structured-object-reader.js';
import { parseGitObject } from '../../utils/git-object-reader.js';
import {
  createWithSigningPolicy,
  signingPolicy,
} from '../../utils/signing-policy.js';
import {
  verifySignatureStatus,
  type SignatureType,
} from '../../utils/signature-verification.js';

const REF_FORMAT = '--format=%(refname)%00%(objectname)%00%(objecttype)';

/** Signature format comes only from hash-validated stored armor, not prose. */
function signatureType(message: string): SignatureType | undefined {
  const armor =
    /(?:^|\n)-----BEGIN (PGP SIGNATURE|SSH SIGNATURE|SIGNED MESSAGE)-----\r?\n/g;
  const matches = [...message.matchAll(armor)];
  const type = matches.at(-1)?.[1];
  return type === 'PGP SIGNATURE'
    ? 'gpg'
    : type === 'SSH SIGNATURE'
      ? 'ssh'
      : type === 'SIGNED MESSAGE'
        ? 'x509'
        : undefined;
}

/** Enumerate structural fields only; annotation text never frames tag records. */
export async function executeTag(
  options: GitTagOptions,
  context: GitOperationContext,
  execGit: (
    args: string[],
    cwd: string,
    ctx: RequestContext,
    options?: { allowNonZeroExit?: boolean },
  ) => Promise<{ stdout: string; stderr: string; exitCode?: number }>,
): Promise<GitTagResult> {
  const execute = (args: string[], soft = false) =>
    execGit(
      args,
      context.workingDirectory,
      context.requestContext,
      soft ? { allowNonZeroExit: true } : undefined,
    );
  const read = objectReadBudget((args) => execute(args), {
    maxBytes: 16 * 1024 * 1024,
    maxCalls: 4096,
  });
  const named = async () => {
    if (!options.tagName) throw new Error('Tag name is required');
    // Reuse structural ref validation before any ref is interpreted by Git.
    parseTagReferences(
      `refs/tags/${options.tagName}\0${'0'.repeat(40)}\0tag\n`,
    );
    const refs = parseTagReferences(
      (
        await read([
          'for-each-ref',
          REF_FORMAT,
          '--',
          `refs/tags/${options.tagName}`,
        ])
      ).stdout,
    );
    if (refs.length !== 1 || refs[0]!.name !== options.tagName)
      throw new Error('Tag reference is missing or ambiguous');
    return refs[0]!;
  };
  try {
    if (options.mode === 'list') {
      const limit = options.limit ?? 1000;
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
        throw new Error('Tag listing requires between 1 and 1000 records');
      const refs = parseTagReferences(
        (
          await read([
            'for-each-ref',
            REF_FORMAT,
            '--sort=-version:refname',
            '--sort=-creatordate',
            `--count=${limit}`,
            'refs/tags',
          ])
        ).stdout,
      );
      if (refs.length > limit) throw new Error('Unexpected tag record count');
      const tags: GitTagInfo[] = [];
      for (const ref of refs) tags.push(await readTagRecord(ref, read));
      return { mode: 'list', tags };
    }
    if (options.mode === 'create') {
      if (!options.tagName) throw new Error('Tag name is required');
      parseTagReferences(
        `refs/tags/${options.tagName}\0${'0'.repeat(40)}\0tag\n`,
      );
      let nativeSigning = false;
      if (!options.message && !options.annotated) {
        const config = await execute(
          ['config', '--type=bool', '--get', 'tag.gpgSign'],
          true,
        );
        if (config.exitCode !== 0 && config.exitCode !== 1)
          throw new Error(
            'Native tag.gpgSign boolean policy could not be read',
          );
        nativeSigning =
          config.exitCode === 0 && config.stdout.trim() === 'true';
      }
      const result = await createWithSigningPolicy(
        signingPolicy(shouldSignCommits()),
        async (sign) => {
          const args = ['tag'];
          if (sign) args.push('-s');
          if (options.message !== undefined)
            args.push(`--message=${options.message}`);
          else if (sign || options.annotated || nativeSigning)
            args.push(`--message=Tag ${options.tagName}`);
          if (options.force) args.push('--force');
          args.push('--', options.tagName!);
          if (options.commit) {
            if (options.commit.startsWith('-') || options.commit.includes('\0'))
              throw new Error('Invalid tag target');
            args.push(options.commit);
          }
          await execute(args);
        },
        async () => {
          const ref = await named();
          const object =
            ref.objectType === 'tag'
              ? parseGitObject(
                  ref.objectId,
                  'tag',
                  (await read(['cat-file', 'tag', ref.objectId])).stdout,
                )
              : undefined;
          return {
            signed:
              object !== undefined &&
              signatureType(object.message) !== undefined,
          };
        },
      );
      return {
        mode: 'create',
        created: options.tagName,
        signed: result.signed,
      };
    }
    if (options.mode === 'delete') {
      await named();
      await execute(['tag', '-d', '--', options.tagName!]);
      return { mode: 'delete', deleted: options.tagName! };
    }
    if (options.mode === 'verify') {
      const ref = await named();
      const object =
        ref.objectType === 'tag'
          ? parseGitObject(
              ref.objectId,
              'tag',
              (await read(['cat-file', 'tag', ref.objectId])).stdout,
            )
          : undefined;
      const type = object && signatureType(object.message);
      if (!type)
        return {
          mode: 'verify',
          verifiedTag: options.tagName!,
          verified: false,
          warning: 'Tag has no supported signature.',
        };
      // Pin verification to the immutable tag object inspected above.
      const verified = await execute(
        ['verify-tag', '--raw', ref.objectId],
        true,
      );
      const status = verifySignatureStatus(
        verified.stderr,
        verified.exitCode,
        type,
      );
      return {
        mode: 'verify',
        verifiedTag: options.tagName!,
        rawOutput: verified.stderr,
        ...status,
        ...(!status.verified
          ? { warning: 'Native signature verification did not succeed.' }
          : {}),
      };
    }
    throw new Error('Unknown tag operation mode');
  } catch (error) {
    throw mapGitError(error, 'tag');
  }
}
