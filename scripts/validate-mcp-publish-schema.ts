#!/usr/bin/env bun
/**
 * @fileoverview Explicit pre-tag sync or read-only pinned-schema validation.
 * @module scripts/validate-mcp-publish-schema
 * @description No automatic commits, authentication, registry writes or bypass flags.
 */
import { spawnSync } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import {
  synchronizedMetadata,
  validateReleaseMetadata,
} from './security/release-metadata.js';

/** Sync is forbidden on tagged HEAD; failed Git inspection blocks the write. */
export function assertMetadataSyncAllowed(
  status: number | null,
  tags: string,
): void {
  if (status !== 0 || tags.trim()) {
    throw new Error(
      'Metadata sync requires an untagged development HEAD and successful Git inspection.',
    );
  }
}

/** Legacy bypass flags and the implicit publish path fail closed. */
export async function metadataCommand(
  root: string,
  args: string[],
): Promise<void> {
  if (
    args.length !== 1 ||
    !['--sync-only', '--validate-only'].includes(args[0]!)
  ) {
    throw new Error(
      'Use --sync-only before review/tag or --validate-only. Publication requires the reviewed release bundle workflow.',
    );
  }
  const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  const server = JSON.parse(await readFile(join(root, 'server.json'), 'utf8'));
  if (args[0] === '--sync-only') {
    const tags = spawnSync('git', ['tag', '--points-at', 'HEAD'], {
      cwd: root,
      encoding: 'utf8',
      timeout: 5000,
      maxBuffer: 1024 * 1024,
    });
    assertMetadataSyncAllowed(
      tags.error || tags.signal ? null : tags.status,
      tags.stdout ?? '',
    );
    const synced = synchronizedMetadata(pkg, server);
    await validateReleaseMetadata(pkg, synced);
    await writeFile(
      join(root, 'server.json'),
      JSON.stringify(synced, null, 2) + '\n',
    );
    console.log(
      'Metadata prepared. Run checks, commit and review before creating a release tag.',
    );
    return;
  }
  await validateReleaseMetadata(pkg, server);
  console.log(
    'Metadata validated read-only. No commit, login or publication attempted.',
  );
}

if (import.meta.main) {
  try {
    await metadataCommand(
      fileURLToPath(new URL('..', import.meta.url)),
      process.argv.slice(2),
    );
  } catch (error) {
    console.error(
      error instanceof Error ? error.message : 'Metadata gate failed.',
    );
    process.exitCode = 1;
  }
}
