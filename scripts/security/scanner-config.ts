/**
 * @fileoverview Exact official scanner rules, verified before explicit configuration.
 * @module scripts/security/scanner-config
 */
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from './release-evidence.js';
import { TOOLCHAIN_PINS } from './toolchain-pins.js';

/** Canonical source is separate from any auto-discovered repository config. */
export const SCANNER_CONFIG_PATH = fileURLToPath(
  new URL('./gitleaks.toml', import.meta.url),
);

/** Complete-byte proof; semantic similarity or a version label is insufficient. */
export function verifyScannerConfig(bytes: Uint8Array) {
  const digest = sha256(bytes);
  const blob = createHash('sha1')
    .update(`blob ${bytes.byteLength}\0`)
    .update(bytes)
    .digest('hex');
  if (
    digest !== TOOLCHAIN_PINS.gitleaks.rulesSha256 ||
    bytes.byteLength !== TOOLCHAIN_PINS.gitleaks.rulesBytes ||
    blob !== TOOLCHAIN_PINS.gitleaks.rulesGitBlob
  )
    throw new Error(
      'Scanner configuration differs from complete canonical input.',
    );
  return {
    rulesSha256: digest,
    rulesBytes: bytes.byteLength,
    rulesGitBlob: blob,
  };
}

/** Re-read exact source bytes so a stale verification cannot bless a changed file. */
export async function canonicalScannerConfig() {
  return {
    path: SCANNER_CONFIG_PATH,
    ...verifyScannerConfig(await readFile(SCANNER_CONFIG_PATH)),
  };
}

/** Private immutable scan inputs avoid auto-discovery and source-file drift. */
export async function snapshotScannerConfig(directory: string) {
  const bytes = await readFile(SCANNER_CONFIG_PATH);
  const proof = verifyScannerConfig(bytes);
  const path = join(directory, 'canonical-gitleaks.toml');
  const ignorePath = join(directory, 'empty-gitleaks.ignore');
  await writeFile(path, bytes, { flag: 'wx', mode: 0o400 });
  await writeFile(ignorePath, '', { flag: 'wx', mode: 0o400 });
  return { path, ignorePath, ignoreSha256: sha256(''), ...proof };
}
