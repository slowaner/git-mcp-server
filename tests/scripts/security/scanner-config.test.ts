/**
 * @fileoverview Canonical scanner bytes cannot be substituted or normalized.
 * @module tests/scripts/security/scanner-config
 */
import { describe, expect, it } from 'bun:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  SCANNER_CONFIG_PATH,
  snapshotScannerConfig,
  verifyScannerConfig,
} from '../../../scripts/security/scanner-config.js';
import { TOOLCHAIN_PINS } from '../../../scripts/security/toolchain-pins.js';

describe('complete canonical scanner inputs', () => {
  it('binds actual official full bytes to SHA256, size and Git blob', async () => {
    const bytes = await readFile(SCANNER_CONFIG_PATH);
    expect(verifyScannerConfig(bytes)).toEqual({
      rulesSha256: TOOLCHAIN_PINS.gitleaks.rulesSha256,
      rulesBytes: 97731,
      rulesGitBlob: '256f64790ea6d954f0041024be2938089ae1e7a7',
    });
    for (const changed of [
      bytes.subarray(0, -1),
      Buffer.concat([bytes, Buffer.from('\n')]),
      Buffer.from('untrusted rules'),
    ])
      expect(() => verifyScannerConfig(changed)).toThrow('complete canonical');
  });
  it('snapshots verified rules and an exactly empty ignore without overwriting', async () => {
    const scratch = await mkdtemp(join(tmpdir(), 'g6-rules-'));
    try {
      const proof = await snapshotScannerConfig(scratch);
      expect(await readFile(proof.path)).toEqual(
        await readFile(SCANNER_CONFIG_PATH),
      );
      expect((await readFile(proof.ignorePath)).byteLength).toBe(0);
      expect(proof.ignoreSha256).toBe(
        TOOLCHAIN_PINS.gitleaks.emptyIgnoreSha256,
      );
      await expect(snapshotScannerConfig(scratch)).rejects.toThrow();
    } finally {
      await rm(scratch, { recursive: true, force: true });
    }
  });
});
