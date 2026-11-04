#!/usr/bin/env bun
/**
 * @fileoverview Full reachable-history scan with exact verified tool and fixture disposition.
 * @module scripts/check-secret-history
 */
import { spawnSync } from 'node:child_process';
import { lstat, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { classifyHistoryScan } from './security/history-result.js';
import { extractHistoryScanner } from './security/release-tools.js';
import { sha256 } from './security/release-evidence.js';
import { TOOLCHAIN_PINS } from './security/toolchain-pins.js';
import { proveHistoryScope } from './security/history-scope.js';
import { snapshotScannerConfig } from './security/scanner-config.js';

if (import.meta.main) {
  let scratch: string | undefined;
  try {
    const args = process.argv.slice(2);
    if (
      args.length !== 4 ||
      args[0] !== '--head' ||
      !/^[0-9a-f]{40}$/.test(args[1] ?? '') ||
      args[2] !== '--archive' ||
      !args[3]
    )
      throw new Error(
        'Usage: bun scripts/check-secret-history.ts --head <exact-head> --archive <reviewed-gitleaks.tar.gz>',
      );
    if (
      process.env.GITLEAKS_CONFIG !== undefined ||
      process.env.GITLEAKS_CONFIG_TOML !== undefined
    )
      throw new Error('Custom scanner configuration is unsupported.');
    const root = fileURLToPath(new URL('..', import.meta.url));
    try {
      await lstat(join(root, '.gitleaks.toml'));
      throw new Error('Custom scanner configuration requires review.');
    } catch (error) {
      if (!(
        error &&
        typeof error === 'object' &&
        'code' in error &&
        error.code === 'ENOENT'
      ))
        throw error;
    }
    const profile =
      process.platform === 'linux' && process.arch === 'x64'
        ? 'linuxX64'
        : process.platform === 'darwin' && process.arch === 'arm64'
          ? 'darwinArm64'
          : undefined;
    if (!profile) throw new Error('Unsupported scanner platform.');
    const scope = await proveHistoryScope(root, args[1]!);
    scratch = await mkdtemp(join(tmpdir(), 'git-mcp-history-'));
    const rules = await snapshotScannerConfig(scratch);
    const binary = await extractHistoryScanner(resolve(args[3]), scratch);
    const version = spawnSync(binary, ['version'], {
      encoding: 'utf8',
      timeout: 5000,
    });
    if (
      version.error ||
      version.signal ||
      version.status !== 0 ||
      version.stderr.trim()
    )
      throw new Error('Cannot prove scanner version.');
    const reportPath = join(scratch, 'redacted-history.json');
    const scan = spawnSync(
      binary,
      [
        'git',
        '--config',
        rules.path,
        '--redact=100',
        '--no-banner',
        '--ignore-gitleaks-allow',
        '--gitleaks-ignore-path',
        rules.ignorePath,
        '--log-level',
        'error',
        `--log-opts=${scope.logOptions}`,
        '--report-format',
        'json',
        '--report-path',
        reportPath,
        '--timeout',
        '180',
        root,
      ],
      {
        cwd: root,
        encoding: 'utf8',
        timeout: 190_000,
        killSignal: 'SIGKILL',
        maxBuffer: 16 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    const afterScope = await proveHistoryScope(root, args[1]!);
    if (JSON.stringify(scope) !== JSON.stringify(afterScope))
      throw new Error('History scope changed during scan.');
    const reportBytes = await readFile(reportPath);
    const outcome = classifyHistoryScan(
      {
        ref: args[1]!,
        ...scope,
        after: afterScope.before,
        scannerVersion: version.stdout.trim(),
        scannerArchiveSha256: TOOLCHAIN_PINS.gitleaks[profile].sha256,
        rulesSha256: rules.rulesSha256,
        rulesBytes: rules.rulesBytes,
        rulesGitBlob: rules.rulesGitBlob,
        ignoreSha256: rules.ignoreSha256,
        exitCode: scan.status,
        stderr: scan.stderr,
        executionError: Boolean(scan.error || scan.signal),
        report: JSON.parse(reportBytes.toString('utf8')),
      },
      args[1]!,
      profile,
    );
    console.log(
      JSON.stringify(
        {
          ...outcome,
          ref: args[1],
          scannerVersion: version.stdout.trim(),
          scannerArchiveSha256: TOOLCHAIN_PINS.gitleaks[profile].sha256,
          rulesSha256: TOOLCHAIN_PINS.gitleaks.rulesSha256,
          rulesBytes: rules.rulesBytes,
          rulesGitBlob: rules.rulesGitBlob,
          ignoreSha256: rules.ignoreSha256,
          scope,
          scannerBinarySha256: sha256(await readFile(binary)),
          reportSha256: sha256(reportBytes),
        },
        null,
        2,
      ),
    );
    process.exitCode = outcome.status === 'accepted-history-fixtures' ? 0 : 1;
  } catch {
    console.error('History scan incomplete or failed; no acceptance evidence.');
    process.exitCode = 2;
  } finally {
    if (scratch) await rm(scratch, { recursive: true, force: true });
  }
}
