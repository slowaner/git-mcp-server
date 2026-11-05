/**
 * @fileoverview Verify vendor archives before extracting release tools.
 * @module scripts/security/release-tools
 */
import { spawnSync } from 'node:child_process';
import { readFile, writeFile, lstat, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { sha256 } from './release-evidence.js';
import { TOOLCHAIN_PINS } from './toolchain-pins.js';

/** Extract a verified scanner for history checks without changing global tools. */
export async function extractHistoryScanner(
  archive: string,
  scratch: string,
): Promise<string> {
  return extractTool(archive, scratch, 'gitleaks');
}

/** Exact operator-provided archives; no global tool resolution or auto-download. */
export interface ToolArchives {
  bun: string;
  gitleaks: string;
  publisher?: string;
}

/** Binaries extracted from reviewed bytes into private scratch. */
export interface ReleaseTools {
  bun: string;
  gitleaks: string;
  publisher?: string;
}

function platformKey(
  platform: string,
  arch: string,
): 'linuxX64' | 'darwinArm64' {
  if (platform === 'linux' && arch === 'x64') return 'linuxX64';
  if (platform === 'darwin' && arch === 'arm64') return 'darwinArm64';
  throw new Error('Unsupported release platform; no unpinned tool fallback.');
}

/** Never reuse one platform archive digest for another OS or architecture. */
export function publisherPlatform(platform: string, arch: string) {
  return TOOLCHAIN_PINS.publisher[platformKey(platform, arch)];
}

/** Version strings and URLs cannot substitute for checking actual archive bytes. */
export function verifyToolArchive(
  bytes: Uint8Array,
  expectedSha256: string,
): void {
  if (
    !/^[0-9a-f]{64}$/.test(expectedSha256) ||
    sha256(bytes) !== expectedSha256
  ) {
    throw new Error('Tool archive differs from reviewed vendor digest.');
  }
}

async function extractTool(
  archive: string,
  scratch: string,
  name: 'bun' | 'gitleaks' | 'publisher',
): Promise<string> {
  const key = platformKey(process.platform, process.arch);
  const pin = TOOLCHAIN_PINS[name][key];
  const bytes = await readFile(archive);
  verifyToolArchive(bytes, pin.sha256);
  const target = join(scratch, name);
  await mkdir(target, { mode: 0o700 });
  const snapshot = join(
    target,
    name === 'bun' ? 'archive.zip' : 'archive.tar.gz',
  );
  await writeFile(snapshot, bytes, { flag: 'wx', mode: 0o400 });
  const binaryName = name === 'publisher' ? 'mcp-publisher' : name;
  const args =
    name === 'bun'
      ? ['unzip', '-q', snapshot, '-d', target]
      : ['tar', '-xzf', snapshot, '-C', target, binaryName];
  const result = spawnSync(args[0]!, args.slice(1), {
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error || result.signal || result.status !== 0) {
    throw new Error('Pinned release tool extraction failed.');
  }
  const binary =
    name === 'bun'
      ? join(
          target,
          key === 'linuxX64' ? 'bun-linux-x64' : 'bun-darwin-aarch64',
          'bun',
        )
      : join(target, binaryName);
  const stat = await lstat(binary);
  if (!stat.isFile() || stat.isSymbolicLink())
    throw new Error('Invalid tool binary type.');
  return binary;
}

/** Bind the running Bun and each child tool to its exact vendor archive bytes. */
export async function initializeReleaseTools(
  archives: ToolArchives,
  scratch: string,
): Promise<ReleaseTools> {
  const bun = await extractTool(archives.bun, scratch, 'bun');
  if (
    Bun.version !== TOOLCHAIN_PINS.bun.version ||
    sha256(await readFile(process.execPath)) !== sha256(await readFile(bun))
  ) {
    throw new Error('Run release with the exact verified vendor Bun binary.');
  }
  const gitleaks = await extractTool(archives.gitleaks, scratch, 'gitleaks');
  if (archives.publisher) {
    return {
      bun,
      gitleaks,
      publisher: await extractTool(archives.publisher, scratch, 'publisher'),
    };
  }
  return { bun, gitleaks };
}
