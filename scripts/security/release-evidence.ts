/**
 * @fileoverview Immutable release identity and fail-closed publication sequencing.
 * @module scripts/security/release-evidence
 */
import { createHash } from 'node:crypto';

/** SHA-256 identifies bytes, independent of paths or timestamps. */
export function sha256(bytes: string | Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Deterministic JSON for comparing registry metadata independently of key order. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object' && value !== null) {
    return `{${Object.entries(value)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(',')}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined)
    throw new Error('Unsupported registry metadata value.');
  return encoded;
}

/** Hash the exact MCP payload separately from source metadata with legacy mcpName. */
export function registryManifest(source: string): string {
  const value = record(JSON.parse(source));
  const { mcpName: _legacy, ...manifest } = value;
  return canonicalJson(manifest);
}

/** Source evidence collected with argv-based Git calls in the release checkout. */
export interface ReleaseSource {
  head: string;
  tree: string;
  tag: string;
  tagCommit: string;
  tagObject: string;
  tagType: string;
  status: string;
  packageJson: string;
  lockfile: string;
  serverJson: string;
  bunVersion: string;
}

/** Reviewed identity is explicit; the current checkout cannot choose it for itself. */
export interface ReviewedRelease {
  commit: string;
  tag: string;
}

/** Stable identity recorded in the bundle and checked before each destination. */
export interface ReleaseIdentity {
  commit: string;
  tree: string;
  tag: string;
  tagObject: string;
  version: string;
  packageName: string;
  serverName: string;
  bunVersion: string;
  packageSha256: string;
  lockSha256: string;
  serverSha256: string;
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Expected metadata object.');
  }
  return value as Record<string, unknown>;
}

/** Reject missing metadata instead of synchronizing files after the source gate. */
export function verifyReleaseSource(
  source: ReleaseSource,
  reviewed: ReviewedRelease,
): ReleaseIdentity {
  const pkg = record(JSON.parse(source.packageJson));
  const server = record(JSON.parse(source.serverJson));
  if (
    !/^[0-9a-f]{40}$/.test(reviewed.commit) ||
    source.head !== reviewed.commit ||
    source.tagCommit !== reviewed.commit ||
    !/^[0-9a-f]{40}$/.test(source.tagObject) ||
    !/^[0-9a-f]{40}$/.test(source.tree) ||
    source.tagType !== 'tag' ||
    source.tag !== reviewed.tag ||
    source.status !== ''
  ) {
    throw new Error(
      'Release requires clean, reviewed HEAD and its exact annotated tag.',
    );
  }
  if (
    typeof pkg.version !== 'string' ||
    !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(pkg.version) ||
    reviewed.tag !== `v${pkg.version}` ||
    typeof pkg.name !== 'string' ||
    !/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(pkg.name) ||
    typeof pkg.mcpName !== 'string' ||
    server.name !== pkg.mcpName ||
    server.mcpName !== pkg.mcpName ||
    server.version !== pkg.version ||
    !Array.isArray(server.packages) ||
    server.packages.length === 0 ||
    !server.packages.every((entry: unknown) => {
      const item = record(entry);
      return (
        item.registryType === 'npm' &&
        item.registryBaseUrl === 'https://registry.npmjs.org' &&
        item.identifier === pkg.name &&
        item.version === pkg.version
      );
    })
  ) {
    throw new Error(
      'Release metadata drift; synchronize and review before tagging.',
    );
  }
  if (
    pkg.packageManager !== `bun@${source.bunVersion}` ||
    !source.lockfile.trim()
  ) {
    throw new Error(
      'Release toolchain or lockfile does not match approved inputs.',
    );
  }
  return {
    commit: source.head,
    tree: source.tree,
    tag: source.tag,
    tagObject: source.tagObject,
    version: pkg.version,
    packageName: pkg.name,
    serverName: pkg.mcpName,
    bunVersion: source.bunVersion,
    packageSha256: sha256(source.packageJson),
    lockSha256: sha256(source.lockfile),
    serverSha256: sha256(source.serverJson),
  };
}

/** Each artifact is hashed once and rechecked against the same receipt manifest. */
export interface ReleaseBundle {
  schemaVersion: 1;
  source: ReleaseIdentity;
  files: Record<string, string>;
}

/** Check exact inventory and bytes; extra, missing, or replaced files abort. */
export function verifyBundleFiles(
  bundle: ReleaseBundle,
  files: Record<string, Uint8Array>,
): void {
  const required = [
    'source.tar',
    'package.json',
    'bun.lock',
    'server.json',
    'registry-manifest.json',
    'package.tgz',
    'build.json',
    'sbom.json',
    'checks.json',
  ].sort();
  if (
    bundle.schemaVersion !== 1 ||
    JSON.stringify(Object.keys(bundle.files).sort()) !==
      JSON.stringify(required) ||
    JSON.stringify(Object.keys(files).sort()) !== JSON.stringify(required)
  ) {
    throw new Error('Incomplete or unsupported release bundle inventory.');
  }
  for (const file of required) {
    if (
      !/^[0-9a-f]{64}$/.test(bundle.files[file] ?? '') ||
      sha256(files[file]!) !== bundle.files[file]
    ) {
      throw new Error(`Release bundle byte mismatch: ${file}`);
    }
  }
  if (
    bundle.files['package.json'] !== bundle.source.packageSha256 ||
    bundle.files['bun.lock'] !== bundle.source.lockSha256 ||
    bundle.files['server.json'] !== bundle.source.serverSha256 ||
    bundle.files['registry-manifest.json'] !==
      sha256(
        registryManifest(Buffer.from(files['server.json']!).toString('utf8')),
      )
  ) {
    throw new Error('Release bundle metadata differs from reviewed source.');
  }
}

/** Destination verification is separate from a successful upload command. */
export interface PublicationReceipt {
  destination: 'npm' | 'mcp';
  version: string;
  identity: string;
  sha256: string;
}

/** Injectable side effects allow dry-run regression tests without registry access. */
export interface ReleaseOperations {
  snapshot(): Promise<ReleaseSource>;
  checks(): Promise<void>;
  buildBundle(source: ReleaseIdentity): Promise<ReleaseBundle>;
  verifyBundle(bundle: ReleaseBundle): Promise<void>;
  publish(bundle: ReleaseBundle, destination: 'npm' | 'mcp'): Promise<void>;
  receipt(
    bundle: ReleaseBundle,
    destination: 'npm' | 'mcp',
  ): Promise<PublicationReceipt>;
  saveReceipt(receipt: PublicationReceipt): Promise<void>;
}

/**
 * Run checks/build from reviewed tagged bytes, then verify before every upload.
 * No fixer, Git mutation, automatic commit, duplicate-version shortcut or retry.
 * Receipt persistence precedes the next destination, preserving partial success.
 */
export async function runRelease(
  reviewed: ReviewedRelease,
  ops: ReleaseOperations,
  publish = false,
): Promise<ReleaseBundle> {
  const source = verifyReleaseSource(await ops.snapshot(), reviewed);
  const assertUnchanged = async () => {
    const current = verifyReleaseSource(await ops.snapshot(), reviewed);
    if (JSON.stringify(current) !== JSON.stringify(source)) {
      throw new Error('Release source changed after the source gate.');
    }
  };
  await ops.checks();
  await assertUnchanged();
  const bundle = await ops.buildBundle(source);
  if (JSON.stringify(bundle.source) !== JSON.stringify(source)) {
    throw new Error('Release build claims a different source identity.');
  }
  await assertUnchanged();
  await ops.verifyBundle(bundle);
  if (!publish) return bundle;

  for (const destination of ['npm', 'mcp'] as const) {
    await assertUnchanged();
    await ops.verifyBundle(bundle);
    await ops.publish(bundle, destination);
    const receipt = await ops.receipt(bundle, destination);
    const expectedIdentity =
      destination === 'npm' ? source.packageName : source.serverName;
    const expectedHash =
      destination === 'npm'
        ? bundle.files['package.tgz']
        : bundle.files['registry-manifest.json'];
    if (
      receipt.destination !== destination ||
      receipt.version !== source.version ||
      receipt.identity !== expectedIdentity ||
      receipt.sha256 !== expectedHash
    ) {
      throw new Error(`Unverified ${destination} destination receipt.`);
    }
    await ops.saveReceipt(receipt);
  }
  return bundle;
}
