#!/usr/bin/env bun
/**
 * @fileoverview Prepare one reviewed release bundle, or explicitly publish its exact bytes.
 * @module scripts/release
 */
import { spawnSync } from 'node:child_process';
import {
  readFile,
  writeFile,
  readdir,
  lstat,
  mkdir,
  mkdtemp,
  rm,
  realpath,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import {
  basename,
  delimiter,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
} from 'node:path';
import { fileURLToPath } from 'node:url';
import { createLockInventory } from './security/lock-inventory.js';
import { validateReleaseMetadata } from './security/release-metadata.js';
import {
  canonicalJson,
  registryManifest,
  runRelease,
  sha256,
  verifyBundleFiles,
  type ReleaseBundle,
  type ReleaseOperations,
  type ReleaseSource,
  type ReviewedRelease,
} from './security/release-evidence.js';
import {
  initializeReleaseTools,
  type ReleaseTools,
  type ToolArchives,
} from './security/release-tools.js';
import { TOOLCHAIN_PINS } from './security/toolchain-pins.js';
import {
  canonicalScannerConfig,
  snapshotScannerConfig,
} from './security/scanner-config.js';
import { assertZeroSecretScan } from './security/secret-result.js';
import {
  completeSourceArchive,
  sourceTreeEntries,
} from './security/release-source-archive.js';
import { publisherDestinationGate } from './security/release-publisher-destination.js';

function sourceArchive(root: string, commit: string): Buffer {
  const entries = sourceTreeEntries(
    command(['git', 'ls-tree', '-r', '-z', '--full-tree', commit], root),
  );
  return completeSourceArchive(
    entries.map((entry) => ({
      ...entry,
      bytes: command(['git', 'cat-file', 'blob', entry.oid], root),
    })),
  );
}

/** Explicit reviewed source and local archive/bundle inputs. No implicit publication. */
export interface ReleaseOptions {
  reviewed: ReviewedRelease;
  archives: ToolArchives;
  output: string;
  publish: boolean;
  bundleDigest?: string;
}

/** Parse before any filesystem/network work; legacy bypass switches are rejected. */
export function parseReleaseArgs(args: string[]): ReleaseOptions {
  const values = new Map<string, string>();
  let publish = false;
  const allowed = new Set([
    '--commit',
    '--tag',
    '--output',
    '--bun-archive',
    '--gitleaks-archive',
    '--publisher-archive',
    '--bundle-sha256',
  ]);
  for (let index = 0; index < args.length; index++) {
    const key = args[index]!;
    if (key === '--publish' && !publish) {
      publish = true;
      continue;
    }
    const value = args[++index];
    if (
      !allowed.has(key) ||
      values.has(key) ||
      !value ||
      value.startsWith('--')
    )
      throw new Error('Invalid or duplicate release argument.');
    values.set(key, value);
  }
  const required = (key: string) => {
    const value = values.get(key);
    if (!value) throw new Error(`Required release argument: ${key}`);
    return value;
  };
  const commit = required('--commit');
  const tag = required('--tag');
  if (
    !/^[0-9a-f]{40}$/.test(commit) ||
    !/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(tag)
  )
    throw new Error('Require an exact reviewed commit and version tag.');
  const archives: ToolArchives = {
    bun: resolve(required('--bun-archive')),
    gitleaks: resolve(required('--gitleaks-archive')),
  };
  const options: ReleaseOptions = {
    reviewed: { commit, tag },
    archives,
    output: resolve(required('--output')),
    publish,
  };
  if (publish) {
    archives.publisher = resolve(required('--publisher-archive'));
    const digest = required('--bundle-sha256');
    if (!/^[0-9a-f]{64}$/.test(digest))
      throw new Error('Require the separately recorded bundle SHA-256.');
    options.bundleDigest = digest;
  } else if (
    values.has('--bundle-sha256') ||
    values.has('--publisher-archive')
  ) {
    throw new Error('Publication inputs require explicit --publish.');
  }
  return options;
}

function command(args: string[], cwd: string, timeout = 120_000): Buffer {
  const result = spawnSync(args[0]!, args.slice(1), {
    cwd,
    timeout,
    killSignal: 'SIGKILL',
    maxBuffer: 128 * 1024 * 1024,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      PATH: `${dirname(process.execPath)}${delimiter}${process.env.PATH ?? ''}`,
    },
  });
  if (result.error || result.signal || result.status !== 0) {
    // Never echo registry credentials, opaque child stderr or command arguments.
    throw new Error(
      `Release command failed: ${basename(args[0]!)} (exit ${result.status ?? 'unknown'}). Publication state must be checked before retry.`,
    );
  }
  return result.stdout;
}

async function snapshot(
  root: string,
  reviewed: ReviewedRelease,
): Promise<ReleaseSource> {
  const git = (...args: string[]) =>
    command(['git', ...args], root)
      .toString('utf8')
      .trim();
  return {
    head: git('rev-parse', '--verify', 'HEAD^{commit}'),
    tree: git('rev-parse', '--verify', 'HEAD^{tree}'),
    tag: reviewed.tag,
    tagCommit: git(
      'rev-parse',
      '--verify',
      `refs/tags/${reviewed.tag}^{commit}`,
    ),
    tagObject: git('rev-parse', '--verify', `refs/tags/${reviewed.tag}^{tag}`),
    tagType: git('cat-file', '-t', `refs/tags/${reviewed.tag}`),
    status: git('status', '--porcelain=v1', '--untracked-files=all'),
    packageJson: await readFile(join(root, 'package.json'), 'utf8'),
    lockfile: await readFile(join(root, 'bun.lock'), 'utf8'),
    serverJson: await readFile(join(root, 'server.json'), 'utf8'),
    bunVersion: Bun.version,
  };
}

async function buildFiles(root: string): Promise<Record<string, string>> {
  const files: Record<string, string> = {};
  const walk = async (directory: string) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink())
        throw new Error('Build contains a symbolic link.');
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile())
        files[relative(join(root, 'dist'), path)] = sha256(
          await readFile(path),
        );
      else throw new Error('Unsupported build file type.');
    }
  };
  await walk(join(root, 'dist'));
  if (!files['index.js'])
    throw new Error('Expected release entry point missing.');
  return files;
}

function verifyPackedFiles(
  root: string,
  reviewed: ReviewedRelease,
  archive: string,
  build: Record<string, string>,
  packageJson: string,
): void {
  const listing = command(['tar', '-tzf', archive], root)
    .toString('utf8')
    .trim()
    .split('\n');
  const found = new Set<string>();
  for (const name of listing) {
    if (name.endsWith('/')) continue;
    if (
      !name.startsWith('package/') ||
      /[\x00-\x1f\x7f]/.test(name) ||
      name.split('/').some((part) => part === '..' || !part)
    )
      throw new Error('Unsafe package archive entry.');
    const path = name.slice('package/'.length);
    if (found.has(path)) throw new Error('Duplicate package archive entry.');
    found.add(path);
    const bytes = command(['tar', '-xOzf', archive, '--', name], root);
    if (path === 'package.json') {
      if (
        canonicalJson(JSON.parse(bytes.toString('utf8'))) !==
        canonicalJson(JSON.parse(packageJson))
      )
        throw new Error(
          'Packed package metadata differs from reviewed source.',
        );
    } else if (path.startsWith('dist/')) {
      if (build[path.slice(5)] !== sha256(bytes))
        throw new Error('Packed build differs from checked build.');
    } else if (
      sha256(bytes) !==
      sha256(command(['git', 'show', `${reviewed.commit}:${path}`], root))
    ) {
      throw new Error('Package file differs from reviewed source.');
    }
  }
  if (
    !found.has('package.json') ||
    Object.keys(build).some((path) => !found.has(`dist/${path}`))
  )
    throw new Error('Packed build is incomplete.');
}

async function outsideOutput(root: string, output: string): Promise<void> {
  const candidate = join(await realpath(dirname(output)), basename(output));
  const rel = relative(await realpath(root), candidate);
  if (
    !rel ||
    (!rel.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) &&
      !isAbsolute(rel))
  )
    throw new Error('Release bundle must be outside the source checkout.');
}

async function bundleFiles(
  output: string,
): Promise<Record<string, Uint8Array>> {
  const result: Record<string, Uint8Array> = {};
  for (const name of await readdir(output)) {
    if (name === 'provenance.json') continue;
    const stat = await lstat(join(output, name));
    if (!stat.isFile() || stat.isSymbolicLink())
      throw new Error('Unsupported release bundle entry.');
    result[name] = await readFile(join(output, name));
  }
  return result;
}

async function responseBytes(url: string, limit: number): Promise<Uint8Array> {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(30_000),
    redirect: 'error',
  });
  if (!response.ok || !response.body)
    throw new Error('Destination verification request failed.');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) break;
    total += chunk.value.length;
    if (total > limit) {
      await reader.cancel();
      throw new Error('Destination verification output exceeded budget.');
    }
    chunks.push(chunk.value);
  }
  return Buffer.concat(chunks, total);
}

/** Concrete effects are separate from protocol ordering, which is tested offline. */
export function releaseOperations(
  root: string,
  options: ReleaseOptions,
  tools: ReleaseTools,
): ReleaseOperations {
  const checks: {
    command: string[];
    exitCode: number;
    stdoutSha256: string;
  }[] = [];
  const checkPublisherDestination = publisherDestinationGate();
  let approvedRegistry: string | undefined;
  return {
    snapshot: () => snapshot(root, options.reviewed),
    checks: async () => {
      if (
        process.env.GITLEAKS_CONFIG !== undefined ||
        process.env.GITLEAKS_CONFIG_TOML !== undefined
      )
        throw new Error('Custom scanner overrides require separate review.');
      await canonicalScannerConfig();
      await validateReleaseMetadata(
        JSON.parse(await readFile(join(root, 'package.json'), 'utf8')),
        JSON.parse(await readFile(join(root, 'server.json'), 'utf8')),
      );
      const commands = [
        [tools.bun, 'install', '--frozen-lockfile', '--ignore-scripts'],
        [tools.bun, join(root, 'scripts/devcheck.ts'), '--no-fix'],
        [tools.bun, 'run', 'rebuild'],
        [tools.bun, 'test'],
      ];
      for (const args of commands) {
        const stdout = command(args, root, 10 * 60_000);
        checks.push({
          command: args,
          exitCode: 0,
          stdoutSha256: sha256(stdout),
        });
      }
    },
    buildBundle: async (source) => {
      await outsideOutput(root, options.output);
      if (options.publish) {
        const bytes = await readFile(join(options.output, 'provenance.json'));
        if (sha256(bytes) !== options.bundleDigest)
          throw new Error('Bundle manifest differs from reviewed digest.');
        return JSON.parse(bytes.toString('utf8')) as ReleaseBundle;
      }
      await mkdir(options.output, { mode: 0o700 });
      const current = await snapshot(root, options.reviewed);
      const build = await buildFiles(root);
      await writeFile(
        join(options.output, 'source.tar'),
        sourceArchive(root, source.commit),
        { flag: 'wx', mode: 0o400 },
      );
      for (const [name, bytes] of Object.entries({
        'package.json': current.packageJson,
        'bun.lock': current.lockfile,
        'server.json': current.serverJson,
        'registry-manifest.json': registryManifest(current.serverJson),
        'build.json': canonicalJson(build),
        'sbom.json': canonicalJson(createLockInventory(current.lockfile)),
        'checks.json': canonicalJson({
          source,
          tools: TOOLCHAIN_PINS,
          results: checks,
        }),
      }))
        await writeFile(join(options.output, name), bytes, {
          flag: 'wx',
          mode: 0o400,
        });
      const archive = join(options.output, 'package.tgz');
      command(
        [tools.bun, 'pm', 'pack', '--ignore-scripts', '--filename', archive],
        root,
      );
      verifyPackedFiles(
        root,
        options.reviewed,
        archive,
        build,
        current.packageJson,
      );
      const scanScratch = await mkdtemp(join(tmpdir(), 'release-secret-gate-'));
      try {
        const rules = await snapshotScannerConfig(scanScratch);
        const reportPath = join(scanScratch, 'report.json');
        const scan = spawnSync(
          tools.gitleaks,
          [
            'dir',
            '--config',
            rules.path,
            '--redact=100',
            '--no-banner',
            '--ignore-gitleaks-allow',
            '--gitleaks-ignore-path',
            rules.ignorePath,
            '--log-level',
            'error',
            '--report-format',
            'json',
            '--report-path',
            reportPath,
            '--max-archive-depth',
            '2',
            '--timeout',
            '180',
            options.output,
          ],
          {
            cwd: root,
            timeout: 190_000,
            killSignal: 'SIGKILL',
            maxBuffer: 16 * 1024 * 1024,
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe'],
          },
        );
        assertZeroSecretScan({
          exitCode: scan.status,
          stderr: scan.stderr,
          executionError: Boolean(scan.error || scan.signal),
          report: JSON.parse(await readFile(reportPath, 'utf8')),
        });
      } finally {
        await rm(scanScratch, { recursive: true, force: true });
      }
      await canonicalScannerConfig();
      const files = await bundleFiles(options.output);
      const bundle: ReleaseBundle = {
        schemaVersion: 1,
        source,
        files: Object.fromEntries(
          Object.entries(files).map(([name, bytes]) => [name, sha256(bytes)]),
        ),
      };
      verifyBundleFiles(bundle, files);
      await writeFile(
        join(options.output, 'provenance.json'),
        JSON.stringify(bundle, null, 2) + '\n',
        { flag: 'wx', mode: 0o400 },
      );
      return bundle;
    },
    verifyBundle: async (bundle) => {
      const files = await bundleFiles(options.output);
      verifyBundleFiles(bundle, files);
      if (
        sha256(sourceArchive(root, bundle.source.commit)) !==
        bundle.files['source.tar']
      )
        throw new Error('Source archive differs from exact reviewed commit.');
      const build: Record<string, string> = JSON.parse(
        Buffer.from(files['build.json']!).toString('utf8'),
      );
      verifyPackedFiles(
        root,
        options.reviewed,
        join(options.output, 'package.tgz'),
        build,
        Buffer.from(files['package.json']!).toString('utf8'),
      );
    },
    preflightPublication: async () => {
      if (!options.publish || !tools.publisher)
        throw new Error('Pinned publication inputs required.');
      approvedRegistry = await checkPublisherDestination();
    },
    publish: async (_bundle, destination) => {
      if (!options.publish || !approvedRegistry)
        throw new Error('Publication preflight required.');
      if ((await checkPublisherDestination()) !== approvedRegistry)
        throw new Error('Publisher destination drift.');
      if (destination === 'npm')
        command(
          [
            tools.bun,
            'publish',
            join(options.output, 'package.tgz'),
            '--access',
            'public',
            '--ignore-scripts',
          ],
          root,
        );
      else {
        if (!tools.publisher)
          throw new Error('Pinned publisher archive required.');
        command(
          [
            tools.publisher,
            'publish',
            join(options.output, 'registry-manifest.json'),
          ],
          root,
        );
      }
    },
    receipt: async (bundle, destination) => {
      const source = bundle.source;
      if (destination === 'npm') {
        const info = JSON.parse(
          Buffer.from(
            await responseBytes(
              `https://registry.npmjs.org/${encodeURIComponent(source.packageName)}/${encodeURIComponent(source.version)}`,
              4 * 1024 * 1024,
            ),
          ).toString('utf8'),
        );
        if (
          info.name !== source.packageName ||
          info.version !== source.version ||
          typeof info.dist?.tarball !== 'string' ||
          new URL(info.dist.tarball).origin !== 'https://registry.npmjs.org'
        )
          throw new Error('Unexpected npm destination identity.');
        return {
          destination,
          identity: info.name,
          version: info.version,
          sha256: sha256(
            await responseBytes(info.dist.tarball, 128 * 1024 * 1024),
          ),
        };
      }
      if (!approvedRegistry) throw new Error('Publication preflight required.');
      const info = JSON.parse(
        Buffer.from(
          await responseBytes(
            `${approvedRegistry}/v0.1/servers/${encodeURIComponent(source.serverName)}/versions/${encodeURIComponent(source.version)}`,
            4 * 1024 * 1024,
          ),
        ).toString('utf8'),
      );
      if (
        info.server?.name !== source.serverName ||
        info.server?.version !== source.version
      )
        throw new Error('Unexpected MCP destination identity.');
      return {
        destination,
        identity: info.server.name,
        version: info.server.version,
        sha256: sha256(canonicalJson(info.server)),
      };
    },
    saveReceipt: async (receipt) => {
      const directory = `${options.output}.receipts`;
      await mkdir(directory, { mode: 0o700, recursive: true });
      await writeFile(
        join(directory, `${receipt.destination}.json`),
        JSON.stringify(
          {
            ...receipt,
            checkedAt: new Date().toISOString(),
            reviewed: options.reviewed,
            bundleSha256: options.bundleDigest,
          },
          null,
          2,
        ) + '\n',
        { flag: 'wx', mode: 0o400 },
      );
    },
    recordPublication: async (action) => {
      const directory = `${options.output}.receipts`;
      await mkdir(directory, { mode: 0o700, recursive: true });
      await writeFile(
        join(directory, `${action.destination}.${action.stage}.json`),
        JSON.stringify(
          {
            ...action,
            reviewed: options.reviewed,
            bundleSha256: options.bundleDigest,
            registry:
              action.destination === 'mcp'
                ? approvedRegistry
                : 'https://registry.npmjs.org',
            checkedAt: new Date().toISOString(),
          },
          null,
          2,
        ) + '\n',
        { flag: 'wx', mode: 0o400 },
      );
    },
  };
}

if (import.meta.main) {
  let scratch: string | undefined;
  try {
    const options = parseReleaseArgs(process.argv.slice(2));
    scratch = await mkdtemp(join(tmpdir(), 'git-mcp-release-'));
    const tools = await initializeReleaseTools(options.archives, scratch);
    const root = fileURLToPath(new URL('..', import.meta.url));
    await runRelease(
      options.reviewed,
      releaseOperations(root, options, tools),
      options.publish,
    );
    const digest = sha256(
      await readFile(join(options.output, 'provenance.json')),
    );
    console.log(
      `Release ${options.publish ? 'publication verified' : 'bundle prepared; no publication attempted'}. Bundle SHA-256: ${digest}`,
    );
  } catch (error) {
    console.error(
      error instanceof Error
        ? error.message
        : 'Release failed. Check saved receipts before retrying.',
    );
    process.exitCode = 1;
  } finally {
    if (scratch) await rm(scratch, { recursive: true, force: true });
  }
}
