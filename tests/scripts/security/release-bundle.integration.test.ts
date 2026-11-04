/**
 * @fileoverview Real offline preparation maps packed files to an isolated fixture commit.
 * @module tests/scripts/security/release-bundle-integration
 */
import { describe, expect, it } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { releaseOperations } from '../../../scripts/release.js';
import {
  runRelease,
  sha256,
} from '../../../scripts/security/release-evidence.js';
import { synchronizedMetadata } from '../../../scripts/security/release-metadata.js';
import ts from 'typescript';
import { snapshotScannerConfig } from '../../../scripts/security/scanner-config.js';
import { assertZeroSecretScan } from '../../../scripts/security/secret-result.js';

const scanner = Bun.which('gitleaks');

function command(root: string, args: string[], quietErrors = false): string {
  const result = spawnSync(args[0]!, args.slice(1), {
    cwd: root,
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (
    result.status !== 0 ||
    result.error ||
    result.signal ||
    (quietErrors && result.stderr.trim())
  )
    throw new Error(
      `Fixture command failed: ${basename(args[0]!)} (${result.status ?? 'unknown'})`,
    );
  return result.stdout.trim();
}

describe('real release preparation profile', () => {
  for (const attributes of [
    '',
    'src/index.ts export-ignore\n',
    'src/index.ts export-subst\n',
  ]) {
    (scanner ? it : it.skip)(
      attributes
        ? `rejects source export attributes ${attributes.trim()}`
        : 'builds and verifies a source/lock/build/manifest bundle without publication',
      async () => {
        const parent = await mkdtemp(join(tmpdir(), 'g6-release-fixture-'));
        const root = join(parent, 'source');
        const output = join(parent, 'bundle');
        try {
          if (
            process.env.GITLEAKS_CONFIG !== undefined ||
            process.env.GITLEAKS_CONFIG_TOML !== undefined
          )
            throw new Error(
              'Fixture requires explicit canonical scanner rules.',
            );
          await mkdir(root);
          await mkdir(join(root, 'src'));
          await mkdir(join(root, 'scripts'));
          if (attributes)
            await writeFile(join(root, '.gitattributes'), attributes);
          const pkg = {
            name: '@example/release-fixture',
            version: '1.2.3',
            mcpName: 'io.github.example/release-fixture',
            packageManager: `bun@${Bun.version}`,
            type: 'module',
            files: ['dist'],
            scripts: {
              rebuild: 'bun build src/index.ts --outdir dist --target node',
            },
            dependencies: { 'reflect-metadata': '0.2.2' },
          };
          const original = JSON.parse(
            await readFile(
              new URL('../../../server.json', import.meta.url),
              'utf8',
            ),
          );
          await writeFile(
            join(root, 'package.json'),
            JSON.stringify(pkg, null, 2) + '\n',
          );
          await writeFile(
            join(root, 'server.json'),
            JSON.stringify(synchronizedMetadata(pkg, original), null, 2) + '\n',
          );
          await writeFile(
            join(root, 'src/index.ts'),
            'export const fixture = "checked source";\n',
          );
          await writeFile(
            join(root, 'fixture.test.ts'),
            'import { expect, test } from "bun:test"; import { fixture } from "./src/index.ts"; test("source", () => expect(fixture).toBe("checked source"));\n',
          );
          await writeFile(
            join(root, 'scripts/devcheck.ts'),
            'if (!process.argv.includes("--no-fix")) throw new Error("Release must not fix source");\n',
          );
          await writeFile(join(root, '.gitignore'), 'node_modules/\ndist/\n');
          command(root, [process.execPath, 'install', '--ignore-scripts']);
          command(root, ['git', 'init', '--initial-branch=fixture']);
          command(root, ['git', 'add', '.']);
          const tree = command(root, ['git', 'write-tree']);
          const staged = join(parent, 'staged');
          await mkdir(staged);
          command(root, [
            'git',
            'checkout-index',
            '--all',
            `--prefix=${staged}/`,
          ]);
          expect(command(root, [scanner!, 'version'])).toBe('8.30.1');
          const scannerConfig = await snapshotScannerConfig(parent);
          const scanReport = join(parent, 'staged-report.json');
          command(
            root,
            [
              scanner!,
              'dir',
              '--config',
              scannerConfig.path,
              '--redact=100',
              '--no-banner',
              '--ignore-gitleaks-allow',
              '--gitleaks-ignore-path',
              scannerConfig.ignorePath,
              '--log-level',
              'error',
              '--report-format',
              'json',
              '--report-path',
              scanReport,
              staged,
            ],
            true,
          );
          assertZeroSecretScan({
            exitCode: 0,
            stderr: '',
            executionError: false,
            report: JSON.parse(await readFile(scanReport, 'utf8')),
          });
          expect(command(root, ['git', 'write-tree'])).toBe(tree);
          // Fixture-only commit/tag; no source-repository refs or provider writes.
          const identity = [
            '-c',
            'user.name=Release fixture',
            '-c',
            'user.email=release-fixture@example.invalid',
          ];
          command(root, [
            'git',
            ...identity,
            '-c',
            'commit.gpgSign=false',
            'commit',
            '-m',
            'test: isolated release fixture',
          ]);
          command(root, [
            'git',
            ...identity,
            '-c',
            'tag.gpgSign=false',
            'tag',
            '-a',
            'v1.2.3',
            '-m',
            'Release fixture',
          ]);
          const reviewed = {
            commit: command(root, ['git', 'rev-parse', 'HEAD']),
            tag: 'v1.2.3',
          };
          const options = {
            reviewed,
            archives: {
              bun: '/unused-injected-tools',
              gitleaks: '/unused-injected-tools',
            },
            output,
            publish: false,
          };
          const ops = releaseOperations(root, options, {
            bun: process.execPath,
            gitleaks: scanner!,
          });
          if (attributes) {
            await expect(runRelease(reviewed, ops)).rejects.toThrow(
              'source archive attributes',
            );
            return;
          }
          const bundle = await runRelease(reviewed, ops);
          expect(bundle.source.commit).toBe(reviewed.commit);
          expect(bundle.files['package.tgz']).toBe(
            sha256(await readFile(join(output, 'package.tgz'))),
          );
          expect(Object.keys(bundle.files)).toHaveLength(9);
          expect(command(root, ['git', 'status', '--porcelain'])).toBe('');
          expect(
            await readFile(join(output, 'provenance.json'), 'utf8'),
          ).toContain(reviewed.commit);
        } catch (error) {
          const bytes = await readFile(join(root, 'bun.lock'), 'utf8');
          const parsed = ts.parseConfigFileTextToJson('bun.lock', bytes).config;
          const version = Number.isSafeInteger(parsed?.lockfileVersion)
            ? parsed.lockfileVersion
            : typeof parsed?.lockfileVersion;
          const configVersion = Number.isSafeInteger(parsed?.configVersion)
            ? parsed.configVersion
            : typeof parsed?.configVersion;
          const packages =
            parsed?.packages && typeof parsed.packages === 'object'
              ? Object.keys(parsed.packages).length
              : typeof parsed?.packages;
          throw new Error(
            `Fixture lock structural diagnosis: ${JSON.stringify({ version, configVersion, packages })}; ${error instanceof Error ? error.message : 'preparation failed'}`,
          );
        } finally {
          await rm(parent, { recursive: true, force: true });
        }
      },
      120_000,
    );
  }
});
