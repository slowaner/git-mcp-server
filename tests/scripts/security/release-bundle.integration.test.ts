/**
 * @fileoverview Real offline preparation maps packed files to an isolated fixture commit.
 * @module tests/scripts/security/release-bundle-integration
 */
import { describe, expect, it } from 'bun:test';
import { spawnSync } from 'node:child_process';
import {
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
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
import { sourceTreeEntries } from '../../../scripts/security/release-source-archive.js';

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
  for (const profile of ['none', 'ignore', 'subst', 'repository'] as const) {
    (scanner ? it : it.skip)(
      `preserves complete reviewed source with ${profile} attributes without publication`,
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
          const attributes =
            profile === 'repository'
              ? await readFile(
                  new URL('../../../.gitattributes', import.meta.url),
                  'utf8',
                )
              : profile === 'none'
                ? ''
                : `src/index.ts export-${profile}\n`;
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
            '// $Format:%H$\nexport const fixture = "checked source";\n',
          );
          await writeFile(
            join(root, 'CLAUDE.md'),
            'Reviewed fixture instructions.\n',
          );
          await symlink('CLAUDE.md', join(root, 'AGENTS.md'));
          await writeFile(
            join(root, 'fixture.test.ts'),
            'import { expect, test } from "bun:test"; import { fixture } from "./dist/index.js"; test("current build", () => expect(fixture).toBe("checked source"));\n',
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
          // An ignored stale bundle must be rebuilt before the compiled consumer test.
          await mkdir(join(root, 'dist'));
          await writeFile(
            join(root, 'dist/index.js'),
            'export const fixture = "stale build";\n',
          );
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
          const extracted = join(parent, 'complete-source');
          await mkdir(extracted);
          command(root, [
            'tar',
            '-xf',
            join(output, 'source.tar'),
            '-C',
            extracted,
          ]);
          const treeBytes = spawnSync(
            'git',
            ['ls-tree', '-r', '-z', '--full-tree', reviewed.commit],
            { cwd: root },
          );
          expect(treeBytes.status).toBe(0);
          const entries = sourceTreeEntries(treeBytes.stdout);
          expect(
            command(root, ['tar', '-tf', join(output, 'source.tar')])
              .split('\n')
              .sort(),
          ).toEqual(entries.map((entry) => entry.path).sort());
          for (const entry of entries) {
            const blob = spawnSync('git', ['cat-file', 'blob', entry.oid], {
              cwd: root,
            });
            expect(blob.status).toBe(0);
            const actual =
              entry.mode === '120000'
                ? Buffer.from(await readlink(join(extracted, entry.path)))
                : await readFile(join(extracted, entry.path));
            expect(actual).toEqual(blob.stdout);
          }
          expect(
            await readFile(join(extracted, 'CLAUDE.md'), 'utf8'),
          ).toContain('Reviewed fixture');
          expect(
            await readFile(join(extracted, 'scripts/devcheck.ts'), 'utf8'),
          ).toContain('--no-fix');
          expect(
            await readFile(join(extracted, 'fixture.test.ts'), 'utf8'),
          ).toContain('current build');
          expect(
            await readFile(join(extracted, 'src/index.ts'), 'utf8'),
          ).toContain('$Format:%H$');
          if (attributes) {
            // Even a rewritten artifact hash cannot bless an attribute-transformed export.
            const transformed = spawnSync(
              'git',
              ['archive', '--format=tar', reviewed.commit],
              { cwd: root },
            );
            expect(transformed.status).toBe(0);
            await rm(join(output, 'source.tar'));
            await writeFile(join(output, 'source.tar'), transformed.stdout);
            const altered = structuredClone(bundle);
            altered.files['source.tar'] = sha256(transformed.stdout);
            await expect(ops.verifyBundle(altered)).rejects.toThrow(
              'Source archive differs',
            );
          }
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
