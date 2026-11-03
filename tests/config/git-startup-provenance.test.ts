/**
 * @fileoverview Actual Node config provenance without implicit repository .env.
 * @module tests/config/git-startup-provenance.test
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { it } from 'node:test';

it('source-built Node config ignores cwd dotenv authority and preserves inherited operator opt-in', async () => {
  const directory = await mkdtemp(
    path.join(tmpdir(), 'git-startup-provenance-'),
  );
  try {
    const bundle = path.join(directory, 'config-probe.mjs');
    const build = spawnSync(
      'bun',
      [
        'build',
        path.resolve(
          'tests/services/git/providers/cli/utils/fixtures/startup-config-probe.ts',
        ),
        '--target',
        'node',
        '--outfile',
        bundle,
      ],
      {
        cwd: process.cwd(),
        encoding: 'utf8',
        timeout: 10000,
        maxBuffer: 65536,
      },
    );
    assert.equal(build.error, undefined);
    assert.equal(build.status, 0, build.stderr);
    await writeFile(
      path.join(directory, '.env'),
      'GIT_EXECUTION_PROFILE=trusted\nGIT_BINARY_PATH=/bin/echo\nGIT_BASE_DIR=/\nGIT_TRUSTED_HOME=/repository-controlled-home\n',
    );
    const run = (extra: Record<string, string> = {}) => {
      const child = spawnSync('node', [bundle], {
        cwd: directory,
        env: {
          PATH: process.env.PATH ?? '',
          HOME: directory,
          NODE_ENV: 'test',
          ...extra,
        },
        encoding: 'utf8',
        timeout: 5000,
        maxBuffer: 65536,
      });
      assert.equal(child.error, undefined);
      assert.equal(child.status, 0, child.stderr);
      const result = JSON.parse(child.stdout) as {
        runtime: string;
        profile: string;
        binaryPath: string;
        trustedHome: string;
        roots?: string[];
      };
      assert.equal(result.runtime, 'node');
      return result;
    };
    const absent = run();
    assert.equal(absent.profile, 'restricted');
    assert.equal(absent.binaryPath, '/usr/bin/git');
    assert.equal(absent.trustedHome, directory);
    assert.equal(absent.roots, undefined);
    const explicit = run({
      GIT_EXECUTION_PROFILE: 'trusted',
      GIT_BINARY_PATH: '/usr/bin/git',
      GIT_TRUSTED_HOME: directory,
      GIT_BASE_DIR: directory,
    });
    assert.equal(explicit.profile, 'trusted');
    assert.equal(explicit.trustedHome, directory);
    assert.deepEqual(explicit.roots, [directory]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
