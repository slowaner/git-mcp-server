/**
 * @fileoverview Real Bun lifecycle and cross-file trusted-fixture isolation.
 * @module tests/config/git-fixture-isolation.test
 */
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

describe('explicit trusted unit fixture lifetime', () => {
  it('restores restricted after failed test bodies and does not leak through cached helper imports', async () => {
    const directory = await mkdtemp(
      path.join(tmpdir(), 'git-fixture-isolation-'),
    );
    const configPath = path.resolve('src/config/index.ts');
    const helperPath = path.resolve(
      'tests/mcp-server/tools/definitions/helpers/testContext.ts',
    );
    try {
      const opted = path.join(directory, 'a-opted.test.ts');
      const unopted = path.join(directory, 'b-unopted.test.ts');
      await writeFile(
        opted,
        `
import { describe, test, expect, afterAll } from 'bun:test';
import { config } from ${JSON.stringify(configPath)};
import { installTrustedGitFixture } from ${JSON.stringify(helperPath)};
expect(config.git.executionProfile).toBe('restricted');
installTrustedGitFixture();
test('trusted positive', () => { expect(config.git.executionProfile).toBe('trusted'); });
test('intentional failed body', () => { expect(config.git.executionProfile).toBe('trusted'); throw new Error('EXPECTED_CONTROLLED_FAILURE'); });
afterAll(() => { expect(config.git.executionProfile).toBe('restricted'); console.log('RESTORED_AFTER_FAILED_BODY'); });
`,
      );
      await writeFile(
        unopted,
        `
import { test, expect } from 'bun:test';
import { config } from ${JSON.stringify(configPath)};
import { installTrustedGitFixture } from ${JSON.stringify(helperPath)};
test('unopted remains restricted with cached helper', () => {
  expect(typeof installTrustedGitFixture).toBe('function');
  expect(config.git.executionProfile).toBe('restricted');
  console.log('UNOPTED_RESTRICTED');
});
`,
      );
      const env = { ...process.env };
      delete env.GIT_EXECUTION_PROFILE;
      const child = spawnSync(process.execPath, ['test', opted, unopted], {
        cwd: process.cwd(),
        env,
        encoding: 'utf8',
        timeout: 15000,
        maxBuffer: 1024 * 1024,
      });
      const output = child.stdout + child.stderr;
      expect(child.error).toBeUndefined();
      expect(child.status, output).toBe(1); // exactly the deliberate fixture failure
      expect(output).toContain('EXPECTED_CONTROLLED_FAILURE');
      expect(output).toContain('RESTORED_AFTER_FAILED_BODY');
      expect(output).toContain('UNOPTED_RESTRICTED');
      expect(output).toMatch(/2 pass/);
      expect(output).toMatch(/1 fail/);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }, 20000);
});
