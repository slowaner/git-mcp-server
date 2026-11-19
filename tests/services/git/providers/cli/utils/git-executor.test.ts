/**
 * @fileoverview Unit tests for executeGitCommand cwd validation
 * @module tests/services/git/providers/cli/utils/git-executor.test
 */
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { executeGitCommand } from '@/services/git/providers/cli/utils/git-executor.js';
import { McpError } from '@/types-global/errors.js';

it('enforces GIT_MAX_COMMAND_TIMEOUT_MS when running Git', () => {
  const directory = realpathSync(
    mkdtempSync(join(tmpdir(), 'git-executor-deadline-')),
  );
  try {
    const binary = join(directory, 'slow-git');
    writeFileSync(binary, '#!/bin/sh\nexec /bin/sleep 5\n', { mode: 0o700 });
    // A fresh executor loads its own environment. The version probe does not
    // inspect repository metadata, so only the supervised command is timed.
    const result = Bun.spawnSync(
      [
        process.execPath,
        '-e',
        `import { executeGitCommand } from '@/services/git/providers/cli/utils/git-executor.js';
        try {
          await executeGitCommand(['--version'], process.env.GIT_BASE_DIR);
        } catch (error) {
          console.error(error.data?.reason);
          process.exitCode = 1;
        }`,
      ],
      {
        env: {
          ...process.env,
          GIT_BASE_DIR: directory,
          GIT_BINARY_PATH: binary,
          GIT_TRUSTED_HOME: directory,
          GIT_TRUSTED_PATH: '/usr/bin:/bin',
          GIT_MAX_COMMAND_TIMEOUT_MS: '250',
        },
      },
    );

    expect(result.exitCode).toBe(1);
    expect(result.stderr.toString().trim()).toBe('DEADLINE');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe('executeGitCommand cwd pre-flight', () => {
  it('throws a clear error when cwd does not exist (not generic "Git not found")', async () => {
    await expect(
      executeGitCommand(['status'], '/definitely/not/a/real/path/xyz123'),
    ).rejects.toThrow(McpError);

    try {
      await executeGitCommand(['status'], '/definitely/not/a/real/path/xyz123');
      expect.unreachable();
    } catch (err) {
      const message = (err as Error).message;
      expect(message).toContain('Working directory does not exist');
      expect(message).not.toContain('Git command not found');
    }
  });

  it('throws when cwd exists but is not a directory', async () => {
    await expect(executeGitCommand(['status'], '/etc/hosts')).rejects.toThrow(
      /not a directory/,
    );
  });
});
