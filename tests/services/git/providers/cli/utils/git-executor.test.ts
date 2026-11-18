/**
 * @fileoverview Unit tests for executeGitCommand cwd validation
 * @module tests/services/git/providers/cli/utils/git-executor.test
 */
import { describe, expect, it } from 'vitest';

import { executeGitCommand } from '@/services/git/providers/cli/utils/git-executor.js';
import { McpError } from '@/types-global/errors.js';

it('enforces GIT_MAX_COMMAND_TIMEOUT_MS when running Git', () => {
  // Start a fresh executor so configuration is loaded from its own environment.
  const result = Bun.spawnSync(
    [
      'bun',
      '-e',
      `import { executeGitCommand } from '@/services/git/providers/cli/utils/git-executor.js';
     await executeGitCommand(['-c', 'alias.wait-for-timeout=!sleep 1', 'wait-for-timeout'], process.cwd());`,
    ],
    { env: { ...process.env, GIT_MAX_COMMAND_TIMEOUT_MS: '50' } },
  );

  expect(result.exitCode).not.toBe(0);
  expect(result.stderr.toString()).toContain(
    'Git command timed out after 0.05s',
  );
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
