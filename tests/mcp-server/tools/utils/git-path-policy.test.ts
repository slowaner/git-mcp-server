/**
 * @fileoverview Lexical multi-root resolution and cached working directory checks.
 * @module tests/mcp-server/tools/utils/git-path-policy.test
 */
import { describe, expect, it } from 'vitest';
import { resolvePathWithinGitRoots } from '@/mcp-server/tools/utils/git-path-policy.js';
import { resolveWorkingDirectory } from '@/mcp-server/tools/utils/git-validators.js';
import type { StorageService } from '@/storage/core/StorageService.js';
import { requestContextService } from '@/utils/index.js';

const roots = ['/allowed/repos', '/allowed/worktrees'];
describe('lexical Git roots', () => {
  it('accepts either absolute root and missing destinations', () => {
    for (const root of roots) {
      expect(resolvePathWithinGitRoots(root, roots)).toBe(root);
      expect(resolvePathWithinGitRoots(`${root}/new/missing`, roots)).toBe(
        `${root}/new/missing`,
      );
    }
  });
  it('anchors relative paths to only the first root', () => {
    expect(resolvePathWithinGitRoots('repo', roots)).toBe(
      '/allowed/repos/repo',
    );
    expect(resolvePathWithinGitRoots('a/../repo', roots)).toBe(
      '/allowed/repos/repo',
    );
  });
  it('anchors extra paths to the selected repository cwd', () => {
    expect(
      resolvePathWithinGitRoots('../wt', roots, '/allowed/worktrees/repo'),
    ).toBe('/allowed/worktrees/wt');
  });
  for (const input of [
    '',
    '/outside/repo',
    '../outside',
    '/allowed/repos-evil/repo',
    '/allowed/worktrees-extra/repo',
    '/allowed/repos/../../outside',
    '/allowed/repos/repo\0',
  ]) {
    it(`rejects a forbidden path: ${JSON.stringify(input)}`, () => {
      expect(() => resolvePathWithinGitRoots(input, roots)).toThrow();
    });
  }
  it('fails closed for an explicit empty allowlist', () => {
    expect(() => resolvePathWithinGitRoots('/allowed/repos', [])).toThrow();
  });
  it('retains the unrestricted-root mode', () => {
    expect(resolvePathWithinGitRoots('/outside/repo')).toBe('/outside/repo');
  });
  it('does not select a root when stored cwd is missing', async () => {
    const storage = { get: async () => null } as unknown as StorageService;
    await expect(
      resolveWorkingDirectory(
        '.',
        requestContextService.createRequestContext({ operation: 'test' }),
        storage,
      ),
    ).rejects.toThrow('No session working directory');
  });
});
