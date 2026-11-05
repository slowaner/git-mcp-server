/**
 * @fileoverview Unit tests for git push operation
 * @module tests/services/git/providers/cli/operations/remotes/push.test
 */
import { describe, expect, it, vi, beforeEach } from 'vitest';

import { executePush } from '@/services/git/providers/cli/operations/remotes/push.js';
import type { GitOperationContext } from '@/services/git/types.js';
import type { RequestContext } from '@/utils/index.js';

type ExecGitFn = (
  args: string[],
  cwd: string,
  ctx: RequestContext,
) => Promise<{ stdout: string; stderr: string }>;

describe('executePush', () => {
  const mockContext: GitOperationContext = {
    workingDirectory: '/test/repo',
    requestContext: {
      requestId: 'test-request-id',
    } as RequestContext,
    tenantId: 'test-tenant',
  };

  let mockExecGit: ReturnType<typeof vi.fn<ExecGitFn>>;
  let tagOutput: string;

  const mockExecution: ExecGitFn = (args, cwd, ctx) => {
    if (args[0] === 'config')
      return Promise.resolve({ stdout: 'push.default\ncurrent\0', stderr: '' });
    if (args[0] === 'rev-parse')
      return Promise.resolve({ stdout: 'feature\n', stderr: '' });
    if (args[0] === 'for-each-ref')
      return Promise.resolve({ stdout: tagOutput, stderr: '' });
    return mockExecGit(args, cwd, ctx);
  };

  beforeEach(() => {
    mockExecGit = vi.fn<ExecGitFn>();
    tagOutput = 'refs/tags/v1\n';
  });

  describe('basic push operations', () => {
    it('pushes to default remote origin', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: 'Everything up-to-date\n',
      });

      const result = await executePush({}, mockContext, mockExecution);

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).toContain('push');
      expect(args).toContain('origin');
      expect(result.success).toBe(true);
      expect(result.remote).toBe('origin');
      expect(result.branch).toBe('HEAD');
    });

    it('pushes to specified remote', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: '',
      });

      const result = await executePush(
        { remote: 'upstream' },
        mockContext,
        mockExecution,
      );

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).toContain('upstream');
      expect(result.remote).toBe('upstream');
    });

    it('pushes specific branch', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: '',
      });

      const result = await executePush(
        { branch: 'feature-x' },
        mockContext,
        mockExecution,
      );

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).toContain('refs/heads/feature-x:refs/heads/feature-x');
      expect(result.branch).toBe('feature-x');
    });
  });

  describe('delete option', () => {
    it('uses an empty source for confirmed concrete deletion', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: '',
      });

      await executePush(
        { branch: 'old-branch', delete: true, confirmed: true },
        mockContext,
        mockExecution,
      );

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).toContain(':refs/heads/old-branch');
    });

    it('does not add --delete flag when delete is falsy', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: '',
      });

      await executePush({ branch: 'main' }, mockContext, mockExecution);

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).not.toContain('--delete');
    });
  });

  describe('remoteBranch option', () => {
    it('builds local:remote refspec when remoteBranch differs from branch', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: '',
      });

      await executePush(
        { branch: 'local-feat', remoteBranch: 'remote-feat' },
        mockContext,
        mockExecution,
      );

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).toContain('refs/heads/local-feat:refs/heads/remote-feat');
      expect(args).not.toContain('local-feat');
    });

    it('pins an explicit destination when remoteBranch matches branch', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: '',
      });

      await executePush(
        { branch: 'feat', remoteBranch: 'feat' },
        mockContext,
        mockExecution,
      );

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).toContain('refs/heads/feat:refs/heads/feat');
    });

    it('pushes HEAD:remote when remoteBranch is set without branch', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: '',
      });

      await executePush({ remoteBranch: 'deploy' }, mockContext, mockExecution);

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).toContain('HEAD:refs/heads/deploy');
    });
  });

  describe('force push options', () => {
    it('pins a confirmed force refspec when force is true', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: '',
      });

      await executePush(
        { force: true, confirmed: true },
        mockContext,
        mockExecution,
      );

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).toContain('+refs/heads/feature:refs/heads/feature');
      expect(args).not.toContain('--force-with-lease');
    });

    it('adds --force-with-lease when forceWithLease is true', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: '',
      });

      await executePush(
        { forceWithLease: true, confirmed: true },
        mockContext,
        mockExecution,
      );

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).toContain('--force-with-lease');
      expect(args).not.toContain('--force');
    });

    it('rejects contradictory force and lease assertions', async () => {
      await expect(
        executePush(
          { force: true, forceWithLease: true, confirmed: true },
          mockContext,
          mockExecution,
        ),
      ).rejects.toThrow(/Choose force/);
      expect(mockExecGit).not.toHaveBeenCalled();
    });
  });

  describe('set upstream option', () => {
    it('adds --set-upstream flag when setUpstream is true', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr:
          "Branch 'feature' set up to track remote branch 'feature' from 'origin'.\n",
      });

      const result = await executePush(
        { setUpstream: true },
        mockContext,
        mockExecution,
      );

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).toContain('--set-upstream');
      expect(result.upstreamSet).toBe(true);
    });

    it('returns upstreamSet false when setUpstream is not specified', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: '',
      });

      const result = await executePush({}, mockContext, mockExecution);

      expect(result.upstreamSet).toBe(false);
    });
  });

  describe('tags option', () => {
    it('returns only a truthful no-effect result after closed destination authorization', async () => {
      tagOutput = '';
      const authorize = vi.fn(async (_remote: string) => {});
      const result = await executePush(
        { tags: true, setUpstream: true },
        mockContext,
        mockExecution,
        authorize,
      );
      expect(authorize).toHaveBeenCalledTimes(1);
      expect(authorize).toHaveBeenCalledWith('origin');
      expect(mockExecGit).not.toHaveBeenCalled();
      expect(result).toEqual({
        success: true,
        remote: 'origin',
        branch: '',
        upstreamSet: false,
        pushedRefs: [],
        rejectedRefs: [],
      });
    });
    it('fails closed if the empty-selection callback is missing or rejects', async () => {
      tagOutput = '';
      await expect(
        executePush({ tags: true }, mockContext, mockExecution),
      ).rejects.toThrow(/authorization/);
      const failure = new Error('destination denied');
      const authorize = vi.fn(async (_remote: string) => {
        throw failure;
      });
      await expect(
        executePush({ tags: true }, mockContext, mockExecution, authorize),
      ).rejects.toThrow(/destination denied/);
      expect(authorize).toHaveBeenCalledTimes(1);
      expect(authorize).toHaveBeenCalledWith('origin');
      expect(mockExecGit).not.toHaveBeenCalled();
    });
    it('pins enumerated tag destinations when tags is true', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: '',
      });

      await executePush({ tags: true }, mockContext, mockExecution);

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).toContain('refs/tags/v1:refs/tags/v1');
    });

    it('does not add --tags when tags is false', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: '',
      });

      await executePush({ tags: false }, mockContext, mockExecution);

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).not.toContain('--tags');
    });
  });

  describe('dry run option', () => {
    it('adds --dry-run flag when dryRun is true', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: '',
      });

      await executePush({ dryRun: true }, mockContext, mockExecution);

      const [args] = mockExecGit.mock.calls[0]!;
      expect(args).toContain('--dry-run');
    });
  });

  describe('pushed refs parsing', () => {
    it('parses new branch push from stderr', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: `To github.com:user/repo.git
 * [new branch]      feature -> feature\n`,
      });

      const result = await executePush(
        { branch: 'feature' },
        mockContext,
        mockExecution,
      );

      expect(result.success).toBe(true);
      expect(result.pushedRefs).toContain('feature');
    });

    it('parses rejected refs from stderr', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: `To github.com:user/repo.git
 ! [rejected]        main -> main (non-fast-forward)\n`,
      });

      const result = await executePush(
        { branch: 'main' },
        mockContext,
        mockExecution,
      );

      expect(result.success).toBe(false);
      expect(result.rejectedRefs).toContain('main');
    });
  });

  describe('result structure', () => {
    it('returns correct structure for successful push', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: 'Everything up-to-date\n',
      });

      const result = await executePush({}, mockContext, mockExecution);

      expect(result).toEqual({
        success: true,
        remote: 'origin',
        branch: 'HEAD',
        upstreamSet: false,
        pushedRefs: [],
        rejectedRefs: [],
      });
    });

    it('returns specified remote and branch in result', async () => {
      mockExecGit.mockResolvedValueOnce({
        stdout: '',
        stderr: '',
      });

      const result = await executePush(
        { remote: 'upstream', branch: 'develop', setUpstream: true },
        mockContext,
        mockExecution,
      );

      expect(result.remote).toBe('upstream');
      expect(result.branch).toBe('develop');
      expect(result.upstreamSet).toBe(true);
    });
  });
});
