/**
 * @fileoverview Unit tests for git-status tool
 * @module tests/mcp-server/tools/definitions/unit/git-status.tool.test
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { container } from 'tsyringe';

import { gitStatusTool } from '@/mcp-server/tools/definitions/git-status.tool.js';
import {
  GitProviderFactory as GitProviderFactoryToken,
  StorageService as StorageServiceToken,
} from '@/container/tokens.js';
import {
  createTestContext,
  createTestSdkContext,
  createMockGitProvider,
  createMockStorageService,
  assertJsonContent,
  assertJsonField,
  parseJsonContent,
  assertProviderCalledWithContext,
  assertLlmFriendlyFormat,
} from '../helpers/index.js';
import type { GitStatusResult } from '@/services/git/types.js';
import { GitProviderFactory } from '@/services/git/core/GitProviderFactory.js';

describe('git_status tool', () => {
  const mockProvider = createMockGitProvider();
  const mockStorage = createMockStorageService();
  const mockFactory = {
    getProvider: vi.fn(async () => mockProvider),
  } as unknown as GitProviderFactory;

  beforeEach(() => {
    // Reset mocks
    mockProvider.resetMocks();
    mockStorage.clearAll();

    // Register mock dependencies
    container.clearInstances();
    container.register(GitProviderFactoryToken, { useValue: mockFactory });
    container.register(StorageServiceToken, { useValue: mockStorage });

    // Set up default session working directory
    const tenantId = 'test-tenant';
    const context = createTestContext({ tenantId });
    mockStorage.set(`session:workingDir:${tenantId}`, '/test/repo', context);
  });

  describe('Input Schema', () => {
    it('validates correct input with default values', () => {
      const input = { path: '.' };
      const result = gitStatusTool.inputSchema.safeParse(input);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.includeUntracked).toBe(true); // default
      }
    });

    it('accepts absolute path', () => {
      const input = { path: '/absolute/path/to/repo' };
      const result = gitStatusTool.inputSchema.safeParse(input);
      expect(result.success).toBe(true);
    });

    it('accepts includeUntracked option', () => {
      const input = { path: '.', includeUntracked: false };
      const result = gitStatusTool.inputSchema.safeParse(input);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.includeUntracked).toBe(false);
      }
    });

    it('rejects invalid input types', () => {
      const input = { path: 123 }; // Invalid: path should be string
      const result = gitStatusTool.inputSchema.safeParse(input);
      expect(result.success).toBe(false);
    });
  });

  describe('Tool Logic', () => {
    it('executes status operation successfully with session path', async () => {
      const mockStatusResult: GitStatusResult = {
        currentBranch: 'main',
        isClean: false,
        stagedChanges: {
          added: ['file1.txt'],
          modified: ['file2.txt'],
        },
        unstagedChanges: {
          modified: ['file3.txt'],
        },
        untrackedFiles: ['file4.txt'],
        conflictedFiles: [],
      };

      mockProvider.status.mockResolvedValue(mockStatusResult);

      // Parse input through schema to get defaults
      const parsedInput = gitStatusTool.inputSchema.parse({ path: '.' });
      const appContext = createTestContext({ tenantId: 'test-tenant' });
      const sdkContext = createTestSdkContext();

      const result = await gitStatusTool.logic(
        parsedInput,
        appContext,
        sdkContext,
      );

      // Verify provider was called correctly
      expect(mockProvider.status).toHaveBeenCalledTimes(1);
      assertProviderCalledWithContext(
        mockProvider.status.mock.calls[0] as unknown[],
        '/test/repo',
        'test-tenant',
      );

      // Verify output structure
      expect(result).toMatchObject({
        currentBranch: 'main',
        isClean: false,
        stagedChanges: {
          added: ['file1.txt'],
          modified: ['file2.txt'],
        },
        unstagedChanges: {
          modified: ['file3.txt'],
        },
        untrackedFiles: ['file4.txt'],
        conflictedFiles: [],
      });
    });

    it('executes status operation with absolute path', async () => {
      const mockStatusResult: GitStatusResult = {
        currentBranch: 'develop',
        isClean: true,
        stagedChanges: {},
        unstagedChanges: {},
        untrackedFiles: [],
        conflictedFiles: [],
      };

      mockProvider.status.mockResolvedValue(mockStatusResult);

      const parsedInput = gitStatusTool.inputSchema.parse({
        path: '/absolute/repo/path',
      });
      const appContext = createTestContext({ tenantId: 'test-tenant' });
      const sdkContext = createTestSdkContext();

      const result = await gitStatusTool.logic(
        parsedInput,
        appContext,
        sdkContext,
      );

      // Verify provider was called with absolute path
      expect(mockProvider.status).toHaveBeenCalledTimes(1);
      const [_options, context] = mockProvider.status.mock.calls[0] as [
        unknown,
        { workingDirectory: string },
      ];
      expect(context.workingDirectory).toBe('/absolute/repo/path');

      expect(result.isClean).toBe(true);
    });

    it('applies graceful tenantId default when missing', async () => {
      const mockStatusResult: GitStatusResult = {
        currentBranch: 'main',
        isClean: true,
        stagedChanges: {},
        unstagedChanges: {},
        untrackedFiles: [],
        conflictedFiles: [],
      };

      mockProvider.status.mockResolvedValue(mockStatusResult);

      // Context without tenantId (development mode)
      const appContext = createTestContext();
      const sdkContext = createTestSdkContext();

      // Set up default tenant storage
      mockStorage.set(
        'session:workingDir:default-tenant',
        '/default/repo',
        appContext,
      );

      const parsedInput = gitStatusTool.inputSchema.parse({ path: '.' });
      await gitStatusTool.logic(parsedInput, appContext, sdkContext);

      // Verify default tenant was used
      expect(mockProvider.status).toHaveBeenCalledTimes(1);
      const [_options, context] = mockProvider.status.mock.calls[0] as [
        unknown,
        { tenantId: string },
      ];
      expect(context.tenantId).toBe('default-tenant');
    });

    it('passes includeUntracked option to provider', async () => {
      const mockStatusResult: GitStatusResult = {
        currentBranch: 'main',
        isClean: true,
        stagedChanges: {},
        unstagedChanges: {},
        untrackedFiles: [],
        conflictedFiles: [],
      };

      mockProvider.status.mockResolvedValue(mockStatusResult);

      const input = { path: '.', includeUntracked: false };
      const appContext = createTestContext({ tenantId: 'test-tenant' });
      const sdkContext = createTestSdkContext();

      await gitStatusTool.logic(input, appContext, sdkContext);

      // Verify option was passed to provider
      expect(mockProvider.status).toHaveBeenCalledTimes(1);
      const [options, _context] = mockProvider.status.mock.calls[0]!;
      expect(options.includeUntracked).toBe(false);
    });
  });

  describe('Response Formatter', () => {
    it('formats clean repository status correctly', () => {
      const result = {
        success: true,
        currentBranch: 'main',
        isClean: true,
        stagedChanges: {},
        unstagedChanges: {},
        untrackedFiles: [],
        conflictedFiles: [],
      };

      const content = gitStatusTool.responseFormatter!(result);

      assertJsonContent(content, {
        success: true,
        currentBranch: 'main',
        isClean: true,
      });

      assertJsonField(content, 'currentBranch', 'main');
      assertJsonField(content, 'isClean', true);
      assertLlmFriendlyFormat(content, 30);
    });

    it('formats status with changes correctly', () => {
      const result = {
        success: true,
        currentBranch: 'feature-branch',
        isClean: false,
        stagedChanges: {
          added: ['new-file.txt'],
          modified: ['existing-file.txt'],
        },
        unstagedChanges: {
          modified: ['changed-file.txt'],
        },
        untrackedFiles: ['untracked.txt'],
        conflictedFiles: [],
      };

      const content = gitStatusTool.responseFormatter!(result);

      assertJsonContent(content, {
        success: true,
        currentBranch: 'feature-branch',
        isClean: false,
      });

      assertJsonField(content, 'currentBranch', 'feature-branch');
      assertJsonField(content, 'isClean', false);

      const parsed = parseJsonContent(content) as {
        stagedChanges: { added: string[]; modified: string[] };
        unstagedChanges: { modified: string[] };
        untrackedFiles: string[];
      };

      expect(parsed.stagedChanges.added).toContain('new-file.txt');
      expect(parsed.stagedChanges.modified).toContain('existing-file.txt');
      expect(parsed.unstagedChanges.modified).toContain('changed-file.txt');
      expect(parsed.untrackedFiles).toContain('untracked.txt');

      assertLlmFriendlyFormat(content);
    });

    it('formats status with conflicts', () => {
      const result = {
        success: true,
        currentBranch: 'main',
        isClean: false,
        stagedChanges: {},
        unstagedChanges: {},
        untrackedFiles: [],
        conflictedFiles: ['conflict1.txt', 'conflict2.txt'],
      };

      const content = gitStatusTool.responseFormatter!(result);

      assertJsonContent(content, {
        success: true,
        currentBranch: 'main',
        isClean: false,
      });

      assertJsonField(content, 'conflictedFiles', [
        'conflict1.txt',
        'conflict2.txt',
      ]);

      const parsed = parseJsonContent(content) as {
        conflictedFiles: string[];
      };
      expect(parsed.conflictedFiles).toHaveLength(2);
    });

    it('formats status without branch (detached HEAD)', () => {
      const result = {
        success: true,
        currentBranch: null,
        isClean: true,
        stagedChanges: {},
        unstagedChanges: {},
        untrackedFiles: [],
        conflictedFiles: [],
      };

      const content = gitStatusTool.responseFormatter!(result);

      assertJsonContent(content, {
        success: true,
        currentBranch: null,
        isClean: true,
      });

      assertJsonField(content, 'currentBranch', null);
      assertJsonField(content, 'isClean', true);
    });

    it('includes counts for each category', () => {
      const result = {
        success: true,
        currentBranch: 'main',
        isClean: false,
        stagedChanges: {
          added: ['file1.txt', 'file2.txt'],
          modified: ['file3.txt'],
        },
        unstagedChanges: {
          modified: ['file4.txt', 'file5.txt', 'file6.txt'],
        },
        untrackedFiles: ['file7.txt'],
        conflictedFiles: [],
      };

      const content = gitStatusTool.responseFormatter!(result);

      assertJsonContent(content, {
        success: true,
        currentBranch: 'main',
        isClean: false,
      });

      const parsed = parseJsonContent(content) as {
        stagedChanges: { added: string[]; modified: string[] };
        unstagedChanges: { modified: string[] };
        untrackedFiles: string[];
      };

      // Check for counts
      expect(parsed.stagedChanges.added).toHaveLength(2);
      expect(parsed.stagedChanges.modified).toHaveLength(1);
      expect(parsed.unstagedChanges.modified).toHaveLength(3);
      expect(parsed.untrackedFiles).toHaveLength(1);
    });
  });

  describe('Tool Metadata', () => {
    it('has correct tool name', () => {
      expect(gitStatusTool.name).toBe('git_status');
    });

    it('has correct read-only annotation', () => {
      expect(gitStatusTool.annotations?.readOnlyHint).toBe(true);
    });

    it('has descriptive title and description', () => {
      expect(gitStatusTool.title).toBeTruthy();
      expect(gitStatusTool.description).toBeTruthy();
      expect(gitStatusTool.description.length).toBeGreaterThan(20);
    });

    it('has valid input and output schemas', () => {
      expect(gitStatusTool.inputSchema).toBeDefined();
      expect(gitStatusTool.outputSchema).toBeDefined();
    });
  });
});
