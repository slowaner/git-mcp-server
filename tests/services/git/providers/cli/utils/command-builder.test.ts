/**
 * @fileoverview Unit tests for git command builder utilities
 * @module tests/services/git/providers/cli/utils/command-builder.test
 */
import { describe, expect, it } from 'vitest';

import {
  buildGitCommand,
  buildGitEnv,
  validateGitArgs,
} from '../../../../../../src/services/git/providers/cli/utils/command-builder.js';

describe('Command Builder', () => {
  describe('buildGitCommand', () => {
    it('should build a simple command', () => {
      const result = buildGitCommand({ command: 'status' });
      expect(result).toEqual(['status']);
    });

    it('should build a command with arguments', () => {
      const result = buildGitCommand({
        command: 'log',
        args: ['--oneline', '-n', '5'],
      });
      expect(result).toEqual(['log', '--oneline', '-n', '5']);
    });

    it('should handle empty args array', () => {
      const result = buildGitCommand({
        command: 'status',
        args: [],
      });
      expect(result).toEqual(['status']);
    });

    it('should preserve argument order', () => {
      const result = buildGitCommand({
        command: 'commit',
        args: ['-m', 'message', '--amend'],
      });
      expect(result).toEqual(['commit', '-m', 'message', '--amend']);
    });

    it('should handle arguments with special characters', () => {
      const result = buildGitCommand({
        command: 'commit',
        args: ['-m', 'feat: add "quotes" and $pecial chars'],
      });
      expect(result).toEqual([
        'commit',
        '-m',
        'feat: add "quotes" and $pecial chars',
      ]);
    });
  });

  describe('buildGitEnv', () => {
    const policy = {
      profile: 'trusted' as const,
      binaryPath: '/usr/bin/git',
      homeDirectory: '/tmp/operator-home',
      helperPath: '/usr/bin:/bin',
    };
    it('uses operator HOME/PATH and fixed noninteractive settings', () => {
      const env = buildGitEnv(
        { HOME: '/outside', PATH: '/outside', GIT_TERMINAL_PROMPT: '1' },
        policy,
      );
      expect(env.HOME).toBe('/tmp/operator-home');
      expect(env.PATH).toBe('/usr/bin:/bin');
      expect(env.GIT_TERMINAL_PROMPT).toBe('0');
      expect(env.LANG).toBe('en_US.UTF-8');
    });
    it('strips routing, injected config and unrelated secrets', () => {
      const env = buildGitEnv(
        {
          GIT_DIR: '/outside',
          GIT_CONFIG_COUNT: '1',
          SERVER_SECRET: 'fixture',
          NODE_OPTIONS: '--require=fixture',
        },
        policy,
      );
      for (const key of [
        'GIT_DIR',
        'GIT_CONFIG_COUNT',
        'SERVER_SECRET',
        'NODE_OPTIONS',
      ])
        expect(env[key]).toBeUndefined();
    });
    it('retains explicit trusted agent/keyring authority', () => {
      const env = buildGitEnv(
        { SSH_AUTH_SOCK: '/operator/agent', GNUPGHOME: '/operator/keyring' },
        policy,
      );
      expect(env.SSH_AUTH_SOCK).toBe('/operator/agent');
      expect(env.GNUPGHOME).toBe('/operator/keyring');
    });
    it('does not mutate inherited input or share output objects', () => {
      const input = { PATH: '/outside' };
      expect(buildGitEnv(input, policy)).not.toBe(buildGitEnv(input, policy));
      expect(input).toEqual({ PATH: '/outside' });
    });
  });

  describe('validateGitArgs', () => {
    it('does not grant runtime eval or native config routing short flags to Git', () => {
      for (const flag of ['-e', '-c', '-C', '-o']) {
        expect(() => validateGitArgs([flag])).toThrow(/Unsafe git flag/i);
      }
    });
    it('should accept valid arguments', () => {
      expect(() => validateGitArgs(['status'])).not.toThrow();
      expect(() => validateGitArgs(['commit', '-m', 'message'])).not.toThrow();
      expect(() =>
        validateGitArgs(['log', '--oneline', '-n', '10']),
      ).not.toThrow();
    });

    it('should reject null bytes in arguments', () => {
      expect(() => validateGitArgs(['status\0'])).toThrow(/null byte/i);
      expect(() =>
        validateGitArgs(['commit', '-m', 'msg\0with\0nulls']),
      ).toThrow(/null byte/i);
    });

    it('should accept safe short flags', () => {
      expect(() => validateGitArgs(['-v'])).not.toThrow();
      expect(() => validateGitArgs(['-f'])).not.toThrow();
      expect(() => validateGitArgs(['-q'])).not.toThrow();
      expect(() => validateGitArgs(['-m', 'message'])).not.toThrow();
    });

    it('should accept safe long flags', () => {
      expect(() => validateGitArgs(['--version'])).not.toThrow();
      expect(() => validateGitArgs(['--help'])).not.toThrow();
      expect(() => validateGitArgs(['--porcelain'])).not.toThrow();
      expect(() => validateGitArgs(['--oneline'])).not.toThrow();
    });

    it('should accept allow-listed flags with values', () => {
      // Acceptance is gated on the flag NAME being in SAFE_GIT_OPTIONS,
      // not merely on the presence of `=`. This is the security contract:
      // an unknown flag with a value is still rejected.
      expect(() => validateGitArgs(['--format=%H'])).not.toThrow();
      expect(() => validateGitArgs(['--max-count=10'])).not.toThrow();
      expect(() => validateGitArgs(['--initial-branch=main'])).not.toThrow();
      expect(() => validateGitArgs(['--depth=1'])).not.toThrow();
    });

    describe('argument injection (CVE-2017-1000117 class)', () => {
      // Each case below is a known attack payload from public CVEs or the
      // same vulnerability family. validateGitArgs must reject them — they
      // were the failure mode in GHSA-86j2-w37r-q256.

      it('rejects --config=core.sshCommand= (advisory PoC)', () => {
        expect(() =>
          validateGitArgs([
            '--config=core.sshCommand=sh -c "touch /tmp/pwned"',
          ]),
        ).toThrow(/Unsafe git flag|argument injection/i);
      });

      it('rejects --upload-pack= (CVE-2017-1000117 family)', () => {
        expect(() =>
          validateGitArgs(['--upload-pack=touch /tmp/pwned']),
        ).toThrow(/Unsafe git flag/i);
      });

      it('rejects --exec= (option-injection variant)', () => {
        expect(() => validateGitArgs(['--exec=touch /tmp/pwned'])).toThrow(
          /Unsafe git flag/i,
        );
      });

      it('rejects --receive-pack= (push-side variant)', () => {
        expect(() =>
          validateGitArgs(['--receive-pack=touch /tmp/pwned']),
        ).toThrow(/Unsafe git flag/i);
      });

      it('rejects standalone --config (not in allow-list)', () => {
        expect(() => validateGitArgs(['--config'])).toThrow(/Unsafe git flag/i);
      });

      it('rejects unknown long flags without values', () => {
        expect(() => validateGitArgs(['--unknown-flag'])).toThrow(
          /Unsafe git flag/i,
        );
        expect(() => validateGitArgs(['--evil'])).toThrow(/Unsafe git flag/i);
      });

      it('rejects unknown long flags with values (= bypass closed)', () => {
        // The previous bug: any --flag=value passed unchecked. Closed now.
        expect(() => validateGitArgs(['--unknown-flag=value'])).toThrow(
          /Unsafe git flag/i,
        );
        expect(() =>
          validateGitArgs(['--ProxyCommand=touch /tmp/pwned']),
        ).toThrow(/Unsafe git flag/i);
      });

      it('rejects malicious URL-shaped args that start with dash', () => {
        // Even if a leading-dash URL slips past schema validation,
        // validateGitArgs catches it because git's option parser would
        // treat it as a flag.
        expect(() =>
          validateGitArgs(['--upload-pack=evil', '/tmp/dest']),
        ).toThrow(/Unsafe git flag/i);
      });

      it('rejects --server-option= (smuggled config)', () => {
        expect(() =>
          validateGitArgs(['--server-option=core.sshCommand=evil']),
        ).toThrow(/Unsafe git flag/i);
      });

      it('error message names the offending flag for debuggability', () => {
        try {
          validateGitArgs(['--evil-flag=payload']);
          throw new Error('should have thrown');
        } catch (err) {
          expect((err as Error).message).toContain('--evil-flag');
        }
      });
    });

    describe('--end-of-options separator', () => {
      it('accepts --end-of-options as a safe flag', () => {
        expect(() => validateGitArgs(['--end-of-options'])).not.toThrow();
      });

      it('still rejects `-`-prefixed args after --end-of-options', () => {
        /**
         * Design choice: `validateGitArgs` validates every arg in isolation.
         * It does NOT model git's parser state — anything `-`-prefixed must
         * still pass the allow-list, even after `--end-of-options`. Schema-
         * layer leading-`-` rejection is the primary defense for user input
         * that's expected to land positionally; this validator is the safety
         * net that catches anything slipping past the schema layer.
         */
        expect(() =>
          validateGitArgs(['--end-of-options', '--upload-pack=evil']),
        ).toThrow(/Unsafe git flag/i);
      });
    });

    it('should handle shell metacharacters safely (array spawn protection)', () => {
      // These are safe because we use array-based spawn, not shell
      expect(() =>
        validateGitArgs(['commit', '-m', 'msg; rm -rf /']),
      ).not.toThrow();
      expect(() =>
        validateGitArgs(['commit', '-m', 'msg | cat']),
      ).not.toThrow();
      expect(() =>
        validateGitArgs(['commit', '-m', 'msg $HOME']),
      ).not.toThrow();
      expect(() =>
        validateGitArgs(['commit', '-m', 'msg `whoami`']),
      ).not.toThrow();
    });

    it('should accept newlines in commit messages', () => {
      expect(() =>
        validateGitArgs(['commit', '-m', 'line1\nline2\nline3']),
      ).not.toThrow();
    });

    it('should handle empty args array', () => {
      expect(() => validateGitArgs([])).not.toThrow();
    });

    it('should accept file paths as arguments', () => {
      expect(() => validateGitArgs(['add', 'src/file.ts'])).not.toThrow();
      expect(() => validateGitArgs(['add', '../parent/file.ts'])).not.toThrow();
      expect(() => validateGitArgs(['add', './relative/path'])).not.toThrow();
    });
  });
});
