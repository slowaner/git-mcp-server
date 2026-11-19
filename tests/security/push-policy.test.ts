/**
 * @fileoverview Destructive push normalization and caller assertion contract.
 * @module tests/security/push-policy
 */
import { describe, expect, it } from 'bun:test';
import {
  assertPushPolicy,
  normalizePushRef,
} from '@/services/git/providers/cli/utils/push-policy.js';

describe('push policy', () => {
  for (const destination of [
    'main',
    'refs/heads/main',
    'custom-protected',
    'refs/tags/v1',
    undefined,
  ])
    for (const mode of ['force', 'forceWithLease', 'delete'] as const)
      it(`requires confirmation for ${mode} to ${destination}`, () => {
        expect(() =>
          assertPushPolicy({
            branch: 'feature',
            ...(destination === undefined ? {} : { remoteBranch: destination }),
            [mode]: true,
            confirmed: false,
          }),
        ).toThrow(/confirmation/);
      });

  it('allows ordinary feature push and explicit confirmed destination', () => {
    expect(() => assertPushPolicy({ branch: 'feature' })).not.toThrow();
    expect(() =>
      assertPushPolicy({
        branch: 'feature',
        remoteBranch: 'refs/heads/main',
        forceWithLease: true,
        confirmed: true,
      }),
    ).not.toThrow();
    expect(normalizePushRef('main')).toBe('refs/heads/main');
    expect(normalizePushRef('refs/heads/main')).toBe('refs/heads/main');
  });

  it('fails closed on wildcard, multiple refspec, revision and option syntax', () => {
    for (const value of [
      'HEAD',
      '@',
      '-main',
      'feature:main',
      '+refs/heads/main',
      'refs/heads/*',
      'refs/heads/a..b',
      'refs/heads/.hidden',
      'refs/heads/a.lock',
      'refs/heads/a\nmain',
      'refs/heads/a@{1}',
      'refs/heads/a\\b',
      'refs/heads/a b',
      'refs/remotes/origin/main',
    ])
      expect(() => normalizePushRef(value)).toThrow();
  });

  it('rejects combined and ambiguous destructive modes even when confirmed', () => {
    expect(() =>
      assertPushPolicy({ confirmed: true, force: true, forceWithLease: true }),
    ).toThrow();
    expect(() => assertPushPolicy({ confirmed: true, delete: true })).toThrow();
    expect(() =>
      assertPushPolicy({
        confirmed: true,
        delete: true,
        branch: 'feature',
        tags: true,
      }),
    ).toThrow();
  });
});
