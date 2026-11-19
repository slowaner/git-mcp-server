/**
 * @fileoverview Signing downgrade and repeated hook-side-effect regressions.
 * @module tests/security/signing-policy
 */
import { describe, expect, it } from 'bun:test';
import {
  createWithSigningPolicy,
  signingPolicy,
} from '@/services/git/providers/cli/utils/signing-policy.js';

describe('single-attempt signing', () => {
  for (const failure of [
    'signer unavailable',
    'pre-commit hook failed',
    'process cancelled',
  ])
    it(`never retries or inspects after ${failure}`, async () => {
      const calls: boolean[] = [];
      let inspections = 0;
      await expect(
        createWithSigningPolicy(
          signingPolicy(true),
          async (required) => {
            calls.push(required);
            throw new Error(failure);
          },
          async () => {
            inspections++;
            return { signed: true };
          },
        ),
      ).rejects.toThrow(failure);
      expect(calls).toEqual([true]);
      expect(inspections).toBe(0);
    });

  it('does not repeat creation when postcondition inspection fails', async () => {
    let creations = 0;
    await expect(
      createWithSigningPolicy(
        'required',
        async () => {
          creations++;
        },
        async () => {
          throw new Error('inspection failed');
        },
      ),
    ).rejects.toThrow('inspection failed');
    expect(creations).toBe(1);
  });

  it('rejects unsigned strict postcondition without another mutation', async () => {
    let creations = 0;
    await expect(
      createWithSigningPolicy(
        'required',
        async () => {
          creations++;
        },
        async () => ({ signed: false }),
      ),
    ).rejects.toThrow(/signature is absent/);
    expect(creations).toBe(1);
  });

  it('preserves explicit native policy and actual unsigned presence without fallback', async () => {
    const calls: boolean[] = [];
    const result = await createWithSigningPolicy(
      signingPolicy(false),
      async (required) => {
        calls.push(required);
      },
      async () => ({ signed: false, marker: 'native' }),
    );
    expect(calls).toEqual([false]);
    expect(result).toEqual({ signed: false, marker: 'native' });
  });

  it('keeps native-required signing failure authoritative', async () => {
    let creations = 0;
    await expect(
      createWithSigningPolicy(
        'native',
        async (required) => {
          expect(required).toBe(false);
          creations++;
          throw new Error('native signing required');
        },
        async () => ({ signed: false }),
      ),
    ).rejects.toThrow('native signing required');
    expect(creations).toBe(1);
  });
});
