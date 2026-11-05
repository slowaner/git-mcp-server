/**
 * @fileoverview Configured/default destination and destructive refspec regressions.
 * @module tests/security/push-plan
 */
import { describe, expect, it } from 'bun:test';
import {
  resolvePrivatePushPlan,
  resolvePushPlan,
} from '@/services/git/providers/cli/utils/push-plan.js';

describe('concrete push destinations', () => {
  it('uses the same-named destination only for proved triangular simple pushes', () => {
    const config = { currentBranch: 'feature', pushDefault: 'simple' };
    expect(
      resolvePushPlan({}, { ...config, pushRemoteMatchesTracking: false }),
    ).toEqual([
      {
        source: 'refs/heads/feature',
        destination: 'refs/heads/feature',
        force: false,
        delete: false,
      },
    ]);
    for (const relationship of [undefined, true])
      expect(() =>
        resolvePushPlan(
          {},
          {
            ...config,
            ...(relationship === undefined
              ? {}
              : { pushRemoteMatchesTracking: relationship }),
          },
        ),
      ).toThrow(/upstream/);
    expect(() =>
      resolvePushPlan(
        {},
        {
          ...config,
          pushRemoteMatchesTracking: true,
          upstreamDestination: 'refs/heads/main',
        },
      ),
    ).toThrow(/differs/);
    expect(() =>
      resolvePushPlan(
        {},
        {
          ...config,
          pushDefault: 'upstream',
          pushRemoteMatchesTracking: false,
        },
      ),
    ).toThrow(/upstream/);
    expect(() =>
      resolvePushPlan(
        { forceWithLease: true },
        { ...config, pushRemoteMatchesTracking: false },
      ),
    ).toThrow(/confirmation/);
  });
  it('distinguishes only a proved explicit empty tag set from an invalid empty plan', () => {
    expect(
      resolvePrivatePushPlan(
        { tags: true },
        {
          tagRefs: [],
          configuredRefspecs: ['+feature:main'],
          pushDefault: 'matching',
        },
      ),
    ).toEqual({ kind: 'empty-explicit-tags' });
    expect(() => resolvePushPlan({ tags: true }, { tagRefs: [] })).toThrow();
    expect(() => resolvePrivatePushPlan({ tags: true }, {})).toThrow();
    expect(() => resolvePrivatePushPlan({}, { tagRefs: [] })).toThrow();
    expect(() =>
      resolvePrivatePushPlan({ tags: true }, { tagRefs: [], mirror: true }),
    ).toThrow();
    expect(() =>
      resolvePrivatePushPlan({ tags: true, branch: '' }, { tagRefs: [] }),
    ).toThrow();
    expect(() =>
      resolvePrivatePushPlan({ tags: true, delete: true }, { tagRefs: [] }),
    ).toThrow();
    expect(() =>
      resolvePrivatePushPlan({ tags: true, force: true }, { tagRefs: [] }),
    ).toThrow(/confirmation/);
    expect(
      resolvePrivatePushPlan(
        { tags: true, branch: 'feature' },
        { tagRefs: [] },
      ),
    ).toEqual({
      kind: 'destinations',
      entries: [
        {
          source: 'refs/heads/feature',
          destination: 'refs/heads/feature',
          force: false,
          delete: false,
        },
      ],
    });
  });
  it('pins feature-to-main destination with qualified refs', () => {
    const plan = resolvePushPlan(
      {
        branch: 'feature',
        remoteBranch: 'main',
        forceWithLease: true,
        confirmed: true,
      },
      {},
    );
    expect(plan).toEqual([
      {
        source: 'refs/heads/feature',
        destination: 'refs/heads/main',
        force: false,
        delete: false,
      },
    ]);
  });

  for (const spec of [
    '+refs/heads/feature:refs/heads/main',
    ':refs/heads/main',
  ])
    it(`denies configured destructive default ${spec} without confirmation`, () => {
      expect(() => resolvePushPlan({}, { configuredRefspecs: [spec] })).toThrow(
        /confirmation/,
      );
      expect(
        resolvePushPlan({ confirmed: true }, { configuredRefspecs: [spec] })[0]
          ?.destination,
      ).toBe('refs/heads/main');
    });

  it('resolves upstream/current/simple independently of source display name', () => {
    expect(
      resolvePushPlan(
        {},
        {
          currentBranch: 'feature',
          pushDefault: 'upstream',
          upstreamDestination: 'refs/heads/main',
        },
      )[0]?.destination,
    ).toBe('refs/heads/main');
    expect(
      resolvePushPlan(
        {},
        { currentBranch: 'feature', pushDefault: 'current' },
      )[0]?.destination,
    ).toBe('refs/heads/feature');
    expect(() =>
      resolvePushPlan(
        {},
        {
          currentBranch: 'feature',
          pushDefault: 'simple',
          upstreamDestination: 'main',
        },
      ),
    ).toThrow(/differs/);
    expect(() =>
      resolvePushPlan(
        { forceWithLease: true },
        {
          currentBranch: 'feature',
          pushDefault: 'upstream',
          upstreamDestination: 'main',
        },
      ),
    ).toThrow(/confirmation/);
  });

  it('fails closed on mirror/matching/wildcard/multiple or detached ambiguity', () => {
    for (const spec of [
      ':',
      '+:',
      'refs/heads/*:refs/heads/*',
      'feature:main:other',
    ])
      expect(() =>
        resolvePushPlan({ confirmed: true }, { configuredRefspecs: [spec] }),
      ).toThrow();
    expect(() =>
      resolvePushPlan({ confirmed: true, branch: 'feature' }, { mirror: true }),
    ).toThrow(/Mirror/);
    expect(() =>
      resolvePushPlan(
        {},
        { pushDefault: 'matching', currentBranch: 'feature' },
      ),
    ).toThrow();
    expect(() => resolvePushPlan({}, {})).toThrow(/Detached/);
    expect(
      resolvePushPlan({ branch: 'HEAD', remoteBranch: 'feature' }, {})[0]
        ?.source,
    ).toBe('HEAD');
  });

  it('enumerates tags with bounded count and no silent truncation or duplicates', () => {
    const refs = Array.from({ length: 256 }, (_, i) => `refs/tags/v${i}`);
    expect(resolvePushPlan({ tags: true }, { tagRefs: refs })).toHaveLength(
      256,
    );
    expect(() =>
      resolvePushPlan(
        { tags: true },
        { tagRefs: [...refs, 'refs/tags/extra'] },
      ),
    ).toThrow(/256/);
    expect(() =>
      resolvePushPlan(
        { tags: true },
        { tagRefs: ['refs/tags/a', 'refs/tags/a'] },
      ),
    ).toThrow(/Duplicate/);
    expect(() =>
      resolvePushPlan({ tags: true }, { tagRefs: ['refs/heads/main'] }),
    ).toThrow(/tag/);
  });
});
