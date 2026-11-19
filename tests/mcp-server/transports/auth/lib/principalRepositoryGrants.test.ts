/**
 * @fileoverview Equal-scope principal separation and explicit repository grant tests.
 * @module tests/mcp-server/transports/auth/lib/principalRepositoryGrants.test
 */
import path from 'node:path';
import { describe, expect, it } from 'vitest';

import { PrincipalRepositoryGrants } from '@/mcp-server/transports/auth/lib/principalRepositoryGrants.js';

const owner = {
  issuer: 'https://issuer.example.test',
  tenantId: 'a',
  clientId: 'client',
  subject: 'user-a',
};
const rootA = path.resolve('/repositories/a');
const rootB = path.resolve('/repositories/b');

describe('principal repository grants', () => {
  it('selects only explicit owner roots and permits deliberate shared repositories', () => {
    const other = { ...owner, tenantId: 'b', subject: 'user-b' };
    const shared = path.resolve('/repositories/shared');
    const policy = new PrincipalRepositoryGrants([
      { ...owner, roots: [rootA, shared] },
      { ...other, roots: [rootB, shared] },
    ]);
    expect(policy.rootsFor(owner)).toEqual([rootA, shared]);
    expect(policy.rootsFor(other)).toEqual([rootB, shared]);
    expect(Object.isFrozen(policy.rootsFor(owner))).toBe(true);
  });

  it.each(['issuer', 'tenantId', 'clientId', 'subject'] as const)(
    'denies a different %s without global or tenant-only fallback',
    (field) => {
      const policy = new PrincipalRepositoryGrants([
        { ...owner, roots: [rootA] },
      ]);
      expect(() => policy.rootsFor({ ...owner, [field]: 'foreign' })).toThrow();
    },
  );

  it('copies operator root arrays so later mutation cannot expand access', () => {
    const roots = [rootA];
    const policy = new PrincipalRepositoryGrants([{ ...owner, roots }]);
    roots.push(rootB);
    expect(policy.rootsFor(owner)).toEqual([rootA]);
  });

  it.each(
    [
      undefined,
      {},
      [],
      [{ ...owner, roots: [] }],
      [{ ...owner, roots: ['relative'] }],
      [{ ...owner, roots: [rootA], wildcard: true }],
      [{ ...owner, subject: undefined, roots: [rootA] }],
      [
        { ...owner, roots: [rootA] },
        { ...owner, roots: [rootB] },
      ],
      [{ ...owner, roots: [`${rootA}\0`] }],
    ].map((input) => ({ input })),
  )('rejects ambiguous or incomplete configuration %j', ({ input }) => {
    expect(() => new PrincipalRepositoryGrants(input)).toThrow();
  });
});
