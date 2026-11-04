/**
 * @fileoverview Single-attempt strict or explicitly native signing semantics.
 * @module services/git/providers/cli/utils/signing-policy
 */

/**
 * Required adds an explicit signing request and checks presence after creation.
 * Native delegates to operator-trusted Git configuration on the first attempt;
 * unsigned objects are possible only when that native policy permits them.
 */
export type SigningPolicy = 'required' | 'native';

/** Map the existing operator setting without changing native Git configuration. */
export function signingPolicy(explicitSigning: boolean): SigningPolicy {
  return explicitSigning ? 'required' : 'native';
}

/**
 * Run creation exactly once in either policy. Neither a signing failure nor a
 * hook failure is safely retryable: hooks may already have had side effects.
 * Read-only inspection may be retried by a caller after classified infrastructure
 * recovery, but must never cause this function's creation to run again.
 */
export async function createWithSigningPolicy<T extends { signed: boolean }>(
  policy: SigningPolicy,
  create: (requireSigning: boolean) => Promise<void>,
  inspect: () => Promise<T>,
): Promise<T> {
  await create(policy === 'required');
  const result = await inspect();
  if (policy === 'required' && !result.signed) {
    throw new Error(
      'Required signature is absent after creation; inspect repository state before another operation',
    );
  }
  return result;
}
