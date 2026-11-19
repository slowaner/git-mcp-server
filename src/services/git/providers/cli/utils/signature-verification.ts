/**
 * @fileoverview Fail-closed verifier policy independent of localized prose.
 * @module services/git/providers/cli/utils/signature-verification
 */

/** Format derived from the stored Git object's signature armor. */
export type SignatureType = 'gpg' | 'ssh' | 'x509';

/** Presence, cryptographic evidence, and native verifier acceptance are distinct. */
export interface SignatureVerification {
  verified: boolean;
  cryptographicallyValid: boolean;
  trust: 'trusted' | 'untrusted' | 'unknown';
  signatureType?: SignatureType;
  signerKey?: string;
}

/**
 * Consume `git verify-tag --raw` status. A zero exit AND positive status are
 * required; signal/unknown exit, failure status and prose alone never pass.
 * Trust means only the configured native verifier policy, not host authorization.
 * GPG and CMS raw status share a format: callers must supply the type from the
 * validated immutable Git object, never infer it from localized verifier prose.
 */
export function verifySignatureStatus(
  stderr: string,
  exitCode: number | undefined,
  signatureType: SignatureType,
  signal?: string | null,
): SignatureVerification {
  if (
    signatureType !== 'gpg' &&
    signatureType !== 'ssh' &&
    signatureType !== 'x509'
  )
    return { verified: false, cryptographicallyValid: false, trust: 'unknown' };
  const statuses = stderr
    .split('\n')
    .filter((line) => line.startsWith('[GNUPG:] '))
    .map((line) => line.slice(9));
  const valid = statuses
    .map((line) =>
      /^VALIDSIG ([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})(?: |$)/.exec(line),
    )
    .find((match) => match !== null);
  const failed = statuses.some((line) =>
    /^(?:BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|KEYEXPIRED|SIGEXPIRED|KEYREVOKED|NO_PUBKEY|NODATA|FAILURE|ERROR|BADARMOR)(?: |$)/.test(
      line,
    ),
  );
  const trusted = statuses.some((line) =>
    /^TRUST_(?:FULLY|ULTIMATE)(?: |$)/.test(line),
  );
  const untrusted = statuses.some((line) =>
    /^TRUST_(?:NEVER|UNDEFINED|MARGINAL)(?: |$)/.test(line),
  );
  const ssh =
    /^Good "git" signature for (.+) with \S+ key (SHA256:[A-Za-z0-9+/=]+)$/m.exec(
      stderr,
    );
  const sshFailure =
    /^(?:No principal matched|Could not verify signature|Signature verification failed|error:)/m.test(
      stderr,
    );
  const positive =
    signatureType === 'ssh' ? Boolean(ssh && !sshFailure) : Boolean(valid);
  const result: SignatureVerification = {
    verified: exitCode === 0 && !signal && !failed && positive,
    cryptographicallyValid:
      signatureType === 'ssh' ? Boolean(ssh) : Boolean(valid),
    trust:
      trusted || (ssh && !sshFailure && exitCode === 0 && !signal)
        ? 'trusted'
        : untrusted
          ? 'untrusted'
          : 'unknown',
  };
  if (valid && signatureType !== 'ssh') {
    result.signatureType = signatureType;
    result.signerKey = valid[1]!;
  } else if (ssh && signatureType === 'ssh') {
    result.signatureType = 'ssh';
    result.signerKey = ssh[2]!;
  }
  return result;
}
