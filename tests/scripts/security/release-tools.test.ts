/**
 * @fileoverview Publisher platform selection and archive tampering regressions.
 * @module tests/scripts/security/release-tools
 */
import { describe, expect, it } from 'bun:test';
import {
  publisherPlatform,
  verifyToolArchive,
} from '../../../scripts/security/release-tools.js';
import { sha256 } from '../../../scripts/security/release-evidence.js';

describe('reviewed release tools', () => {
  it('pins different vendor hashes for Linux x64 and Darwin arm64', () => {
    const linux = publisherPlatform('linux', 'x64');
    const darwin = publisherPlatform('darwin', 'arm64');
    expect(linux.url).toContain('/v1.8.7/mcp-publisher_linux_amd64.tar.gz');
    expect(darwin.url).toContain('/v1.8.7/mcp-publisher_darwin_arm64.tar.gz');
    expect(linux.sha256).not.toBe(darwin.sha256);
  });
  it('fails closed on unsupported platforms without a global binary fallback', () => {
    expect(() => publisherPlatform('win32', 'x64')).toThrow('Unsupported');
    expect(() => publisherPlatform('linux', 'arm64')).toThrow('Unsupported');
  });
  it('accepts only exact reviewed archive bytes', () => {
    const reviewed = new TextEncoder().encode('synthetic reviewed archive');
    expect(() => verifyToolArchive(reviewed, sha256(reviewed))).not.toThrow();
    expect(() =>
      verifyToolArchive(new TextEncoder().encode('tampered'), sha256(reviewed)),
    ).toThrow();
    expect(() => verifyToolArchive(reviewed, 'unknown')).toThrow();
  });
});
