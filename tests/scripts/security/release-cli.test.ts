/**
 * @fileoverview Release entry-point requires explicit source, tool and bundle identities.
 * @module tests/scripts/security/release-cli
 */
import { describe, expect, it } from 'bun:test';
import {
  parseReleaseArgs,
  releaseOperations,
} from '../../../scripts/release.js';
import { runRelease } from '../../../scripts/security/release-evidence.js';

const args = [
  '--commit',
  'a'.repeat(40),
  '--tag',
  'v1.2.3',
  '--output',
  '/tmp/g6-test-bundle',
  '--bun-archive',
  '/tmp/bun.zip',
  '--gitleaks-archive',
  '/tmp/gitleaks.tar.gz',
];

describe('release CLI', () => {
  it('prepares only by default', () => {
    const result = parseReleaseArgs(args);
    expect(result.publish).toBe(false);
    expect(result.bundleDigest).toBeUndefined();
  });
  it('requires an independently recorded bundle digest and pinned publisher for upload', () => {
    const result = parseReleaseArgs([
      ...args,
      '--publish',
      '--bundle-sha256',
      'b'.repeat(64),
      '--publisher-archive',
      '/tmp/publisher.tar.gz',
    ]);
    expect(result.publish).toBe(true);
    expect(result.bundleDigest).toBe('b'.repeat(64));
  });
  const invalid = [
    [],
    args.slice(2),
    [...args, '--publish'],
    [...args, '--no-verify'],
    [...args, '--no-commit'],
    [...args, '--commit', 'c'.repeat(40)],
    [...args, '--publisher-archive', '/tmp/publisher.tar.gz'],
    [...args, '--bundle-sha256', 'b'.repeat(64)],
    [
      ...args,
      '--publish',
      '--publisher-archive',
      '/tmp/publisher.tar.gz',
      '--bundle-sha256',
      'invalid',
    ],
    args.map((value) => (value === 'v1.2.3' ? 'v1.2.3;unsafe' : value)),
  ];
  for (const [index, value] of invalid.entries()) {
    it(`rejects incomplete/bypass/publication input ${index + 1}`, () => {
      expect(() => parseReleaseArgs(value)).toThrow();
    });
  }
  it('stops before checks/build/upload on failed real Git source inspection', async () => {
    const options = parseReleaseArgs(args);
    const ops = releaseOperations(
      '/definitely-missing-g6-release-root',
      options,
      {
        bun: '/must-not-run-bun',
        gitleaks: '/must-not-run-scanner',
      },
    );
    await expect(runRelease(options.reviewed, ops)).rejects.toThrow(
      'Release command failed: git',
    );
  });
});
