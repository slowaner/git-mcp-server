/**
 * @fileoverview Release ordering and byte provenance tested without publication.
 * @module tests/scripts/security/release-evidence
 */
import { describe, expect, it } from 'bun:test';
import {
  runRelease,
  sha256,
  registryManifest,
  verifyBundleFiles,
  verifyReleaseSource,
  type ReleaseBundle,
  type ReleaseOperations,
  type ReleaseSource,
} from '../../../scripts/security/release-evidence.js';

const commit = 'a'.repeat(40);
const reviewed = { commit, tag: 'v1.2.3' };
const pkg = {
  version: '1.2.3',
  name: '@example/server',
  mcpName: 'io.github.example/server',
  packageManager: 'bun@1.4.3',
};
const server = {
  version: pkg.version,
  name: pkg.mcpName,
  mcpName: pkg.mcpName,
  packages: [
    {
      registryType: 'npm',
      registryBaseUrl: 'https://registry.npmjs.org',
      identifier: pkg.name,
      version: pkg.version,
    },
  ],
};

function source(): ReleaseSource {
  return {
    head: commit,
    tree: 'b'.repeat(40),
    tag: reviewed.tag,
    tagCommit: commit,
    tagObject: 'f'.repeat(40),
    tagType: 'tag',
    status: '',
    packageJson: JSON.stringify(pkg),
    lockfile: 'synthetic locked dependency inventory',
    serverJson: JSON.stringify(server),
    bunVersion: '1.4.3',
  };
}

function fixture() {
  let current = source();
  const calls: string[] = [];
  const bytes = Object.fromEntries(
    Object.entries({
      'source.tar': 'synthetic source archive',
      'package.json': current.packageJson,
      'bun.lock': current.lockfile,
      'server.json': current.serverJson,
      'registry-manifest.json': registryManifest(current.serverJson),
      'package.tgz': 'synthetic packed build',
      'build.json': '{}',
      'sbom.json': '{}',
      'checks.json': '{}',
    }).map(([name, value]) => [name, new TextEncoder().encode(value)]),
  );
  const bundle: ReleaseBundle = {
    schemaVersion: 1,
    source: verifyReleaseSource(current, reviewed),
    files: Object.fromEntries(
      Object.entries(bytes).map(([name, value]) => [name, sha256(value)]),
    ),
  };
  const ops: ReleaseOperations = {
    snapshot: async () => {
      calls.push('snapshot');
      return { ...current };
    },
    checks: async () => {
      calls.push('checks');
    },
    buildBundle: async () => {
      calls.push('build');
      return bundle;
    },
    verifyBundle: async (value) => {
      calls.push('verify');
      verifyBundleFiles(value, bytes);
    },
    publish: async (_value, destination) => {
      calls.push(`publish:${destination}`);
    },
    receipt: async (_value, destination) => {
      calls.push(`receipt:${destination}`);
      return {
        destination,
        version: pkg.version,
        identity: destination === 'npm' ? pkg.name : pkg.mcpName,
        sha256:
          bundle.files[
            destination === 'npm' ? 'package.tgz' : 'registry-manifest.json'
          ]!,
      };
    },
    saveReceipt: async (receipt) => {
      calls.push(`save:${receipt.destination}`);
    },
  };
  return {
    ops,
    calls,
    bytes,
    bundle,
    setSource: (value: ReleaseSource) => {
      current = value;
    },
  };
}

describe('release source gate', () => {
  it('binds reviewed commit, annotated tag, tree, toolchain, manifests and lock bytes', () => {
    const result = verifyReleaseSource(source(), reviewed);
    expect(result.commit).toBe(commit);
    expect(result.packageSha256).toBe(sha256(JSON.stringify(pkg)));
    expect(result.lockSha256).toBe(sha256(source().lockfile));
  });

  const changes: Partial<ReleaseSource>[] = [
    { head: 'c'.repeat(40) },
    { tagCommit: 'c'.repeat(40) },
    { tagObject: '' },
    { tagType: 'commit' },
    { tag: 'v1.2.2' },
    { tree: '' },
    { status: ' M server.json' },
    { status: '?? unexpected-source.ts' },
    { lockfile: '' },
    { bunVersion: '1.4.4' },
    { serverJson: JSON.stringify({ ...server, version: '1.2.2' }) },
    { serverJson: JSON.stringify({ ...server, name: 'other/server' }) },
    { serverJson: JSON.stringify({ ...server, packages: [] }) },
    {
      serverJson: JSON.stringify({
        ...server,
        packages: [{ ...server.packages[0], version: '1.2.2' }],
      }),
    },
    {
      serverJson: JSON.stringify({
        ...server,
        packages: [{ ...server.packages[0], identifier: 'other' }],
      }),
    },
    { packageJson: JSON.stringify({ ...pkg, version: '1.2.3; command' }) },
    { packageJson: JSON.stringify({ ...pkg, packageManager: 'bun@latest' }) },
  ];
  for (const [index, change] of changes.entries()) {
    it(`rejects source or metadata drift ${index + 1}`, () => {
      expect(() =>
        verifyReleaseSource({ ...source(), ...change }, reviewed),
      ).toThrow();
    });
  }
});

describe('release protocol dry runs', () => {
  it('rejects registry payload drift even when its own hash was rewritten', () => {
    const f = fixture();
    f.bytes['registry-manifest.json'] = new TextEncoder().encode('{}');
    f.bundle.files['registry-manifest.json'] = sha256(
      f.bytes['registry-manifest.json'],
    );
    expect(() => verifyBundleFiles(f.bundle, f.bytes)).toThrow(
      'metadata differs',
    );
  });
  it('defaults to preparation only and never uploads', async () => {
    const f = fixture();
    expect(await runRelease(reviewed, f.ops)).toBe(f.bundle);
    expect(f.calls).toEqual([
      'snapshot',
      'checks',
      'snapshot',
      'build',
      'snapshot',
      'verify',
    ]);
  });

  it('persists exact npm receipt before MCP upload', async () => {
    const f = fixture();
    await runRelease(reviewed, f.ops, true);
    expect(f.calls.slice(6)).toEqual([
      'snapshot',
      'verify',
      'publish:npm',
      'receipt:npm',
      'save:npm',
      'snapshot',
      'verify',
      'publish:mcp',
      'receipt:mcp',
      'save:mcp',
    ]);
  });

  it('stops on failed checks without building, committing or publishing', async () => {
    const f = fixture();
    f.ops.checks = async () => {
      throw new Error('gate failed');
    };
    await expect(runRelease(reviewed, f.ops, true)).rejects.toThrow(
      'gate failed',
    );
    expect(f.calls).toEqual(['snapshot']);
  });

  it('stops after fixer drift before build or publication', async () => {
    const f = fixture();
    f.ops.checks = async () => {
      f.setSource({ ...source(), status: ' M package.json' });
    };
    await expect(runRelease(reviewed, f.ops, true)).rejects.toThrow('clean');
    expect(f.calls).toEqual(['snapshot', 'snapshot']);
  });

  it('rejects clean checkout on a moved tag or changed HEAD after build', async () => {
    const f = fixture();
    f.ops.buildBundle = async () => {
      f.setSource({ ...source(), tagCommit: 'd'.repeat(40) });
      return f.bundle;
    };
    await expect(runRelease(reviewed, f.ops, true)).rejects.toThrow(
      'annotated tag',
    );
    expect(f.calls.some((call) => call.startsWith('publish:'))).toBe(false);
  });

  it('rejects lock drift even when a status implementation misses it', async () => {
    const f = fixture();
    f.ops.checks = async () => {
      f.setSource({ ...source(), lockfile: 'other lock' });
    };
    await expect(runRelease(reviewed, f.ops, true)).rejects.toThrow(
      'source changed',
    );
  });

  it('rejects artifact tampering before the first upload', async () => {
    const f = fixture();
    f.bytes['package.tgz'] = new TextEncoder().encode('tampered');
    await expect(runRelease(reviewed, f.ops, true)).rejects.toThrow(
      'byte mismatch',
    );
    expect(f.calls.some((call) => call.startsWith('publish:'))).toBe(false);
  });

  it('rejects missing and additional bundle files', () => {
    const f = fixture();
    const { 'sbom.json': _missing, ...partial } = f.bytes;
    expect(() => verifyBundleFiles(f.bundle, partial)).toThrow('inventory');
    expect(() =>
      verifyBundleFiles(f.bundle, { ...f.bytes, extra: new Uint8Array() }),
    ).toThrow('inventory');
  });

  it('rejects a bundle claiming another reviewed source', async () => {
    const f = fixture();
    f.bundle.source.commit = 'e'.repeat(40);
    await expect(runRelease(reviewed, f.ops, true)).rejects.toThrow(
      'different source',
    );
  });

  it('does not interpret duplicate-version upload errors as success or retry', async () => {
    const f = fixture();
    f.ops.publish = async () => {
      throw new Error('duplicate version');
    };
    await expect(runRelease(reviewed, f.ops, true)).rejects.toThrow(
      'duplicate version',
    );
    expect(f.calls.includes('receipt:npm')).toBe(false);
    expect(f.calls.includes('publish:mcp')).toBe(false);
  });

  it('blocks MCP publication when npm receipt bytes disagree', async () => {
    const f = fixture();
    f.ops.receipt = async () => ({
      destination: 'npm',
      version: pkg.version,
      identity: pkg.name,
      sha256: 'f'.repeat(64),
    });
    await expect(runRelease(reviewed, f.ops, true)).rejects.toThrow(
      'Unverified npm',
    );
    expect(f.calls.includes('publish:mcp')).toBe(false);
  });

  it('retains npm success when the subsequent MCP upload fails', async () => {
    const f = fixture();
    f.ops.publish = async (_bundle, destination) => {
      f.calls.push(`publish:${destination}`);
      if (destination === 'mcp') throw new Error('permission denied');
    };
    await expect(runRelease(reviewed, f.ops, true)).rejects.toThrow(
      'permission denied',
    );
    expect(f.calls.includes('save:npm')).toBe(true);
    expect(f.calls.includes('save:mcp')).toBe(false);
  });
});
