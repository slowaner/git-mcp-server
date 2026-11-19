/**
 * @fileoverview CycloneDX inventory of every integrity-pinned npm lock entry.
 * @module scripts/security/lock-inventory
 */
import ts from 'typescript';
import { sha256 } from './release-evidence.js';

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Inventory all locked copies, including development/build dependencies. This
 * is not a runtime reachability classification. Unsupported source formats,
 * non-npm entries and missing integrity fail closed instead of being omitted.
 */
export function createLockInventory(lock: string) {
  const parsed = ts.parseConfigFileTextToJson('bun.lock', lock);
  const config: unknown = parsed.config;
  if (
    parsed.error ||
    !object(config) ||
    ![1, 2, 3].includes(config.lockfileVersion as number) ||
    config.configVersion !== 1 ||
    !object(config.packages) ||
    Object.keys(config.packages).length === 0
  ) {
    throw new Error('Unsupported or incomplete Bun lock inventory.');
  }
  const components = new Map<
    string,
    {
      type: 'library';
      'bom-ref': string;
      name: string;
      version: string;
      purl: string;
      hashes: { alg: 'SHA-512'; content: string }[];
    }
  >();
  for (const entry of Object.values(config.packages)) {
    if (
      !Array.isArray(entry) ||
      typeof entry[0] !== 'string' ||
      typeof entry[1] !== 'string' ||
      typeof entry[3] !== 'string'
    ) {
      throw new Error('Lock entry lacks immutable npm integrity.');
    }
    const split = entry[0].lastIndexOf('@');
    const name = entry[0].slice(0, split);
    const version = entry[0].slice(split + 1);
    if (
      split <= 0 ||
      !/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(name) ||
      !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version) ||
      (entry[1] !== '' &&
        (!URL.canParse(entry[1]) ||
          new URL(entry[1]).origin !== 'https://registry.npmjs.org')) ||
      !/^sha512-[A-Za-z0-9+/]{86}==$/.test(entry[3])
    ) {
      throw new Error(
        'Unsupported package resolution or missing SHA-512 integrity.',
      );
    }
    const purl = `pkg:npm/${name.split('/').map(encodeURIComponent).join('/')}@${encodeURIComponent(version)}`;
    const component = {
      type: 'library' as const,
      'bom-ref': purl,
      name,
      version,
      purl,
      hashes: [
        {
          alg: 'SHA-512' as const,
          content: Buffer.from(entry[3].slice(7), 'base64').toString('hex'),
        },
      ],
    };
    const existing = components.get(purl);
    if (existing && JSON.stringify(existing) !== JSON.stringify(component)) {
      throw new Error('One package identity has conflicting locked integrity.');
    }
    components.set(purl, component);
  }
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      properties: [
        { name: 'git-mcp-server:bun.lock:sha256', value: sha256(lock) },
      ],
    },
    components: [...components.values()].sort((a, b) =>
      a.purl.localeCompare(b.purl),
    ),
  };
}
