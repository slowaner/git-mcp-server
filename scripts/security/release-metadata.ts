/**
 * @fileoverview Offline pinned MCP manifest validation and explicit pre-tag sync.
 * @module scripts/security/release-metadata
 */
import { Ajv } from 'ajv';
import { readFile } from 'node:fs/promises';
import { sha256 } from './release-evidence.js';
import { TOOLCHAIN_PINS } from './toolchain-pins.js';

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Validate the pinned registry schema without network access or metadata writes. */
export async function validateReleaseMetadata(
  pkg: unknown,
  server: unknown,
): Promise<void> {
  const schemaBytes = await readFile(
    new URL('./server.schema.json', import.meta.url),
  );
  if (sha256(schemaBytes) !== TOOLCHAIN_PINS.schema.sha256) {
    throw new Error('Vendored MCP schema differs from its reviewed digest.');
  }
  const ajv = new Ajv({
    strict: false,
    allErrors: false,
    validateFormats: true,
  });
  ajv.addFormat('uri', {
    type: 'string',
    validate: (value: string) => URL.canParse(value),
  });
  const validate = ajv.compile(JSON.parse(schemaBytes.toString('utf8')));
  if (!validate(server))
    throw new Error('server.json fails the pinned MCP schema.');
  if (
    !object(pkg) ||
    !object(server) ||
    typeof pkg.version !== 'string' ||
    !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(pkg.version) ||
    typeof pkg.name !== 'string' ||
    typeof pkg.mcpName !== 'string' ||
    server.$schema !== TOOLCHAIN_PINS.schema.url ||
    server.name !== pkg.mcpName ||
    server.mcpName !== pkg.mcpName ||
    server.version !== pkg.version ||
    !Array.isArray(server.packages) ||
    server.packages.length === 0 ||
    !server.packages.every(
      (entry: unknown) =>
        object(entry) &&
        entry.registryType === 'npm' &&
        entry.registryBaseUrl === 'https://registry.npmjs.org' &&
        entry.identifier === pkg.name &&
        entry.version === pkg.version,
    )
  ) {
    throw new Error('Release metadata drift; sync and review before tagging.');
  }
}

/** Produce preparation bytes only; callers must reject tagged HEAD before writing. */
export function synchronizedMetadata(
  pkg: unknown,
  server: unknown,
): Record<string, unknown> {
  if (
    !object(pkg) ||
    !object(server) ||
    typeof pkg.version !== 'string' ||
    typeof pkg.name !== 'string' ||
    typeof pkg.mcpName !== 'string' ||
    !Array.isArray(server.packages)
  )
    throw new Error('Invalid release metadata inputs.');
  return {
    ...structuredClone(server),
    $schema: TOOLCHAIN_PINS.schema.url,
    name: pkg.mcpName,
    mcpName: pkg.mcpName,
    version: pkg.version,
    packages: server.packages.map((entry: unknown) => {
      if (!object(entry) || entry.registryType !== 'npm')
        throw new Error('Unsupported registry package.');
      return { ...entry, identifier: pkg.name, version: pkg.version };
    }),
  };
}
