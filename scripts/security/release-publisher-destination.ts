/**
 * @fileoverview Read-only effective destination preflight for the pinned publisher.
 * @module scripts/security/release-publisher-destination
 * @see https://github.com/modelcontextprotocol/registry/blob/741d575fc2ffe774fa51f442ec6fb2987dd03e18/cmd/publisher/commands/login.go
 * @see https://github.com/modelcontextprotocol/registry/blob/741d575fc2ffe774fa51f442ec6fb2987dd03e18/cmd/publisher/commands/publish.go
 */
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';

/** The only supported upload/receipt target, selected before any destination upload. */
export const MCP_REGISTRY = 'https://registry.modelcontextprotocol.io';
const MAX_CONFIG_BYTES = 64 * 1024;
const jsonString = /"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/g;
const string = jsonString.source;
const flatMap = new RegExp(
  `^\\s*\\{\\s*(?:${string}\\s*:\\s*${string}(?:\\s*,\\s*${string}\\s*:\\s*${string})*)?\\s*\\}\\s*$`,
);

/** Reject ambiguous/unsupported config without logging credentials or target strings. */
export function publisherDestination(source: Uint8Array): typeof MCP_REGISTRY {
  if (!source.length || source.length > MAX_CONFIG_BYTES)
    throw new Error('Unsupported publisher configuration.');
  const text = new TextDecoder('utf-8', {
    fatal: true,
    ignoreBOM: true,
  }).decode(source);
  if (!flatMap.test(text))
    throw new Error('Unsupported publisher configuration.');
  const strings = [...text.matchAll(jsonString)].map(
    (match) => JSON.parse(match[0]) as string,
  );
  const values = new Map<string, string>();
  for (let index = 0; index < strings.length; index += 2) {
    const key = strings[index]!;
    if (!['token', 'registry', 'method'].includes(key) || values.has(key))
      throw new Error('Ambiguous or unsupported publisher configuration.');
    values.set(key, strings[index + 1]!);
  }
  if (!values.get('token'))
    throw new Error('Publisher authentication is unavailable.');
  // PublishCommand uses only saved registry, with this exact default. No publish
  // registry flag or environment variable is supported by the pinned executable.
  const target = values.get('registry') || MCP_REGISTRY;
  if (target !== MCP_REGISTRY && target !== `${MCP_REGISTRY}/`)
    throw new Error('Unsupported publisher destination.');
  return MCP_REGISTRY;
}

/** No global config writes, login, destination rewrite or alternate HOME. */
export async function readPublisherConfiguration(
  home: string | undefined,
): Promise<{ home: string; bytes: Uint8Array }> {
  if (!home || !isAbsolute(home))
    throw new Error('Publisher home is unavailable.');
  try {
    const file = await open(
      join(home, '.config', 'mcp-publisher', 'token.json'),
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
    try {
      const stat = await file.stat();
      if (!stat.isFile() || stat.size <= 0 || stat.size > MAX_CONFIG_BYTES)
        throw new Error('Unsupported publisher configuration.');
      const buffer = Buffer.alloc(MAX_CONFIG_BYTES + 1);
      let total = 0;
      for (;;) {
        const { bytesRead } = await file.read(
          buffer,
          total,
          buffer.length - total,
          total,
        );
        if (!bytesRead) break;
        total += bytesRead;
        if (total > MAX_CONFIG_BYTES)
          throw new Error('Unsupported publisher configuration.');
      }
      return { home, bytes: buffer.subarray(0, total) };
    } finally {
      await file.close();
    }
  } catch {
    throw new Error('Publisher configuration unreadable or unsupported.');
  }
}

/** Recheck the same effective config before each effect; retain bytes only in memory. */
export function publisherDestinationGate(
  read: () => Promise<{ home: string; bytes: Uint8Array }> = () =>
    readPublisherConfiguration(process.env.HOME),
): () => Promise<typeof MCP_REGISTRY> {
  let initial: { home: string; bytes: Buffer } | undefined;
  return async () => {
    const current = await read();
    const target = publisherDestination(current.bytes);
    if (
      initial &&
      (initial.home !== current.home || !initial.bytes.equals(current.bytes))
    )
      throw new Error(
        'Effective publisher configuration changed after preflight.',
      );
    initial ??= { home: current.home, bytes: Buffer.from(current.bytes) };
    return target;
  };
}
