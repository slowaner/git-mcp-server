/**
 * @fileoverview Effective saved-target parsing and read-only drift preflight boundaries.
 * @module tests/scripts/security/release-publisher-destination
 */
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'bun:test';
import {
  MCP_REGISTRY,
  publisherDestination,
  publisherDestinationGate,
  readPublisherConfiguration,
} from '../../../scripts/security/release-publisher-destination.js';

const config = (registry?: string) =>
  Buffer.from(
    JSON.stringify({
      token: 'fixture',
      ...(registry === undefined ? {} : { registry }),
    }),
  );

describe('pinned publisher effective destination', () => {
  for (const registry of [undefined, '', MCP_REGISTRY, MCP_REGISTRY + '/'])
    it('binds the saved or exact default production registry', () => {
      expect(publisherDestination(config(registry))).toBe(MCP_REGISTRY);
    });
  for (const registry of [
    'https://staging.example.test',
    'http://registry.modelcontextprotocol.io',
    MCP_REGISTRY + '/path',
    MCP_REGISTRY + '//',
    MCP_REGISTRY + '?query',
    ' ' + MCP_REGISTRY,
    'https://user@registry.modelcontextprotocol.io',
  ])
    it('blocks an unsupported or ambiguous destination', () => {
      expect(() => publisherDestination(config(registry))).toThrow(
        'destination',
      );
    });
  for (const text of [
    '',
    '{}',
    '{"token":"fixture","registry":null}',
    '{"token":"fixture","extra":"value"}',
    '{"token":"fixture","registry":"","reg\\u0069stry":""}',
    '{"token":"fixture"',
  ])
    it('blocks malformed, duplicate, non-string and incomplete config', () => {
      expect(() => publisherDestination(Buffer.from(text))).toThrow();
    });
  it('rechecks the same home and exact bytes without returning or persisting credentials', async () => {
    let current = { home: '/fixture', bytes: config(MCP_REGISTRY) };
    const check = publisherDestinationGate(async () => current);
    expect(await check()).toBe(MCP_REGISTRY);
    expect(await check()).toBe(MCP_REGISTRY);
    current = {
      ...current,
      bytes: Buffer.from(
        JSON.stringify({ token: 'other fixture', registry: MCP_REGISTRY }),
      ),
    };
    await expect(check()).rejects.toThrow('changed');
    const moved = publisherDestinationGate(async () => current);
    await moved();
    current = { ...current, home: '/different' };
    await expect(moved()).rejects.toThrow('changed');
  });
  it('reads only an existing bounded regular synthetic config and rejects missing/symlink files', async () => {
    const home = await mkdtemp(join(tmpdir(), 'g6-publisher-config-'));
    const directory = join(home, '.config/mcp-publisher');
    try {
      await expect(readPublisherConfiguration(home)).rejects.toThrow(
        'unreadable',
      );
      await mkdir(directory, { recursive: true });
      const path = join(directory, 'token.json');
      await writeFile(path, config(MCP_REGISTRY));
      expect(
        publisherDestination((await readPublisherConfiguration(home)).bytes),
      ).toBe(MCP_REGISTRY);
      await rm(path);
      await writeFile(join(directory, 'fixture.json'), config(MCP_REGISTRY));
      await symlink('fixture.json', path);
      await expect(readPublisherConfiguration(home)).rejects.toThrow(
        'unreadable',
      );
      await rm(path);
      await writeFile(path, Buffer.alloc(64 * 1024 + 1, 0x20));
      await expect(readPublisherConfiguration(home)).rejects.toThrow(
        'unsupported',
      );
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });
});
