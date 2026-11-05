/**
 * @fileoverview Pinned typed publisher projection, including explicit-false source metadata.
 * @module tests/scripts/security/release-publisher-wire
 */
import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'bun:test';
import {
  canonicalJson,
  registryManifest,
} from '../../../scripts/security/release-evidence.js';

describe('pinned publisher wire representation', () => {
  it('matches the current manifest golden typed projection while preserving source bytes', async () => {
    const source = await readFile(
      new URL('../../../server.json', import.meta.url),
      'utf8',
    );
    const expected = JSON.parse(source);
    delete expected.mcpName;
    let explicitFalse = 0;
    for (const pkg of expected.packages)
      for (const input of pkg.environmentVariables) {
        expect(input.isRequired).toBe(false);
        delete input.isRequired;
        explicitFalse++;
      }
    expect(explicitFalse).toBeGreaterThan(0);
    expect(registryManifest(source)).toBe(canonicalJson(expected));
    expect(
      await readFile(new URL('../../../server.json', import.meta.url), 'utf8'),
    ).toBe(source);
  });
  it('preserves Argument empty presence, pointer empties, true flags and arbitrary extension false values', () => {
    const source = {
      $schema: 'fixture',
      name: 'io.example/server',
      description: 'Fixture',
      version: '1',
      title: '',
      repository: {},
      icons: [{ src: 'https://example.test/icon', mimeType: '', sizes: [] }],
      packages: [
        {
          registryType: 'npm',
          identifier: 'fixture',
          transport: { type: 'stdio', headers: [] },
          packageArguments: [
            {
              type: 'positional',
              value: '',
              valueHint: '',
              isRequired: false,
              isRepeated: true,
            },
          ],
          environmentVariables: [
            {
              name: 'FIXTURE',
              value: '',
              isRequired: true,
              isSecret: false,
              choices: [],
            },
          ],
        },
      ],
      _meta: {
        'io.modelcontextprotocol.registry/publisher-provided': {
          isRequired: false,
          unrelated: false,
          count: 0,
        },
      },
    };
    expect(JSON.parse(registryManifest(JSON.stringify(source)))).toEqual({
      $schema: 'fixture',
      name: 'io.example/server',
      description: 'Fixture',
      version: '1',
      repository: {},
      icons: [{ src: 'https://example.test/icon', mimeType: '' }],
      packages: [
        {
          registryType: 'npm',
          identifier: 'fixture',
          transport: { type: 'stdio' },
          packageArguments: [
            { type: 'positional', value: '', valueHint: '', isRepeated: true },
          ],
          environmentVariables: [{ name: 'FIXTURE', isRequired: true }],
        },
      ],
      _meta: source._meta,
    });
  });
  for (const source of [
    { newModelField: false },
    {
      packages: [
        { registryType: 'npm', identifier: 'fixture', unknown: false },
      ],
    },
    {
      packages: [
        { environmentVariables: [{ name: 'FIXTURE', isRequired: 'false' }] },
      ],
    },
    { repository: { newModelField: '' } },
    { packages: [{ packageArguments: [{ valueHint: false }] }] },
    {
      remotes: [
        { type: 'stdio', variables: { fixture: { newModelField: false } } },
      ],
    },
  ])
    it('fails closed on unsupported wire/model drift', () => {
      expect(() => registryManifest(JSON.stringify(source))).toThrow(
        'publisher',
      );
    });
});
