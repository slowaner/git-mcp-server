/**
 * @fileoverview Canonical pinned-publisher typed JSON, preserving source separately.
 * @module scripts/security/release-publisher-wire
 * @see https://github.com/modelcontextprotocol/registry/tree/741d575fc2ffe774fa51f442ec6fb2987dd03e18/pkg
 */

type Shape = Record<string, Field>;
type Field = {
  kind:
    | 'string'
    | 'boolean'
    | 'present-string'
    | 'object'
    | 'array'
    | 'map'
    | 'json';
  omit?: boolean;
  pointer?: boolean;
  shape?: () => Shape;
  strings?: boolean;
};
const string = (omit = true): Field => ({ kind: 'string', omit });
const boolean: Field = { kind: 'boolean', omit: true };
const object = (shape: () => Shape, pointer = true): Field => ({
  kind: 'object',
  shape,
  pointer,
});
const array = (shape?: () => Shape): Field => ({
  kind: 'array',
  omit: true,
  ...(shape ? { shape } : {}),
  strings: !shape,
});
const map = (shape: () => Shape): Field => ({ kind: 'map', omit: true, shape });

// Exact model/types.go fields; zero-valued omitempty fields disappear only here.
const input: Shape = {
  description: string(),
  isRequired: boolean,
  format: string(),
  value: string(),
  isSecret: boolean,
  default: string(),
  placeholder: string(),
  choices: array(),
};
const variables = () => input;
const withVariables: Shape = { ...input, variables: map(variables) };
const keyValue: Shape = { ...withVariables, name: string(false) };
const argument: Shape = {
  ...withVariables,
  type: string(false),
  name: string(),
  isRepeated: boolean,
  // model/argument.go preserves explicitly supplied empty strings, unlike Input.
  value: { kind: 'present-string' },
  valueHint: { kind: 'present-string' },
};
const transport: Shape = {
  type: string(false),
  url: string(),
  headers: array(() => keyValue),
  variables: map(variables),
};
const pkg: Shape = {
  registryType: string(false),
  registryBaseUrl: string(),
  identifier: string(false),
  version: string(),
  fileSha256: string(),
  runtimeHint: string(),
  transport: object(() => transport, false),
  runtimeArguments: array(() => argument),
  packageArguments: array(() => argument),
  environmentVariables: array(() => keyValue),
};
const repository: Shape = {
  url: string(),
  source: string(),
  id: string(),
  subfolder: string(),
};
const icon: Shape = {
  src: string(false),
  mimeType: { kind: 'present-string' },
  sizes: array(),
  theme: { kind: 'present-string' },
};
const server: Shape = {
  $schema: string(false),
  name: string(false),
  description: string(false),
  title: string(),
  repository: object(() => repository),
  version: string(false),
  websiteUrl: string(),
  icons: array(() => icon),
  packages: array(() => pkg),
  remotes: array(() => transport),
  _meta: object(() => ({
    'io.modelcontextprotocol.registry/publisher-provided': {
      kind: 'json',
      omit: true,
    },
  })),
};

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('Unsupported pinned publisher object.');
  return value as Record<string, unknown>;
}

function unicode(value: string): string {
  if (
    value !==
    new TextDecoder('utf-8', { ignoreBOM: true }).decode(
      new TextEncoder().encode(value),
    )
  )
    throw new Error('Unsupported publisher Unicode.');
  return value;
}

function json(value: unknown, depth: number): unknown {
  if (depth > 32)
    throw new Error('Publisher metadata nesting budget exceeded.');
  if (typeof value === 'string') return unicode(value);
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map((item) => json(item, depth + 1));
  const result: Record<string, unknown> = Object.create(null);
  for (const [key, item] of Object.entries(record(value)))
    result[unicode(key)] = json(item, depth + 1);
  return result;
}

function normalize(
  value: unknown,
  shape: Shape,
  depth: number,
): Record<string, unknown> {
  if (depth > 32)
    throw new Error('Publisher metadata nesting budget exceeded.');
  const source = value == null ? {} : record(value);
  if (Object.keys(source).some((key) => !Object.hasOwn(shape, key)))
    throw new Error('Unsupported field in pinned publisher model.');
  const result: Record<string, unknown> = Object.create(null);
  for (const [name, field] of Object.entries(shape)) {
    const item = source[name];
    if (field.kind === 'string' || field.kind === 'present-string') {
      if (item != null && typeof item !== 'string')
        throw new Error('Unsupported publisher string.');
      if (field.kind === 'present-string' && item == null) continue;
      const text = unicode((item ?? '') as string);
      if (!field.omit || text !== '') result[name] = text;
    } else if (field.kind === 'boolean') {
      if (item != null && typeof item !== 'boolean')
        throw new Error('Unsupported publisher boolean.');
      if (item === true) result[name] = true;
    } else if (field.kind === 'object') {
      if (field.pointer && item == null) continue;
      result[name] = normalize(item, field.shape!(), depth + 1);
    } else if (field.kind === 'array') {
      if (item == null) continue;
      if (!Array.isArray(item)) throw new Error('Unsupported publisher array.');
      if (item.length)
        result[name] = item.map((entry) => {
          if (field.strings) {
            if (entry !== null && typeof entry !== 'string')
              throw new Error('Unsupported publisher choice.');
            return unicode((entry ?? '') as string);
          }
          return normalize(entry, field.shape!(), depth + 1);
        });
    } else if (field.kind === 'map') {
      if (item == null) continue;
      const values = record(item);
      if (!Object.keys(values).length) continue;
      result[name] = Object.fromEntries(
        Object.entries(values).map(([key, entry]) => [
          unicode(key),
          normalize(entry, field.shape!(), depth + 1),
        ]),
      );
    } else if (field.kind === 'json') {
      if (item == null) continue;
      const values = record(item);
      if (Object.keys(values).length) result[name] = json(values, depth + 1);
    }
  }
  return result;
}

/** Model drift fails closed; only the documented legacy mcpName is not a wire field. */
export function publisherWireManifest(source: string): Record<string, unknown> {
  if (Buffer.byteLength(source) > 4 * 1024 * 1024)
    throw new Error('Publisher manifest byte budget exceeded.');
  const value = record(JSON.parse(source));
  const { mcpName: legacy, ...manifest } = value;
  if (legacy !== undefined && typeof legacy !== 'string')
    throw new Error('Unsupported legacy manifest identity.');
  return normalize(manifest, server, 0);
}
