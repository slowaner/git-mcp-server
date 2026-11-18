/**
 * @fileoverview Canonical, versioned tenant and key encoding for storage providers.
 * @module src/storage/core/storageKeyCodec
 */
import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';

// Hex preserves logical prefixes and case on case-insensitive filesystems. The
// component bound fits filesystem names and the combined bound fits KV keys.
const MAX_COMPONENT_BYTES = 120;
const VERSION = 'v2';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function invalidComponent(): never {
  throw new McpError(
    JsonRpcErrorCode.ValidationError,
    'Storage components must be valid Unicode without controls, at most 120 UTF-8 bytes.',
  );
}

/** Encode one exact logical component; never normalize, trim or case-fold it. */
export function encodeStorageComponent(value: string): string {
  if (typeof value !== 'string') return invalidComponent();
  for (const character of value) {
    const point = character.codePointAt(0)!;
    if (
      point <= 0x1f ||
      (point >= 0x7f && point <= 0x9f) ||
      (point >= 0xd800 && point <= 0xdfff)
    ) {
      return invalidComponent();
    }
  }
  const bytes = encoder.encode(value);
  if (bytes.length > MAX_COMPONENT_BYTES) return invalidComponent();
  return `x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

/** Decode only canonical codec output, rejecting aliases and invalid UTF-8. */
export function decodeStorageComponent(encoded: string): string {
  if (!/^x(?:[0-9a-f]{2}){0,120}$/.test(encoded)) return invalidComponent();
  const bytes = Uint8Array.from(encoded.slice(1).match(/.{2}/g) ?? [], (pair) =>
    Number.parseInt(pair, 16),
  );
  // TextDecoder failures are deliberately surfaced as invalid storage input.
  let value: string;
  try {
    value = decoder.decode(bytes);
  } catch {
    return invalidComponent();
  }
  if (encodeStorageComponent(value) !== encoded) return invalidComponent();
  return value;
}

/** Namespace prefix shared by filesystem, object, KV and relational adapters. */
export function storageTenantPrefix(tenantId: string): string {
  if (!tenantId) return invalidComponent();
  return `${VERSION}/${encodeStorageComponent(tenantId)}/`;
}

/** Encode a complete logical key. Legacy unversioned keys are never consulted. */
export function encodeStorageKey(tenantId: string, key: string): string {
  if (!key) return invalidComponent();
  return `${storageTenantPrefix(tenantId)}${encodeStorageComponent(key)}`;
}

/** Encode a list prefix, including the empty prefix for the tenant's keys. */
export function encodeStoragePrefix(tenantId: string, prefix = ''): string {
  return `${storageTenantPrefix(tenantId)}${encodeStorageComponent(prefix)}`;
}

/** Decode a key only within the caller's tenant; reject foreign or legacy keys. */
export function decodeStorageKey(tenantId: string, encoded: string): string {
  const prefix = storageTenantPrefix(tenantId);
  if (!encoded.startsWith(prefix)) return invalidComponent();
  const key = decodeStorageComponent(encoded.slice(prefix.length));
  if (!key) return invalidComponent();
  return key;
}
