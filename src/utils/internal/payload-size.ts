/**
 * @fileoverview Bounded payload-size metadata without serializing object graphs.
 * @module utils/internal/payload-size
 */

/** Maximum UTF-16 units inspected for an exact primitive JSON string size. */
export const MAX_MEASURED_STRING_CODE_UNITS = 65_536;

/** Unknown measurements omit bytes; zero never stands in for an unknown size. */
export interface PayloadSize {
  readonly known: boolean;
  readonly bytes?: number;
}

/**
 * Measure only bounded primitives. Objects, arrays, toJSON/getters and large
 * strings are never copied or traversed for observability. This is metadata,
 * not a request, process-output or JSON-RPC wire-envelope limit.
 */
export function payloadSize(value: unknown): PayloadSize {
  if (value === undefined) return { known: true, bytes: 0 };
  if (value === null) return { known: true, bytes: 4 };
  if (typeof value === 'boolean') return { known: true, bytes: value ? 4 : 5 };
  if (typeof value === 'number')
    return {
      known: true,
      bytes: Number.isFinite(value) ? String(value).length : 4,
    };
  if (
    typeof value !== 'string' ||
    value.length > MAX_MEASURED_STRING_CODE_UNITS
  )
    return { known: false };
  let bytes = 2; // JSON string quotes.
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index);
    if (
      unit === 0x22 ||
      unit === 0x5c ||
      unit === 0x08 ||
      unit === 0x0c ||
      unit === 0x0a ||
      unit === 0x0d ||
      unit === 0x09
    )
      bytes += 2;
    else if (unit < 0x20) bytes += 6;
    else if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        index++;
      } else bytes += 6; // Well-formed JSON escapes lone surrogates.
    } else if (unit >= 0xdc00 && unit <= 0xdfff) bytes += 6;
    else if (unit < 0x80) bytes++;
    else if (unit < 0x800) bytes += 2;
    else bytes += 3;
  }
  return { known: true, bytes };
}
