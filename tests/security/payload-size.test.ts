/**
 * @fileoverview Bounded primitive JSON byte metadata, never object serialization.
 * @module tests/security/payload-size
 */
import { describe, expect, it } from 'bun:test';
import {
  MAX_MEASURED_STRING_CODE_UNITS,
  payloadSize,
} from '@/utils/internal/payload-size.js';

describe('bounded payload-size metadata', () => {
  for (const value of [
    '',
    'plain',
    'é中文😀',
    '"\\\b\f\n\r\t\x00\x1f',
    '\ud800',
    '\udc00',
    '\ud800x\udc00',
    true,
    false,
    null,
    0,
    -0,
    1.25,
    1e50,
    NaN,
    Infinity,
  ])
    it(`matches independent JSON UTF8 size for ${typeof value} fixture`, () => {
      expect(payloadSize(value)).toEqual({
        known: true,
        bytes: Buffer.byteLength(JSON.stringify(value), 'utf8'),
      });
    });

  it('marks oversized strings unknown at the exact work boundary without truncation', () => {
    expect(payloadSize('a'.repeat(MAX_MEASURED_STRING_CODE_UNITS))).toEqual({
      known: true,
      bytes: MAX_MEASURED_STRING_CODE_UNITS + 2,
    });
    const result = payloadSize('a'.repeat(MAX_MEASURED_STRING_CODE_UNITS + 1));
    expect(result.known).toBe(false);
    expect(result).not.toHaveProperty('bytes');
  });

  it('does not invoke object getters, toJSON, cycles or proxy traps', () => {
    const fail = () => {
      throw new Error('Object graph was inspected');
    };
    const object = {
      get nested() {
        return fail();
      },
      toJSON: fail,
    };
    const cycle: unknown[] = [];
    cycle.push(cycle);
    const proxy = new Proxy(
      {},
      {
        get: fail,
        ownKeys: fail,
        getPrototypeOf: fail,
        getOwnPropertyDescriptor: fail,
      },
    );
    for (const value of [object, cycle, proxy, BigInt(1), Symbol('synthetic')])
      expect(payloadSize(value)).toEqual({ known: false });
    expect(payloadSize(undefined)).toEqual({ known: true, bytes: 0 });
  });
});
