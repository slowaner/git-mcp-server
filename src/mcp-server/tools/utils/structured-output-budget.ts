/**
 * @fileoverview Bounded JSON envelope sizing before formatting or serialization.
 * @module mcp-server/tools/utils/structured-output-budget
 */
import { recordGitExecutionFailure } from '@/services/git/providers/cli/utils/execution-context.js';
import { GitExecutionError } from '@/services/git/providers/cli/utils/execution-errors.js';

/** Complete response envelope ceiling, independent from native raw-byte limits. */
export const MAX_STRUCTURED_RESPONSE_BYTES = 16 * 1024 * 1024;

/** Reject complete oversized/unsupported results; never truncate or copy payloads. */
export function assertStructuredOutputBudget(
  value: unknown,
  limit: number,
): void {
  let bytes = 0,
    items = 0;
  const active = new WeakSet<object>();
  const fail = (): never => {
    throw recordGitExecutionFailure(
      new GitExecutionError(
        'OUTPUT_LIMIT',
        'Structured tool output exceeds the supported response budget.',
      ),
    );
  };
  if (!Number.isSafeInteger(limit) || limit < 1) fail();
  const add = (size: number) => {
    bytes += size;
    if (bytes > limit) fail();
  };
  const string = (text: string) => {
    add(2);
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i);
      if (code === 34 || code === 92 || [8, 9, 10, 12, 13].includes(code))
        add(2);
      else if (code < 32) add(6);
      else if (code < 128) add(1);
      else if (code < 2048) add(2);
      else if (code >= 0xd800 && code <= 0xdbff) {
        const next = text.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          add(4);
          i++;
        } else add(6);
      } else if (code >= 0xdc00 && code <= 0xdfff) add(6);
      else add(3);
    }
  };
  const walk = (node: unknown, depth: number): void => {
    if (++items > 100000 || depth > 64) fail();
    if (node === null || node === undefined) {
      add(4);
      return;
    }
    if (typeof node === 'string') {
      string(node);
      return;
    }
    if (typeof node === 'boolean') {
      add(node ? 4 : 5);
      return;
    }
    if (typeof node === 'number') {
      add(Number.isFinite(node) ? String(node).length : 4);
      return;
    }
    if (typeof node !== 'object') fail();
    const object = node;
    if (active.has(object)) fail();
    const array = Array.isArray(object);
    const prototype: unknown = Object.getPrototypeOf(object);
    if (!array && prototype !== Object.prototype && prototype !== null) fail();
    active.add(object);
    add(2);
    let count = 0;
    if (array) {
      const length = (object as unknown[]).length;
      if (length > 100000) fail();
      for (let i = 0; i < length; i++) {
        if (count++) add(1);
        const descriptor = Object.getOwnPropertyDescriptor(object, String(i));
        if (descriptor && !('value' in descriptor)) fail();
        walk(descriptor?.value, depth + 1);
      }
    } else {
      for (const key in object) {
        const descriptor = Object.getOwnPropertyDescriptor(object, key);
        if (!descriptor?.enumerable) continue;
        if (!('value' in descriptor)) fail();
        if (descriptor.value === undefined) continue;
        if (count++) add(1);
        string(key);
        add(1);
        walk(descriptor.value, depth + 1);
      }
    }
    active.delete(object);
  };
  walk(value, 0);
}
