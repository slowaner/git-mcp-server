/**
 * @fileoverview Per-operation object output and concurrency-bound regressions.
 * @module tests/security/object-read-budget
 */
import { describe, expect, it } from 'bun:test';
import { objectReadBudget } from '@/services/git/providers/cli/utils/object-read-budget.js';

describe('structured object aggregate budget', () => {
  it('counts both streams in UTF8 and rejects one byte above aggregate limit without truncation', async () => {
    const outputs = [
      { stdout: 'é', stderr: '' },
      { stdout: '', stderr: 'x' },
      { stdout: 'z', stderr: '' },
    ] as const;
    let calls = 0;
    const read = objectReadBudget(async () => outputs[calls++]!, {
      maxBytes: 3,
      maxCalls: 5,
    });
    expect(await read(['first'])).toEqual(outputs[0]);
    expect(await read(['second'])).toEqual(outputs[1]);
    await expect(read(['third'])).rejects.toThrow(/Aggregate/);
    await expect(read(['fourth'])).rejects.toThrow(/exhausted/);
    expect(calls).toBe(3);
  });

  it('caps zero-byte command counts before calling the executor again', async () => {
    let calls = 0;
    const read = objectReadBudget(
      async () => {
        calls++;
        return { stdout: '', stderr: '' };
      },
      { maxBytes: 1, maxCalls: 2 },
    );
    await read(['first']);
    await read(['second']);
    await expect(read(['third'])).rejects.toThrow(/exhausted/);
    expect(calls).toBe(2);
  });

  it('preserves typed executor failure and never retries it', async () => {
    const failure = Object.assign(new Error('Process cancelled'), {
      reason: 'CANCELLED',
    });
    let calls = 0;
    const read = objectReadBudget(
      async () => {
        calls++;
        throw failure;
      },
      { maxBytes: 10, maxCalls: 3 },
    );
    await expect(read(['first'])).rejects.toBe(failure);
    await expect(read(['retry'])).rejects.toThrow(/exhausted/);
    expect(calls).toBe(1);
  });

  it('rejects parallel readers rather than multiplying in-flight buffers', async () => {
    let release!: (value: { stdout: string; stderr: string }) => void;
    let calls = 0;
    const read = objectReadBudget(
      async () => {
        calls++;
        return new Promise((resolve) => {
          release = resolve;
        });
      },
      { maxBytes: 10, maxCalls: 3 },
    );
    const first = read(['first']);
    await expect(read(['parallel'])).rejects.toThrow(/sequential/);
    release({ stdout: 'data', stderr: '' });
    await expect(first).rejects.toThrow(/exhausted/);
    expect(calls).toBe(1);
  });

  it('rejects invalid bounds rather than accepting an unbounded profile', () => {
    for (const maxBytes of [0, -1, Infinity, NaN, 1.5])
      expect(() =>
        objectReadBudget(async () => ({ stdout: '', stderr: '' }), {
          maxBytes,
          maxCalls: 1,
        }),
      ).toThrow();
  });
});
