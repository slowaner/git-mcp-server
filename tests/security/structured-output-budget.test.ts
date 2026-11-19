/**
 * @fileoverview Exact JSON size boundaries and terminal output rejection.
 * @module tests/security/structured-output-budget.test
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { assertStructuredOutputBudget } from '../../src/mcp-server/tools/utils/structured-output-budget.js';
import {
  withGitExecutionContext,
  getGitExecutionFailure,
} from '../../src/services/git/providers/cli/utils/execution-context.js';
import { nativeFileNames } from '../../src/services/git/providers/cli/utils/git-file-operands.js';

describe('structured response budget', () => {
  it('keeps valid replacement/BOM names distinct from invalid string surrogates', () => {
    assert.deepEqual(nativeFileNames('\ufeffname\0\ufffdname\0'), [
      '\ufeffname',
      '\ufffdname',
    ]);
    assert.throws(
      () => nativeFileNames('\ud800\0'),
      /Invalid Git filename output/,
    );
  });
  it('makes caught filename framing/item overflow terminal without partial records', async () => {
    for (const [output, limits, reason] of [
      [
        'one\0truncated',
        { maxBytes: 100, maxFiles: 10 },
        'INVALID_OUTPUT_FORMAT',
      ],
      ['one\0two\0', { maxBytes: 100, maxFiles: 1 }, 'OUTPUT_LIMIT'],
      ['too long\0', { maxBytes: 1, maxFiles: 1 }, 'OUTPUT_LIMIT'],
    ] as const) {
      await assert.rejects(
        withGitExecutionContext({ startedAt: Date.now() }, async () => {
          assert.throws(() => nativeFileNames(output, limits));
          assert.equal(getGitExecutionFailure()?.reason, reason);
        }),
      );
    }
  });
  it('matches JSON escaping and Unicode byte lengths at the exact boundary', () => {
    for (const value of [
      { text: '\0\n\t"\\😀\ufffd\ufeff' },
      ['a', undefined, null, true, 1.2],
      { absent: undefined, nested: { value: '\ud800' } },
    ]) {
      const length = Buffer.byteLength(JSON.stringify(value));
      assert.doesNotThrow(() => assertStructuredOutputBudget(value, length));
      assert.throws(
        () => assertStructuredOutputBudget(value, length - 1),
        /response budget/,
      );
    }
  });
  it('rejects getters without calling them, cycles and excessive structure', () => {
    let called = false;
    assert.throws(() =>
      assertStructuredOutputBudget(
        {
          get text() {
            called = true;
            return 'secret';
          },
        },
        1000,
      ),
    );
    assert.equal(called, false);
    const cycle: unknown[] = [];
    cycle.push(cycle);
    assert.throws(() => assertStructuredOutputBudget(cycle, 1000));
    assert.throws(() =>
      assertStructuredOutputBudget(new Array(100001), 1000000),
    );
  });
  it('keeps a caught overflow terminal for the whole request', async () => {
    await assert.rejects(
      withGitExecutionContext({ startedAt: Date.now() }, async () => {
        assert.throws(() =>
          assertStructuredOutputBudget({ text: 'x'.repeat(100) }, 10),
        );
        assert.equal(getGitExecutionFailure()?.reason, 'OUTPUT_LIMIT');
        return 'partial result must not escape';
      }),
      /response budget/,
    );
  });
});
