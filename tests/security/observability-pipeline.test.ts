/**
 * @fileoverview Capture production performance/error producers before every sink.
 * @module tests/security/observability-pipeline
 */
import { trace, type Span, type Tracer } from '@opentelemetry/api';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import { ErrorHandler } from '@/utils/internal/error-handler/errorHandler.js';
import { logger } from '@/utils/internal/logger.js';
import { measureToolExecution } from '@/utils/internal/performance.js';
import { auditCorrelation } from '@/utils/internal/safe-audit.js';
import { createMcpToolHandler } from '@/mcp-server/tools/utils/toolHandlerFactory.js';
import type { SdkContext } from '@/mcp-server/tools/utils/toolDefinition.js';
import { z } from 'zod';

describe('production observability producer boundaries', () => {
  afterEach(() => vi.restoreAllMocks());

  it('actual SDK handler keeps raw input out of context and raw errors out of logger calls', async () => {
    const sentinel = 'SYNTHETIC_HANDLER_PRIVATE_SENTINEL';
    const captures: unknown[] = [];
    for (const method of ['info', 'error', 'debug', 'warning'] as const)
      vi.spyOn(logger, method).mockImplementation((...args: unknown[]) => {
        captures.push(args);
      });
    const input = {
      token: sentinel,
      nested: { url: 'https://fixture:' + sentinel + '@example.invalid' },
    };
    let rawInputInContext = false;
    const handler = createMcpToolHandler({
      toolName: 'git_push',
      inputSchema: z.object({
        token: z.string().describe('Synthetic private fixture token.'),
        nested: z
          .object({ url: z.string().describe('Synthetic credential URL.') })
          .describe('Nested fixture payload.'),
      }),
      logic: async (_input, context) => {
        rawInputInContext = Object.hasOwn(context, 'input');
        throw new Error(sentinel);
      },
    });
    const response = await handler(input, {
      sessionId: sentinel,
      requestId: 1,
    } as unknown as SdkContext);
    expect(response.isError).toBe(true);
    expect(rawInputInContext).toBe(false);
    expect(JSON.stringify(captures)).not.toContain(sentinel);
    expect(captures.length).toBeGreaterThan(0);
  });

  it('preserves API results/errors while sending no nested/URL/claim/session/error sentinel to logs or traces', async () => {
    const sentinel = 'SYNTHETIC_PIPELINE_PRIVATE_SENTINEL';
    const captures: unknown[] = [];
    const logRecords: Record<string, unknown>[] = [];
    const span = {
      setAttributes(value: unknown) {
        captures.push(value);
      },
      setAttribute(key: string, value: unknown) {
        captures.push({ key, value });
      },
      setStatus(value: unknown) {
        captures.push(value);
      },
      recordException(value: unknown) {
        captures.push(value);
      },
      spanContext() {
        return {
          traceId: 'a'.repeat(32),
          spanId: 'b'.repeat(16),
          traceFlags: 1,
        };
      },
      end() {},
    };
    vi.spyOn(trace, 'getActiveSpan').mockReturnValue(span as unknown as Span);
    vi.spyOn(trace, 'getTracer').mockImplementation((...args) => {
      captures.push(args);
      return {
        startActiveSpan: async (
          name: string,
          run: (value: unknown) => Promise<unknown>,
        ) => {
          captures.push(name);
          return run(span);
        },
      } as unknown as Tracer;
    });
    for (const method of ['info', 'error'] as const)
      vi.spyOn(logger, method).mockImplementation((...args: unknown[]) => {
        captures.push(args);
        logRecords.push(args[1] as Record<string, unknown>);
      });
    const payload = {
      nested: [
        {
          ToKeN: sentinel,
          url: `https://synthetic:${sentinel}@example.invalid/?token=${sentinel}`,
        },
      ],
    };
    const context = {
      toolName: 'git_push',
      requestId: `${sentinel}-request`,
      timestamp: '',
      sessionId: `${sentinel}-session`,
      tenantId: `${sentinel}-tenant`,
      auth: { sub: sentinel, scopes: ['tool:git:write'], claims: payload },
      input: payload,
      traceId: 'a'.repeat(32),
    };
    const result = await measureToolExecution(
      async () => ({ value: sentinel }),
      context,
      payload,
    );
    expect(result.value).toBe(sentinel);
    const failure = new McpError(JsonRpcErrorCode.Forbidden, sentinel, {
      payload,
    });
    await expect(
      measureToolExecution(
        async () => {
          throw failure;
        },
        context,
        payload,
      ),
    ).rejects.toBe(failure);
    const handled = ErrorHandler.handleError(failure, {
      operation: 'git_push',
      context,
      input: payload,
    });
    expect(handled.message).toBe(sentinel);
    ErrorHandler.handleError(Symbol(sentinel), {
      operation: 'git_push',
      context,
      input: payload,
    });
    expect(logRecords).toHaveLength(4);
    const frozenAtBoundary = logRecords.map((record) =>
      Object.isFrozen(record),
    );
    expect(frozenAtBoundary).toEqual([true, true, true, true]);
    expect(JSON.stringify(captures)).not.toContain(sentinel);
    expect(logRecords[0]?.operation).toBe('git_push');
    expect(logRecords[0]?.outcome).toBe('success');
    expect(logRecords[0]?.inputSizeKnown).toBe(false);
    expect(logRecords[0]?.outputSizeKnown).toBe(false);
    expect(Object.hasOwn(logRecords[0]!, 'inputBytes')).toBe(false);
    expect(Object.hasOwn(logRecords[0]!, 'outputBytes')).toBe(false);
    expect(logRecords[2]?.event).toBe('denied');
    expect(logRecords[2]?.outcome).toBe('failure');
    expect(logRecords[2]?.errorCode).toBe(JsonRpcErrorCode.Forbidden);
    for (const [index, record] of logRecords.entries()) {
      expect(record.requestCorrelation).toBe(
        auditCorrelation('requestId', context.requestId),
      );
      expect(Object.hasOwn(record, 'input')).toBe(false);
      expect(Object.hasOwn(record, 'auth')).toBe(false);
      expect(Object.hasOwn(record, 'errorData')).toBe(false);
      expect(
        Object.isFrozen(record),
        `Producer record ${index}: ${JSON.stringify(record)}`,
      ).toBe(true);
    }
  });
});
