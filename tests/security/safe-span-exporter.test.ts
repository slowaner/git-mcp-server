/**
 * @fileoverview Captured trace export privacy including auto-instrumented spans.
 * @module tests/security/safe-span-exporter
 */
import { createTraceState, SpanKind, SpanStatusCode } from '@opentelemetry/api';
import { resourceFromAttributes } from '@opentelemetry/resources';
import type { ReadableSpan, SpanExporter } from '@opentelemetry/sdk-trace-node';
import { describe, expect, it } from 'bun:test';
import {
  SafeSpanExporter,
  safeReadableSpan,
} from '@/utils/telemetry/safe-span-exporter.js';
import { auditCorrelation } from '@/utils/internal/safe-audit.js';

const sentinel = 'SYNTHETIC_TRACE_PRIVATE_SENTINEL';
function hostileSpan(): ReadableSpan {
  const context = {
    traceId: 'a'.repeat(32),
    spanId: 'b'.repeat(16),
    traceFlags: 1,
    traceState: createTraceState(`private=${sentinel}`),
  };
  return {
    name: `https://synthetic:${sentinel}@example.invalid/?token=${sentinel}`,
    kind: SpanKind.INTERNAL,
    spanContext: () => context,
    parentSpanContext: context,
    startTime: [1, 0],
    endTime: [2, 0],
    duration: [1, 0],
    ended: true,
    status: { code: SpanStatusCode.ERROR, message: sentinel },
    attributes: {
      'code.function': 'git_push',
      'mcp.tool.input_bytes': 23,
      'mcp.tool.success': false,
      'mcp.tool.error_code': sentinel,
      'http.url': sentinel,
      'session.id': sentinel,
      'exception.message': sentinel,
    },
    events: [
      { name: sentinel, time: [1, 0], attributes: { private: sentinel } },
    ],
    links: [{ context, attributes: { claims: [sentinel] } }],
    resource: resourceFromAttributes({
      private: sentinel,
      'process.command_args': [sentinel],
    }),
    instrumentationScope: Object.assign(
      { name: sentinel, version: sentinel },
      { attributes: { secret: sentinel } },
    ),
    droppedAttributesCount: 0,
    droppedEventsCount: 0,
    droppedLinksCount: 0,
  };
}

describe('trace export boundary', () => {
  it('captures no payload while retaining operation, metrics and trace correlation', () => {
    const captured: ReadableSpan[] = [];
    const downstream: SpanExporter = {
      export(spans, callback) {
        captured.push(...spans);
        callback({ code: 0 });
      },
      async shutdown() {},
    };
    let code = -1;
    new SafeSpanExporter(downstream).export([hostileSpan()], (result) => {
      code = result.code;
    });
    expect(code).toBe(0);
    const exported = captured[0]!;
    const snapshot = JSON.stringify({
      ...exported,
      context: exported.spanContext(),
      resources: exported.resource.attributes,
    });
    expect(snapshot).not.toContain(sentinel);
    expect(exported.spanContext().traceId).toBe('a'.repeat(32));
    expect(exported.attributes['audit.trace_correlation']).toBe(
      auditCorrelation('traceId', 'a'.repeat(32)),
    );
    expect(exported.spanContext().traceState).toBeUndefined();
    expect(exported.parentSpanContext?.traceState).toBeUndefined();
    expect(exported.attributes).toMatchObject({
      'code.function': 'git_push',
      'mcp.tool.input_bytes': 23,
      'mcp.tool.success': false,
    });
    expect(exported.name).toBe('tool_execution:git_push');
    expect(exported.events).toEqual([]);
    expect(exported.links).toEqual([]);
  });

  it('does not mutate spans consumed by other runtime code', () => {
    const original = hostileSpan();
    safeReadableSpan(original);
    expect(original.status.message).toBe(sentinel);
    expect(original.events).toHaveLength(1);
  });

  it('bounds dynamic operation names and exporter exception text', async () => {
    const original = hostileSpan();
    const safe = safeReadableSpan({
      ...original,
      attributes: {
        'code.function': sentinel,
        'mcp.tool.input_bytes': Infinity,
      },
    });
    expect(safe.name).toBe('internal_operation');
    expect(safe.attributes['mcp.tool.input_bytes']).toBeUndefined();
    let resultError: Error | undefined;
    const exporter = new SafeSpanExporter({
      export(_spans, callback) {
        callback({ code: 1, error: new Error(sentinel) });
      },
      async shutdown() {
        throw new Error(sentinel);
      },
      async forceFlush() {
        throw new Error(sentinel);
      },
    });
    exporter.export([original], (result) => {
      resultError = result.error;
    });
    expect(resultError?.message).toBe('Telemetry export failed');
    await expect(exporter.shutdown()).rejects.toThrow(
      'Telemetry shutdown failed',
    );
    await expect(exporter.forceFlush()).rejects.toThrow(
      'Telemetry flush failed',
    );
  });
});
