/**
 * @fileoverview Payload-free export boundary for manual and automatic tracing.
 * @module utils/telemetry/safe-span-exporter
 */
import type { Attributes, SpanContext } from '@opentelemetry/api';
import { resourceFromAttributes } from '@opentelemetry/resources';
import type { ReadableSpan, SpanExporter } from '@opentelemetry/sdk-trace-node';
import {
  auditCorrelation,
  auditOperation,
} from '@/utils/internal/safe-audit.js';
import * as attributes from './semconv.js';

const numericAttributes = new Set<string>([
  attributes.ATTR_MCP_TOOL_INPUT_BYTES,
  attributes.ATTR_MCP_TOOL_OUTPUT_BYTES,
  attributes.ATTR_MCP_TOOL_DURATION_MS,
  attributes.ATTR_MCP_TOOL_MEMORY_RSS_BEFORE,
  attributes.ATTR_MCP_TOOL_MEMORY_RSS_AFTER,
  attributes.ATTR_MCP_TOOL_MEMORY_RSS_DELTA,
  attributes.ATTR_MCP_TOOL_MEMORY_HEAP_USED_BEFORE,
  attributes.ATTR_MCP_TOOL_MEMORY_HEAP_USED_AFTER,
  attributes.ATTR_MCP_TOOL_MEMORY_HEAP_USED_DELTA,
  'http.response.status_code',
]);

function safeContext(context: SpanContext): SpanContext {
  return {
    traceId: /^[0-9a-f]{32}$/.test(context.traceId)
      ? context.traceId
      : '0'.repeat(32),
    spanId: /^[0-9a-f]{16}$/.test(context.spanId)
      ? context.spanId
      : '0'.repeat(16),
    traceFlags: context.traceFlags & 1,
  };
}

/** Copy only classified operational metrics, never a raw exception or URL. */
export function safeSpanAttributes(input: Attributes): Attributes {
  const output: Attributes = {};
  for (const key of numericAttributes) {
    const value = input[key];
    if (typeof value === 'number' && Number.isFinite(value))
      output[key] = value;
  }
  for (const key of [
    attributes.ATTR_MCP_TOOL_SUCCESS,
    attributes.ATTR_MCP_TOOL_INPUT_SIZE_KNOWN,
    attributes.ATTR_MCP_TOOL_OUTPUT_SIZE_KNOWN,
  ]) {
    const value = input[key];
    if (typeof value === 'boolean') output[key] = value;
  }
  output[attributes.ATTR_CODE_FUNCTION] = auditOperation(
    input[attributes.ATTR_CODE_FUNCTION],
  );
  output[attributes.ATTR_CODE_NAMESPACE] = 'mcp-tools';
  const code = input[attributes.ATTR_MCP_TOOL_ERROR_CODE];
  if (
    code === 'UNHANDLED_ERROR' ||
    code === 'UNKNOWN_ERROR' ||
    (typeof code === 'string' && /^-32[0-9]{3}$/.test(code))
  )
    output[attributes.ATTR_MCP_TOOL_ERROR_CODE] = code;
  const method = input['http.request.method'];
  if (
    typeof method === 'string' &&
    ['GET', 'POST', 'DELETE', 'OPTIONS', 'HEAD'].includes(method)
  )
    output['http.request.method'] = method;
  return output;
}

/**
 * Construct a fresh span: spreading the source would retain hidden payloads.
 * Events, links, baggage/tracestate, auto-detected host/process resources and
 * arbitrary instrumentation scope attributes are deliberately excluded.
 */
export function safeReadableSpan(span: ReadableSpan): ReadableSpan {
  const spanContext = safeContext(span.spanContext());
  const parent = span.parentSpanContext;
  const operation = auditOperation(
    span.attributes[attributes.ATTR_CODE_FUNCTION],
  );
  return {
    name:
      operation === 'internal'
        ? 'internal_operation'
        : `tool_execution:${operation}`,
    kind: span.kind,
    spanContext: () => spanContext,
    ...(parent ? { parentSpanContext: safeContext(parent) } : {}),
    startTime: span.startTime,
    endTime: span.endTime,
    duration: span.duration,
    status: { code: span.status.code },
    attributes: {
      ...safeSpanAttributes(span.attributes),
      'audit.trace_correlation': auditCorrelation(
        'traceId',
        spanContext.traceId,
      )!,
    },
    events: [],
    links: [],
    ended: span.ended,
    resource: resourceFromAttributes({ 'service.name': 'git-mcp-server' }),
    instrumentationScope: { name: 'git-mcp-server' },
    droppedAttributesCount: span.droppedAttributesCount,
    droppedEventsCount: span.droppedEventsCount + span.events.length,
    droppedLinksCount: span.droppedLinksCount + span.links.length,
  };
}

/** Enforce the same sink policy regardless of instrumentation source. */
export class SafeSpanExporter implements SpanExporter {
  constructor(private readonly exporter: SpanExporter) {}

  /** Export only new allowlisted records; preserve failure without raw details. */
  export(
    spans: ReadableSpan[],
    callback: Parameters<SpanExporter['export']>[1],
  ): void {
    try {
      this.exporter.export(spans.map(safeReadableSpan), (result) =>
        callback({
          code: result.code,
          ...(result.error
            ? { error: new Error('Telemetry export failed') }
            : {}),
        }),
      );
    } catch {
      callback({ code: 1, error: new Error('Telemetry export failed') });
    }
  }

  /** Flush exporter state without leaking its error text to diagnostics. */
  async forceFlush(): Promise<void> {
    try {
      await this.exporter.forceFlush?.();
    } catch {
      throw new Error('Telemetry flush failed');
    }
  }

  /** Close exporter state without leaking endpoint/credential error details. */
  async shutdown(): Promise<void> {
    try {
      await this.exporter.shutdown();
    } catch {
      throw new Error('Telemetry shutdown failed');
    }
  }
}
