/**
 * @fileoverview Payload-free HTTP metrics aggregation and export boundaries.
 * @module utils/telemetry/safe-metric-exporter
 */
import { type Attributes, ValueType } from '@opentelemetry/api';
import { resourceFromAttributes } from '@opentelemetry/resources';
import {
  AggregationTemporality,
  AggregationType,
  DataPointType,
  type Histogram,
  type PushMetricExporter,
  type ResourceMetrics,
  type ViewOptions,
} from '@opentelemetry/sdk-metrics';

const methods = new Set([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS',
  'HEAD',
  'CONNECT',
  'TRACE',
  '_OTHER',
]);
const scopes = new Set([
  'git-mcp-server',
  '@opentelemetry/instrumentation-http',
  '@opentelemetry/instrumentation-undici',
]);
const names = new Set([
  'http.server.request.duration',
  'http.client.request.duration',
]);

/** Keep finite method/status dimensions before aggregation, not only on export. */
export function safeMetricAttributes(input: Attributes): Attributes {
  const output: Attributes = {};
  const method = input['http.request.method'];
  if (typeof method === 'string' && methods.has(method))
    output['http.request.method'] = method;
  const status = input['http.response.status_code'];
  if (
    typeof status === 'number' &&
    Number.isInteger(status) &&
    status >= 100 &&
    status <= 599
  )
    output['http.response.status_code'] = status;
  if (input['otel.metric.overflow'] === true)
    output['otel.metric.overflow'] = true;
  return output;
}

/** Strip high-cardinality/private dimensions before the SDK creates time series. */
export function safeMetricViews(): ViewOptions[] {
  return [
    {
      instrumentName: '*',
      aggregationCardinalityLimit: 2000,
      attributesProcessors: [{ process: safeMetricAttributes }],
    },
  ];
}

function finite(value: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0)
    throw new Error('Invalid operational metric');
  return value;
}

function count(value: number): number {
  if (!Number.isSafeInteger(finite(value)))
    throw new Error('Invalid operational metric count');
  return value;
}

function time(value: [number, number]): [number, number] {
  const seconds = count(value[0]);
  const nanos = count(value[1]);
  if (nanos >= 1_000_000_000)
    throw new Error('Invalid operational metric time');
  return [seconds, nanos];
}

function histogram(value: Histogram): Histogram {
  const source = value.buckets;
  if (
    source.boundaries.length > 64 ||
    source.counts.length !== source.boundaries.length + 1
  )
    throw new Error('Invalid operational metric buckets');
  const boundaries = source.boundaries.map(finite);
  for (let i = 1; i < boundaries.length; i++)
    if (boundaries[i]! <= boundaries[i - 1]!)
      throw new Error('Invalid operational metric boundaries');
  const counts = source.counts.map(count);
  const total = count(value.count);
  if (counts.reduce((sum, current) => sum + current, 0) !== total)
    throw new Error('Invalid operational metric count');
  const output: Histogram = { buckets: { boundaries, counts }, count: total };
  if (value.sum !== undefined) output.sum = finite(value.sum);
  if (value.min !== undefined) output.min = finite(value.min);
  if (value.max !== undefined) output.max = finite(value.max);
  if (
    output.min !== undefined &&
    output.max !== undefined &&
    output.min > output.max
  )
    throw new Error('Invalid operational metric range');
  return output;
}

/**
 * Rebuild only known HTTP duration histograms. No original object is spread:
 * scope/resource/descriptor/point extras and exemplars cannot carry payloads.
 * Unsupported streams are excluded; malformed known streams fail the batch.
 */
export function safeResourceMetrics(input: ResourceMetrics): ResourceMetrics {
  const output: ResourceMetrics = {
    resource: resourceFromAttributes({ 'service.name': 'git-mcp-server' }),
    scopeMetrics: [],
  };
  if (input.scopeMetrics.length > 256)
    throw new Error('Metric scope limit exceeded');
  const seenScopes = new Set<string>();
  for (const scope of input.scopeMetrics) {
    if (!scopes.has(scope.scope.name)) continue;
    if (seenScopes.has(scope.scope.name))
      throw new Error('Duplicate operational metric scope');
    seenScopes.add(scope.scope.name);
    if (scope.metrics.length > 256)
      throw new Error('Metric stream limit exceeded');
    const metrics: ResourceMetrics['scopeMetrics'][number]['metrics'] = [];
    const seenNames = new Set<string>();
    for (const metric of scope.metrics) {
      const name = metric.descriptor.name;
      if (!names.has(name)) continue;
      if (seenNames.has(name))
        throw new Error('Duplicate operational metric stream');
      seenNames.add(name);
      if (
        metric.dataPointType !== DataPointType.HISTOGRAM ||
        (metric.aggregationTemporality !== AggregationTemporality.CUMULATIVE &&
          metric.aggregationTemporality !== AggregationTemporality.DELTA) ||
        metric.dataPoints.length > 2000
      )
        throw new Error('Unsupported operational metric shape');
      const seenPoints = new Set<string>();
      const dataPoints = metric.dataPoints.map((point) => {
        const attributes = safeMetricAttributes(point.attributes);
        // Only bounded operational scalars, never the original payload/attributes.
        const key = JSON.stringify([
          attributes['http.request.method'],
          attributes['http.response.status_code'],
          attributes['otel.metric.overflow'],
        ]);
        if (seenPoints.has(key))
          throw new Error('Duplicate operational metric dimensions');
        seenPoints.add(key);
        return {
          startTime: time(point.startTime),
          endTime: time(point.endTime),
          attributes,
          value: histogram(point.value),
        };
      });
      metrics.push({
        descriptor: {
          name,
          description: 'HTTP request duration',
          unit: 's',
          valueType: ValueType.DOUBLE,
        },
        aggregationTemporality: metric.aggregationTemporality,
        dataPointType: DataPointType.HISTOGRAM,
        dataPoints,
      });
    }
    if (metrics.length)
      output.scopeMetrics.push({ scope: { name: scope.scope.name }, metrics });
  }
  return output;
}

/** Enforce metrics privacy and sanitize endpoint/exporter failure diagnostics. */
export class SafeMetricExporter implements PushMetricExporter {
  readonly selectAggregationTemporality: NonNullable<
    PushMetricExporter['selectAggregationTemporality']
  >;
  readonly selectAggregation: NonNullable<
    PushMetricExporter['selectAggregation']
  >;

  constructor(private readonly exporter: PushMetricExporter) {
    this.selectAggregationTemporality = (type) =>
      exporter.selectAggregationTemporality?.(type) ??
      AggregationTemporality.CUMULATIVE;
    this.selectAggregation = (type) =>
      exporter.selectAggregation?.(type) ?? { type: AggregationType.DEFAULT };
  }

  export(
    metrics: ResourceMetrics,
    callback: Parameters<PushMetricExporter['export']>[1],
  ): void {
    try {
      this.exporter.export(safeResourceMetrics(metrics), (result) =>
        callback({
          code: result.code,
          ...(result.error
            ? { error: new Error('Telemetry metric export failed') }
            : {}),
        }),
      );
    } catch {
      callback({ code: 1, error: new Error('Telemetry metric export failed') });
    }
  }

  async forceFlush(): Promise<void> {
    try {
      await this.exporter.forceFlush();
    } catch {
      throw new Error('Telemetry metric flush failed');
    }
  }

  async shutdown(): Promise<void> {
    try {
      await this.exporter.shutdown();
    } catch {
      throw new Error('Telemetry metric shutdown failed');
    }
  }
}
