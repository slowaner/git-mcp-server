/**
 * @fileoverview Real SDK aggregation and hostile metadata metric sink regressions.
 * @module tests/security/safe-metric-exporter
 */
import { describe, expect, it } from 'bun:test';
import { ValueType } from '@opentelemetry/api';
import { resourceFromAttributes } from '@opentelemetry/resources';
import {
  AggregationTemporality,
  DataPointType,
  MeterProvider,
  PeriodicExportingMetricReader,
  type PushMetricExporter,
  type ResourceMetrics,
} from '@opentelemetry/sdk-metrics';
import {
  SafeMetricExporter,
  safeMetricAttributes,
  safeMetricViews,
  safeResourceMetrics,
} from '@/utils/telemetry/safe-metric-exporter.js';

const sentinel = 'synthetic-private-metric-session';

function fixture(): ResourceMetrics {
  return {
    resource: resourceFromAttributes({
      'service.name': sentinel,
      claims: sentinel,
    }),
    scopeMetrics: [
      {
        scope: {
          name: '@opentelemetry/instrumentation-http',
          version: sentinel,
        },
        metrics: [
          {
            descriptor: {
              name: 'http.server.request.duration',
              unit: sentinel,
              description: sentinel,
              valueType: ValueType.DOUBLE,
            },
            dataPointType: DataPointType.HISTOGRAM,
            aggregationTemporality: AggregationTemporality.CUMULATIVE,
            dataPoints: [
              {
                startTime: [1, 0],
                endTime: [2, 0],
                attributes: {
                  'http.request.method': 'POST',
                  'http.response.status_code': 200,
                  'server.address': sentinel,
                  sessionId: sentinel,
                  'error.type': sentinel,
                },
                value: {
                  count: 2,
                  sum: 0.3,
                  min: 0.1,
                  max: 0.2,
                  buckets: { boundaries: [0.5], counts: [2, 0] },
                },
              },
            ],
          },
        ],
      },
    ],
  };
}

function exporter(
  overrides: Partial<PushMetricExporter> = {},
): PushMetricExporter {
  return {
    export: (_metrics, callback) => callback({ code: 0 }),
    forceFlush: async () => {},
    shutdown: async () => {},
    ...overrides,
  };
}

describe('safe metrics boundary', () => {
  it('rebuilds all metadata and preserves operational histogram values without mutating input', () => {
    const input = fixture();
    Object.assign(input.scopeMetrics[0]!.scope, {
      attributes: { private: sentinel },
    });
    const original = JSON.stringify(input);
    const output = safeResourceMetrics(input);
    expect(JSON.stringify(output)).not.toContain(sentinel);
    expect(JSON.stringify(input)).toBe(original);
    const metric = output.scopeMetrics[0]!.metrics[0]!;
    expect(metric.descriptor).toEqual({
      name: 'http.server.request.duration',
      description: 'HTTP request duration',
      unit: 's',
      valueType: ValueType.DOUBLE,
    });
    expect(metric.dataPoints[0]!.attributes).toEqual({
      'http.request.method': 'POST',
      'http.response.status_code': 200,
    });
    expect(metric.dataPoints[0]!.value).toEqual(
      input.scopeMetrics[0]!.metrics[0]!.dataPoints[0]!.value,
    );
    expect(output.resource.attributes).toEqual({
      'service.name': 'git-mcp-server',
    });
    expect(output.scopeMetrics[0]!.scope).toEqual({
      name: '@opentelemetry/instrumentation-http',
    });
  });

  it('excludes unknown stream/scope names and nonfinite dimensions', () => {
    expect(
      safeMetricAttributes({
        'http.request.method': sentinel,
        'http.response.status_code': sentinel,
      }),
    ).toEqual({});
    for (const code of [99, 600, NaN, Infinity, 200.5])
      expect(
        safeMetricAttributes({ 'http.response.status_code': code }),
      ).toEqual({});
    const input = fixture();
    input.scopeMetrics.push({
      scope: { name: sentinel },
      metrics: input.scopeMetrics[0]!.metrics,
    });
    input.scopeMetrics[0]!.metrics.push({
      ...input.scopeMetrics[0]!.metrics[0]!,
      descriptor: {
        name: sentinel,
        unit: sentinel,
        description: sentinel,
        valueType: ValueType.DOUBLE,
      },
    });
    const output = safeResourceMetrics(input);
    expect(output.scopeMetrics).toHaveLength(1);
    expect(output.scopeMetrics[0]!.metrics).toHaveLength(1);
    expect(JSON.stringify(output)).not.toContain(sentinel);
  });

  it('rejects malformed or duplicate known streams instead of exporting partial or ambiguous values', () => {
    const duplicate = fixture();
    const duplicateMetric = duplicate.scopeMetrics[0]!.metrics[0]!;
    if (duplicateMetric.dataPointType !== DataPointType.HISTOGRAM)
      throw new Error('Histogram fixture required');
    duplicateMetric.dataPoints.push(duplicateMetric.dataPoints[0]!);
    expect(() => safeResourceMetrics(duplicate)).toThrow(/Duplicate/);
    const invalid = fixture();
    const point = invalid.scopeMetrics[0]!.metrics[0]!.dataPoints[0]!;
    // Keep the malformed synthetic SDK record isolated from real aggregation.
    Object.assign(point, {
      value: { count: 2, buckets: { boundaries: [1], counts: [1, 0] } },
    });
    expect(() => safeResourceMetrics(invalid)).toThrow(/count/);
    Object.assign(point, {
      value: {
        count: 2,
        sum: Infinity,
        buckets: { boundaries: [1], counts: [2, 0] },
      },
    });
    expect(() => safeResourceMetrics(invalid)).toThrow(/Invalid/);
    Object.assign(point, {
      value: {
        count: 2,
        buckets: { boundaries: Array(65).fill(1), counts: Array(66).fill(0) },
      },
    });
    expect(() => safeResourceMetrics(invalid)).toThrow(/buckets/);
  });

  it('filters private dimensions before actual SDK aggregation, preserving counts across 20000 unique hosts', async () => {
    const exports: ResourceMetrics[] = [];
    const reader = new PeriodicExportingMetricReader({
      exporter: new SafeMetricExporter(
        exporter({
          export: (data, callback) => {
            exports.push(data);
            callback({ code: 0 });
          },
        }),
      ),
      exportIntervalMillis: 60_000,
    });
    const provider = new MeterProvider({
      readers: [reader],
      views: safeMetricViews(),
      resource: resourceFromAttributes({ private: sentinel }),
    });
    try {
      const histogram = provider
        .getMeter('git-mcp-server', sentinel)
        .createHistogram('http.client.request.duration', { unit: 's' });
      for (let i = 0; i < 20_000; i++)
        histogram.record(0.1, {
          'http.request.method': 'POST',
          'http.response.status_code': 200,
          'server.address': `${sentinel}-${i}`,
          'http.route': sentinel,
          'error.type': sentinel,
        });
      await provider.forceFlush();
      expect(exports).toHaveLength(1);
      const metric = exports[0]!.scopeMetrics[0]!.metrics[0]!;
      expect(metric.dataPoints).toHaveLength(1);
      expect(metric.dataPoints[0]!.value).toMatchObject({ count: 20_000 });
      expect(JSON.stringify(exports)).not.toContain(sentinel);
    } finally {
      await provider.shutdown();
    }
  });

  it('retains the SDK overflow marker and total counts when finite method/status combinations exceed the series cap', async () => {
    const exports: ResourceMetrics[] = [];
    const reader = new PeriodicExportingMetricReader({
      exporter: new SafeMetricExporter(
        exporter({
          export: (data, callback) => {
            exports.push(data);
            callback({ code: 0 });
          },
        }),
      ),
      exportIntervalMillis: 60_000,
    });
    const provider = new MeterProvider({
      readers: [reader],
      views: safeMetricViews(),
    });
    try {
      const histogram = provider
        .getMeter('git-mcp-server')
        .createHistogram('http.server.request.duration', { unit: 's' });
      const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
      for (let i = 0; i < 2100; i++)
        histogram.record(0.1, {
          'http.request.method': methods[Math.floor(i / 500)]!,
          'http.response.status_code': 100 + (i % 500),
          sessionId: sentinel,
        });
      await provider.forceFlush();
      expect(exports).toHaveLength(1);
      const metric = exports[0]!.scopeMetrics[0]!.metrics[0]!;
      if (metric.dataPointType !== DataPointType.HISTOGRAM)
        throw new Error('Histogram required');
      expect(metric.dataPoints.length).toBeLessThanOrEqual(2000);
      expect(
        metric.dataPoints.some(
          (point) => point.attributes['otel.metric.overflow'] === true,
        ),
      ).toBe(true);
      expect(
        metric.dataPoints.reduce((sum, point) => sum + point.value.count, 0),
      ).toBe(2100);
      expect(JSON.stringify(exports)).not.toContain(sentinel);
    } finally {
      await provider.shutdown();
    }
  });

  it('never forwards original endpoint errors through callbacks, flush or shutdown', async () => {
    const privateError = new Error(`https://user:${sentinel}@example.invalid`);
    const safe = new SafeMetricExporter(
      exporter({
        export: (_data, callback) => callback({ code: 1, error: privateError }),
        forceFlush: async () => {
          throw privateError;
        },
        shutdown: async () => {
          throw privateError;
        },
      }),
    );
    let error: Error | undefined;
    safe.export(fixture(), (result) => {
      error = result.error;
    });
    expect(error?.message).toBe('Telemetry metric export failed');
    await expect(safe.forceFlush()).rejects.toThrow(
      'Telemetry metric flush failed',
    );
    await expect(safe.shutdown()).rejects.toThrow(
      'Telemetry metric shutdown failed',
    );
    const throwing = new SafeMetricExporter(
      exporter({
        export: () => {
          throw privateError;
        },
      }),
    );
    throwing.export(fixture(), (result) => {
      error = result.error;
    });
    expect(error?.message).toBe('Telemetry metric export failed');
  });
});
