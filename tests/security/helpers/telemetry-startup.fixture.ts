/**
 * @fileoverview Isolated actual SDK startup, wire export and stdout oracle.
 * @module tests/security/helpers/telemetry-startup.fixture
 */
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Server } from 'node:net';
import { metrics, trace } from '@opentelemetry/api';
import { MeterProvider } from '@opentelemetry/sdk-metrics';

const selection = process.argv[2];
const configured = selection === 'configured';
assert.ok(
  ['default', 'console', 'prometheus', 'configured'].includes(selection ?? ''),
);
const sentinel = 'SYNTHETIC_STARTUP_PRIVATE_SENTINEL';
const received: { path: string; body: string }[] = [];
const server = createServer((request, response) => {
  const chunks: Buffer[] = [];
  request.on('data', (chunk: Buffer) => chunks.push(chunk));
  request.on('end', () => {
    received.push({
      path: request.url ?? '',
      body: Buffer.concat(chunks).toString('utf8'),
    });
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{}');
  });
});
await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
const address = server.address();
assert.ok(address && typeof address !== 'string');
const base = `http://127.0.0.1:${address.port}`;
// These are the explicit scenario inputs of this isolated fixture, not changes
// to the parent process or a workaround for a failed command/profile.
for (const key of Object.keys(process.env))
  if (key.startsWith('OTEL_')) delete process.env[key];
Object.assign(process.env, {
  OTEL_ENABLED: 'true',
  OTEL_SERVICE_VERSION: '1.2.3',
  OTEL_EXPORTER_OTLP_ENDPOINT: base,
  OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: base + '/v1/traces',
  OTEL_EXPORTER_OTLP_METRICS_PROTOCOL: 'http/protobuf',
  OTEL_EXPORTER_PROMETHEUS_HOST: '127.0.0.1',
  OTEL_EXPORTER_PROMETHEUS_PORT: '0',
  OTEL_RESOURCE_ATTRIBUTES: 'private=' + sentinel,
});
if (selection !== 'default')
  process.env.OTEL_METRICS_EXPORTER = configured ? 'console' : selection;
if (configured)
  process.env.OTEL_EXPORTER_OTLP_METRICS_ENDPOINT = base + '/v1/metrics';

const originalListen = Server.prototype.listen;
let extraListeners = 0;
Server.prototype.listen = function (
  this: Server,
  ...args: Parameters<typeof originalListen>
) {
  extraListeners++;
  return Reflect.apply(originalListen, this, args);
} as typeof originalListen;
let shutdown: (() => Promise<void>) | undefined;
let closed = false;
try {
  const instrumentation =
    await import('../../../src/utils/telemetry/instrumentation.js');
  shutdown = instrumentation.shutdownOpenTelemetry;
  assert.notEqual(instrumentation.sdk, null, 'actual SDK startup completed');
  const meter = metrics.getMeter('git-mcp-server', sentinel);
  meter
    .createHistogram('http.server.request.duration', {
      description: sentinel,
      unit: 's',
    })
    .record(0.5, {
      'http.request.method': 'GET',
      'http.response.status_code': 200,
      'session.id': sentinel,
    });
  meter.createCounter(sentinel).add(1);
  metrics
    .getMeter(sentinel)
    .createHistogram('http.server.request.duration')
    .record(1);
  const span = trace
    .getTracer('git-mcp-server', sentinel)
    .startSpan('git_status');
  span.setAttribute('private', sentinel);
  span.end();
  const provider = metrics.getMeterProvider();
  if (configured) {
    assert.ok(provider instanceof MeterProvider);
    await provider.forceFlush();
  } else
    assert.ok(
      !(provider instanceof MeterProvider),
      'no environment/default metric provider registered',
    );
  await shutdown();
  closed = true;
  const metricRequests = received.filter(
    (entry) => entry.path === '/v1/metrics',
  );
  const traceRequests = received.filter((entry) => entry.path === '/v1/traces');
  assert.ok(
    traceRequests.length > 0,
    'tracing-only startup remains functional',
  );
  assert.equal(extraListeners, 0, 'no environment-selected exporter listener');
  assert.ok(received.every((entry) => !entry.body.includes(sentinel)));
  if (configured) {
    assert.ok(
      metricRequests.length > 0,
      'wrapped configured reader actually exports',
    );
    let usefulPoint = false;
    for (const request of metricRequests) {
      const wire = JSON.parse(request.body) as {
        resourceMetrics: {
          resource: {
            attributes: { key: string; value: { stringValue?: string } }[];
          };
          scopeMetrics: {
            scope: { name: string; version?: string };
            schemaUrl?: string;
            metrics: {
              name: string;
              description: string;
              unit: string;
              histogram?: {
                dataPoints: {
                  count: string | number;
                  sum?: number;
                  exemplars?: unknown[];
                  attributes: { key: string }[];
                }[];
              };
            }[];
          }[];
        }[];
      };
      for (const resource of wire.resourceMetrics) {
        assert.deepEqual(resource.resource.attributes, [
          { key: 'service.name', value: { stringValue: 'git-mcp-server' } },
        ]);
        for (const scope of resource.scopeMetrics) {
          assert.ok(
            [
              'git-mcp-server',
              '@opentelemetry/instrumentation-http',
              '@opentelemetry/instrumentation-undici',
            ].includes(scope.scope.name),
          );
          assert.ok(!scope.scope.version);
          assert.ok(!scope.schemaUrl);
          for (const metric of scope.metrics) {
            assert.ok(
              [
                'http.server.request.duration',
                'http.client.request.duration',
              ].includes(metric.name),
            );
            assert.equal(metric.description, 'HTTP request duration');
            assert.equal(metric.unit, 's');
            assert.ok(metric.histogram);
            for (const point of metric.histogram.dataPoints) {
              assert.ok(!point.exemplars?.length);
              assert.ok(
                point.attributes.every((attribute) =>
                  [
                    'http.request.method',
                    'http.response.status_code',
                    'otel.metric.overflow',
                  ].includes(attribute.key),
                ),
              );
              if (
                scope.scope.name === 'git-mcp-server' &&
                Number(point.count) === 1 &&
                point.sum === 0.5
              )
                usefulPoint = true;
            }
          }
        }
      }
    }
    assert.equal(
      usefulPoint,
      true,
      'useful allowed metric survives sanitization',
    );
  } else assert.equal(metricRequests.length, 0);
  process.stdout.write(
    JSON.stringify({
      completed: true,
      configured,
      metricRequests: metricRequests.length,
      traceRequests: traceRequests.length,
      extraListeners,
    }) + '\n',
  );
} finally {
  if (shutdown && !closed) await shutdown();
  Server.prototype.listen = originalListen;
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
}
