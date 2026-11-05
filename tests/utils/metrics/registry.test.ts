/**
 * @fileoverview Tests for the metrics registry helper, covering enabled and disabled paths.
 * @module tests/utils/metrics/registry.test
 */
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest';
import { config } from '@/config/index.js';
import { metrics } from '@opentelemetry/api';

const meterMock = {
  createCounter: vi.fn(),
  createHistogram: vi.fn(),
};
const getMeterMock = vi
  .spyOn(metrics, 'getMeter')
  .mockReturnValue(meterMock as unknown as ReturnType<typeof metrics.getMeter>);
const configMock = config;
let savedEnabled: boolean;

let metricsRegistry: typeof import('../../../src/utils/metrics/registry.js').metricsRegistry;
afterAll(() => {
  getMeterMock.mockRestore();
});

beforeAll(async () => {
  ({ metricsRegistry } =
    await import('../../../src/utils/metrics/registry.js'));
});

describe('metricsRegistry', () => {
  beforeEach(() => {
    savedEnabled = configMock.openTelemetry.enabled;
    configMock.openTelemetry.enabled = false;
    getMeterMock.mockClear();
    meterMock.createCounter.mockReset();
    meterMock.createHistogram.mockReset();
  });
  afterEach(() => {
    configMock.openTelemetry.enabled = savedEnabled;
  });

  it('returns no-op meters when OpenTelemetry is disabled', () => {
    expect(metricsRegistry.enabled()).toBe(false);

    expect(() => metricsRegistry.add('disabled_metric', 1)).not.toThrow();
    expect(() => metricsRegistry.record('disabled_histogram', 5)).not.toThrow();
    expect(getMeterMock).not.toHaveBeenCalled();
  });

  it('creates and caches counters and histograms when enabled', () => {
    configMock.openTelemetry.enabled = true;

    const counterWithOptions = {
      add: vi.fn(),
      bind: vi.fn(() => ({ add: vi.fn() })),
      unbind: vi.fn(),
    };
    const counterWithoutOptions = {
      add: vi.fn(),
      bind: vi.fn(() => ({ add: vi.fn() })),
      unbind: vi.fn(),
    };
    const histogramWithOptions = {
      record: vi.fn(),
      bind: vi.fn(() => ({ record: vi.fn() })),
      unbind: vi.fn(),
    };
    const histogramWithoutOptions = {
      record: vi.fn(),
      bind: vi.fn(() => ({ record: vi.fn() })),
      unbind: vi.fn(),
    };

    meterMock.createCounter.mockImplementation((name) => {
      if (name === 'requests_total') return counterWithOptions;
      if (name === 'requests_total_no_opts') return counterWithoutOptions;
      return counterWithOptions;
    });
    meterMock.createHistogram.mockImplementation((name) => {
      if (name === 'latency_ms') return histogramWithOptions;
      if (name === 'latency_ms_no_opts') return histogramWithoutOptions;
      return histogramWithOptions;
    });

    expect(metricsRegistry.enabled()).toBe(true);

    metricsRegistry.add(
      'requests_total',
      2,
      { status: 'ok' },
      'Number of successful requests',
      'requests',
    );

    expect(getMeterMock).toHaveBeenCalledWith(
      configMock.openTelemetry.serviceName,
      configMock.openTelemetry.serviceVersion,
    );
    expect(meterMock.createCounter).toHaveBeenCalledWith('requests_total', {
      description: 'Number of successful requests',
      unit: 'requests',
    });
    expect(counterWithOptions.add).toHaveBeenCalledWith(2, { status: 'ok' });

    // Call again with the same signature to confirm the cached counter is reused.
    counterWithOptions.add.mockClear();
    meterMock.createCounter.mockClear();

    metricsRegistry.add(
      'requests_total',
      3,
      undefined,
      'Number of successful requests',
      'requests',
    );

    expect(meterMock.createCounter).not.toHaveBeenCalled();
    expect(counterWithOptions.add).toHaveBeenCalledWith(3, undefined);

    // Exercise the branch where no metric options are passed.
    metricsRegistry.add('requests_total_no_opts', 1);
    expect(meterMock.createCounter).toHaveBeenCalledWith(
      'requests_total_no_opts',
    );
    expect(counterWithoutOptions.add).toHaveBeenCalledWith(1, undefined);

    metricsRegistry.record(
      'latency_ms',
      125,
      { route: '/cats' },
      'Request latency in milliseconds',
      'ms',
    );
    expect(meterMock.createHistogram).toHaveBeenCalledWith('latency_ms', {
      description: 'Request latency in milliseconds',
      unit: 'ms',
    });
    expect(histogramWithOptions.record).toHaveBeenCalledWith(125, {
      route: '/cats',
    });

    histogramWithOptions.record.mockClear();
    meterMock.createHistogram.mockClear();

    metricsRegistry.record(
      'latency_ms',
      200,
      undefined,
      'Request latency in milliseconds',
      'ms',
    );
    expect(meterMock.createHistogram).not.toHaveBeenCalled();
    expect(histogramWithOptions.record).toHaveBeenCalledWith(200, undefined);

    metricsRegistry.record('latency_ms_no_opts', 50);
    expect(meterMock.createHistogram).toHaveBeenCalledWith(
      'latency_ms_no_opts',
    );
    expect(histogramWithoutOptions.record).toHaveBeenCalledWith(50, undefined);
  });
});
