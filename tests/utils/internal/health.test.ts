/**
 * @fileoverview Unit tests for the health snapshot utility.
 * @module tests/utils/internal/health.test
 */
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from 'vitest';

import { config } from '../../../src/config/index.js';
import { getHealthSnapshot } from '../../../src/utils/internal/health.js';
import { logger } from '../../../src/utils/internal/logger.js';
import { runtimeCaps } from '../../../src/utils/internal/runtime.js';

describe('getHealthSnapshot', () => {
  let isInitializedSpy: MockInstance;

  beforeEach(() => {
    isInitializedSpy = vi.spyOn(logger, 'isInitialized').mockReturnValue(true);
  });

  afterEach(() => {
    isInitializedSpy.mockRestore();
  });

  it('reflects config, runtime, telemetry, and logger state in the snapshot', () => {
    const snapshot = getHealthSnapshot();

    expect(snapshot.app).toEqual({
      name: config.mcpServerName,
      version: config.mcpServerVersion,
      environment: config.environment,
    });
    expect(snapshot.runtime).toEqual({
      isNode: runtimeCaps.isNode,
      isWorkerLike: runtimeCaps.isWorkerLike,
      isBrowserLike: runtimeCaps.isBrowserLike,
    });
    expect(snapshot.telemetry).toEqual({
      enabled: Boolean(config.openTelemetry.enabled),
    });
    expect(snapshot.logging.initialized).toBe(true);
  });

  it('reflects an uninitialized logger', () => {
    isInitializedSpy.mockReturnValue(false);

    expect(getHealthSnapshot().logging.initialized).toBe(false);
  });
});
