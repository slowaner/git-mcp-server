/**
 * @fileoverview Test context factory for creating RequestContext and SdkContext instances.
 * @module tests/mcp-server/tools/definitions/helpers/testContext
 */
import { requestContextService } from '@/utils/index.js';
import { config } from '@/config/index.js';
import { afterEach, beforeEach } from 'vitest';
import type { RequestContext } from '@/utils/index.js';
import type { SdkContext } from '@/mcp-server/tools/utils/toolDefinition.js';

/**
 * Creates a test RequestContext with optional overrides.
 */
export function createTestContext(
  overrides: Partial<RequestContext> = {},
): RequestContext {
  return requestContextService.createRequestContext({
    operation: overrides.operation || 'test-operation',
    additionalContext: overrides,
  });
}

/**
 * Explicitly opt a serial unit-test file into trusted mock-provider execution.
 * Call at file scope; importing this helper never changes the profile. Register
 * hooks per caller so module caching cannot hide fixture lifecycle ownership.
 */
export function installTrustedGitFixture(): void {
  let savedProfile = config.git.executionProfile;
  beforeEach(() => {
    savedProfile = config.git.executionProfile;
    config.git.executionProfile = 'trusted';
  });
  afterEach(() => {
    config.git.executionProfile = savedProfile;
  });
}

/**
 * Creates a test SdkContext for MCP protocol operations.
 */
export function createTestSdkContext(
  overrides: Partial<SdkContext> = {},
): SdkContext {
  return {
    sessionId: 'test-session-id',
    ...overrides,
  } as SdkContext;
}

/**
 * Creates a RequestContext with a specific tenantId for multi-tenancy tests.
 */
export function createTestContextWithTenant(
  tenantId: string,
  overrides: Partial<RequestContext> = {},
): RequestContext {
  const context = createTestContext(overrides);
  return {
    ...context,
    tenantId,
  };
}
