/**
 * @fileoverview Environment-independent startup validation for authentication.
 * @module src/mcp-server/transports/auth/lib/authConfiguration
 */
import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import { JwtTokenPolicy } from './jwtTokenPolicy.js';
import { PrincipalRepositoryGrants } from './principalRepositoryGrants.js';

/** Minimal configuration contract, without importing the runtime config singleton. */
export interface AuthenticationConfiguration {
  mcpAuthMode: 'none' | 'jwt';
  mcpTransportType: 'stdio' | 'http';
  mcpAuthSecretKey?: string | undefined;
  mcpAuthIssuer?: string | undefined;
  mcpAuthAudience?: string | undefined;
  mcpAuthMaxTokenLifetimeSeconds: number;
  mcpAuthClockToleranceSeconds: number;
  mcpRepositoryGrants?: string | undefined;
  devMcpClientId?: string | undefined;
  devMcpScopes?: string[] | undefined;
}

/** Parse only operator configuration; missing/invalid grants have no global-root fallback. */
export function parseRepositoryGrants(
  value: string | undefined,
): PrincipalRepositoryGrants {
  try {
    return new PrincipalRepositoryGrants(JSON.parse(value ?? ''));
  } catch {
    throw new McpError(
      JsonRpcErrorCode.ConfigurationError,
      'MCP_REPOSITORY_GRANTS must contain valid explicit principal grants.',
    );
  }
}

/** Validate enabled authentication in every environment before server composition. */
export function validateAuthenticationConfiguration(
  config: AuthenticationConfiguration,
): void {
  if (config.mcpAuthMode === 'none') return;
  if (config.devMcpClientId !== undefined || config.devMcpScopes !== undefined)
    throw new McpError(
      JsonRpcErrorCode.ConfigurationError,
      'Development authentication bypass settings are unsupported.',
    );
  if (
    !Number.isSafeInteger(config.mcpAuthMaxTokenLifetimeSeconds) ||
    config.mcpAuthMaxTokenLifetimeSeconds < 1 ||
    config.mcpAuthMaxTokenLifetimeSeconds > 86400 ||
    !Number.isSafeInteger(config.mcpAuthClockToleranceSeconds) ||
    config.mcpAuthClockToleranceSeconds < 0 ||
    config.mcpAuthClockToleranceSeconds > 60
  )
    throw new McpError(
      JsonRpcErrorCode.ConfigurationError,
      'Authentication lifetime and clock tolerance must be bounded.',
    );
  new JwtTokenPolicy({
    secret: config.mcpAuthSecretKey ?? '',
    issuer: config.mcpAuthIssuer ?? '',
    audience: config.mcpAuthAudience ?? '',
    maxLifetimeSeconds: config.mcpAuthMaxTokenLifetimeSeconds,
    clockToleranceSeconds: config.mcpAuthClockToleranceSeconds,
  });
  if (config.mcpTransportType === 'http')
    parseRepositoryGrants(config.mcpRepositoryGrants);
}
