/**
 * @fileoverview Environment-independent startup validation for authentication.
 * @module src/mcp-server/transports/auth/lib/authConfiguration
 */
import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import { JwtTokenPolicy } from './jwtTokenPolicy.js';
import { PrincipalRepositoryGrants } from './principalRepositoryGrants.js';

/** Minimal configuration contract, without importing the runtime config singleton. */
export interface AuthenticationConfiguration {
  mcpAuthMode: 'none' | 'jwt' | 'oauth';
  mcpTransportType: 'stdio' | 'http';
  mcpAuthSecretKey?: string | undefined;
  mcpAuthIssuer?: string | undefined;
  mcpAuthAudience?: string | undefined;
  mcpAuthMaxTokenLifetimeSeconds: number;
  mcpAuthClockToleranceSeconds: number;
  mcpRepositoryGrants?: string | undefined;
  oauthIssuerUrl?: string | undefined;
  oauthJwksUri?: string | undefined;
  oauthAudience?: string | undefined;
  devMcpClientId?: string | undefined;
  devMcpScopes?: string[] | undefined;
}

/** No HTTP/credential-bearing URLs are accepted for OAuth trust anchors. */
export function requireHttpsTrustAnchor(value: string | undefined): URL {
  try {
    const url = new URL(value ?? '');
    if (
      url.protocol === 'https:' &&
      !url.username &&
      !url.password &&
      !url.hash
    )
      return url;
  } catch {
    /* Report configuration without echoing a potentially sensitive URL. */
  }
  throw new McpError(
    JsonRpcErrorCode.ConfigurationError,
    'OAuth trust anchors must be HTTPS URLs without credentials or fragments.',
  );
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
  if (config.mcpAuthMode === 'jwt') {
    new JwtTokenPolicy({
      secret: config.mcpAuthSecretKey ?? '',
      issuer: config.mcpAuthIssuer ?? '',
      audience: config.mcpAuthAudience ?? '',
      maxLifetimeSeconds: config.mcpAuthMaxTokenLifetimeSeconds,
      clockToleranceSeconds: config.mcpAuthClockToleranceSeconds,
    });
  } else {
    requireHttpsTrustAnchor(config.oauthIssuerUrl);
    if (config.oauthJwksUri) requireHttpsTrustAnchor(config.oauthJwksUri);
    if (
      !config.oauthAudience?.trim() ||
      config.oauthAudience !== config.oauthAudience.trim()
    )
      throw new McpError(
        JsonRpcErrorCode.ConfigurationError,
        'OAUTH_AUDIENCE is required.',
      );
  }
  if (config.mcpTransportType === 'http')
    parseRepositoryGrants(config.mcpRepositoryGrants);
}
