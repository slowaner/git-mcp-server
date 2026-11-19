/**
 * @fileoverview OAuth JWT verification with explicit algorithms, lifetime and stable identity.
 * @module src/mcp-server/transports/auth/strategies/OauthStrategy
 */
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { inject, injectable } from 'tsyringe';
import type { config as ConfigType } from '@/config/index.js';
import { AppConfig, Logger } from '@/container/tokens.js';
import type { AuthInfo } from '../lib/authTypes.js';
import {
  requireHttpsTrustAnchor,
  validateAuthenticationConfiguration,
} from '../lib/authConfiguration.js';
import { identityFromVerifiedPayload } from '../lib/jwtTokenPolicy.js';
import type { AuthStrategy } from './authStrategy.js';
import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import {
  type logger as LoggerType,
  requestContextService,
} from '@/utils/index.js';

/** Verify remote-key access tokens without accepting symmetric or unbounded tokens. */
@injectable()
export class OauthStrategy implements AuthStrategy {
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;
  constructor(
    @inject(AppConfig) private readonly config: typeof ConfigType,
    @inject(Logger) private readonly logger: typeof LoggerType,
  ) {
    validateAuthenticationConfiguration(config);
    const url = requireHttpsTrustAnchor(
      config.oauthJwksUri ||
        `${config.oauthIssuerUrl?.replace(/\/$/, '')}/.well-known/jwks.json`,
    );
    this.jwks = createRemoteJWKSet(url, {
      cooldownDuration: config.oauthJwksCooldownMs,
      timeoutDuration: config.oauthJwksTimeoutMs,
    });
  }

  async verify(token: string): Promise<AuthInfo> {
    const context = requestContextService.createRequestContext({
      operation: 'OauthStrategy.verify',
    });
    try {
      if (!token || token.length > 16384)
        throw new Error('Invalid token size.');
      const { payload } = await jwtVerify(token, this.jwks, {
        issuer: this.config.oauthIssuerUrl!,
        audience: this.config.oauthAudience!,
        algorithms: ['RS256', 'ES256', 'PS256'],
        requiredClaims: ['exp', 'iat', 'sub', 'tid'],
        maxTokenAge: this.config.mcpAuthMaxTokenLifetimeSeconds,
        clockTolerance: this.config.mcpAuthClockToleranceSeconds,
      });
      if (this.config.mcpServerResourceIdentifier) {
        const resource = payload.resource ?? payload.aud;
        if (
          resource !== this.config.mcpServerResourceIdentifier &&
          !(
            Array.isArray(resource) &&
            resource.includes(this.config.mcpServerResourceIdentifier)
          )
        )
          throw new McpError(
            JsonRpcErrorCode.Forbidden,
            'Token resource indicator mismatch.',
          );
      }
      const { principal, scopes, expiresAt } = identityFromVerifiedPayload(
        payload,
        this.config.mcpAuthMaxTokenLifetimeSeconds,
      );
      this.logger.debug('OAuth verification successful.', context);
      return {
        token,
        clientId: principal.clientId,
        tenantId: principal.tenantId,
        subject: principal.subject,
        principal,
        scopes: [...scopes],
        expiresAt,
      };
    } catch (error) {
      this.logger.warning('OAuth verification failed.', context);
      if (
        error instanceof McpError &&
        error.code === JsonRpcErrorCode.Forbidden
      )
        throw error;
      throw new McpError(
        JsonRpcErrorCode.Unauthorized,
        'OAuth token verification failed.',
      );
    }
  }
}
