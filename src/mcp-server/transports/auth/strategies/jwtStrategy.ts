/**
 * @fileoverview Strict JWT authentication without environment-dependent downgrade.
 * @module src/mcp-server/transports/auth/strategies/JwtStrategy
 */
import { injectable, inject } from 'tsyringe';
import type { config as ConfigType } from '@/config/index.js';
import { AppConfig, Logger } from '@/container/tokens.js';
import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import {
  type logger as LoggerType,
  requestContextService,
} from '@/utils/index.js';
import type { AuthInfo } from '../lib/authTypes.js';
import { JwtTokenPolicy } from '../lib/jwtTokenPolicy.js';
import { validateAuthenticationConfiguration } from '../lib/authConfiguration.js';
import type { AuthStrategy } from './authStrategy.js';

/** Verify every JWT using the operator's fixed issuer, audience, key and lifetime. */
@injectable()
export class JwtStrategy implements AuthStrategy {
  private readonly policy: JwtTokenPolicy;

  constructor(
    @inject(AppConfig) appConfig: typeof ConfigType,
    @inject(Logger) private readonly logger: typeof LoggerType,
  ) {
    validateAuthenticationConfiguration(appConfig);
    this.policy = new JwtTokenPolicy({
      secret: appConfig.mcpAuthSecretKey ?? '',
      issuer: appConfig.mcpAuthIssuer ?? '',
      audience: appConfig.mcpAuthAudience ?? '',
      maxLifetimeSeconds: appConfig.mcpAuthMaxTokenLifetimeSeconds,
      clockToleranceSeconds: appConfig.mcpAuthClockToleranceSeconds,
    });
  }

  async verify(token: string): Promise<AuthInfo> {
    const context = requestContextService.createRequestContext({
      operation: 'JwtStrategy.verify',
    });
    try {
      const { principal, scopes, expiresAt } = await this.policy.verify(token);
      this.logger.debug('JWT verification successful.', context);
      return {
        token,
        clientId: principal.clientId,
        subject: principal.subject,
        tenantId: principal.tenantId,
        principal,
        scopes: [...scopes],
        expiresAt,
      };
    } catch {
      this.logger.warning('JWT verification failed.', context);
      throw new McpError(
        JsonRpcErrorCode.Unauthorized,
        'Token verification failed.',
      );
    }
  }
}
