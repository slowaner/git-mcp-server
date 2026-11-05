/**
 * @fileoverview Defines a unified Hono middleware for authentication.
 * This middleware is strategy-agnostic. It extracts a Bearer token,
 * delegates verification to the provided authentication strategy, and
 * populates the async-local storage context with the resulting auth info.
 * @module src/mcp-server/transports/auth/authMiddleware
 */
import type { HttpBindings } from '@hono/node-server';
import type { Context, Next } from 'hono';

import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import { logger, requestContextService } from '@/utils/index.js';
import { withRepositoryRoots } from '@/services/git/core/configured-repository-policy.js';
import type { PrincipalRepositoryGrants } from './lib/principalRepositoryGrants.js';
import { authContext } from '@/mcp-server/transports/auth/lib/authContext.js';
import type { AuthStrategy } from '@/mcp-server/transports/auth/strategies/authStrategy.js';

/**
 * Creates a Hono middleware function that enforces authentication using a given strategy.
 *
 * @param strategy - An instance of a class that implements the `AuthStrategy` interface.
 * @returns A Hono middleware function.
 */
export function createAuthMiddleware(
  strategy: AuthStrategy,
  grants: PrincipalRepositoryGrants,
) {
  return async function authMiddleware(
    c: Context<{ Bindings: HttpBindings }>,
    next: Next,
  ) {
    const context = requestContextService.createRequestContext({
      operation: 'authMiddleware',
      additionalContext: {
        method: c.req.method,
        path: c.req.path,
      },
    });

    logger.debug('Initiating authentication check.', context);

    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      logger.warning('Authorization header missing or invalid.', context);
      throw new McpError(
        JsonRpcErrorCode.Unauthorized,
        'Missing or invalid Authorization header. Bearer scheme required.',
        context,
      );
    }

    const token = authHeader.substring(7);
    if (!token) {
      logger.warning(
        'Bearer token is missing from Authorization header.',
        context,
      );
      throw new McpError(
        JsonRpcErrorCode.Unauthorized,
        'Authentication token is missing.',
        context,
      );
    }

    logger.debug(
      'Extracted Bearer token, proceeding to verification.',
      context,
    );

    const authInfo = await strategy.verify(token);
    const principal = authInfo.principal;
    if (!principal)
      throw new McpError(
        JsonRpcErrorCode.Unauthorized,
        'Verified principal is required.',
      );
    const repositoryRoots = grants.rootsFor(principal);
    logger.info('Authentication successful.', context);
    await authContext.run(
      { authInfo, principal, repositoryRoots, transport: 'http' },
      () => withRepositoryRoots(repositoryRoots, next),
    );
  };
}
