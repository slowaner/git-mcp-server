/**
 * @fileoverview Defines the interface for all authentication strategies.
 * The core authentication middleware uses this interface to verify tokens.
 * @module src/mcp-server/transports/auth/strategies/AuthStrategy
 */
import type { AuthInfo } from '@/mcp-server/transports/auth/lib/authTypes.js';

export interface AuthStrategy {
  /**
   * Verifies an authentication token.
   * @param token The raw token string extracted from the request.
   * @returns A promise that resolves with the AuthInfo on successful verification.
   * @throws {McpError} if the token is invalid, expired, or fails verification for any reason.
   */
  verify(token: string): Promise<AuthInfo>;
}
