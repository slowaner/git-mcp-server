/**
 * @fileoverview Admission identity adapter; only verified authentication context is used.
 * @module mcp-server/transports/http/httpPrincipal
 */
import { config } from '@/config/index.js';
import { currentPrincipal } from '../auth/lib/requestIdentity.js';
import { principalFingerprint } from '../auth/lib/verifiedPrincipal.js';

/** Stable quota identity. Anonymous callers intentionally share one resource budget. */
export function httpPrincipalKey(): string {
  return config.mcpAuthMode === 'none'
    ? 'anonymous'
    : principalFingerprint(currentPrincipal());
}
