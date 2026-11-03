/**
 * @fileoverview Admission identity adapter; only verified authentication context is used.
 * @module mcp-server/transports/http/httpPrincipal
 */
import { authContext } from '../auth/index.js';

/** Stable quota identity. Anonymous callers intentionally share one resource budget. */
export function httpPrincipalKey(): string {
  const info = authContext.getStore()?.authInfo;
  return info
    ? JSON.stringify([info.tenantId ?? '', info.clientId, info.subject ?? ''])
    : 'anonymous';
}
