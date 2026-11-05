/**
 * @fileoverview Provides a singleton service for interacting with the application's storage layer.
 * This service acts as a proxy to the configured storage provider, ensuring a consistent
 * interface for all storage operations throughout the application. It receives its concrete
 * provider via dependency injection.
 * @module src/storage/core/StorageService
 */
import { injectable, inject } from 'tsyringe';

import { StorageProvider } from '@/container/tokens.js';
import {
  authenticationRequired,
  currentPrincipal,
} from '@/mcp-server/transports/auth/lib/requestIdentity.js';
import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import {
  encodeStorageComponent,
  encodeStorageKey,
  encodeStoragePrefix,
} from './storageKeyCodec.js';
import type { RequestContext } from '@/utils/index.js';
import type {
  IStorageProvider,
  StorageOptions,
  ListOptions,
  ListResult,
} from '@/storage/core/IStorageProvider.js';

/**
 * Get tenant ID from context with graceful degradation.
 * In development (STDIO/no auth), defaults to 'default-tenant'.
 * In production with auth enabled, tenantId will be provided via JWT.
 */
function getTenantId(context: RequestContext): string {
  const tenantId = authenticationRequired()
    ? currentPrincipal().tenantId
    : context.tenantId || 'default-tenant';
  if (
    authenticationRequired() &&
    context.tenantId !== undefined &&
    context.tenantId !== tenantId
  )
    throw new McpError(
      JsonRpcErrorCode.Forbidden,
      'Storage tenant does not match verified identity.',
    );
  encodeStorageComponent(tenantId);
  return tenantId;
}

@injectable()
export class StorageService {
  constructor(@inject(StorageProvider) private provider: IStorageProvider) {}

  get<T>(key: string, context: RequestContext): Promise<T | null> {
    const tenantId = getTenantId(context);
    encodeStorageKey(tenantId, key);
    return this.provider.get(tenantId, key, context);
  }

  set(
    key: string,
    value: unknown,
    context: RequestContext,
    options?: StorageOptions,
  ): Promise<void> {
    const tenantId = getTenantId(context);
    encodeStorageKey(tenantId, key);
    return this.provider.set(tenantId, key, value, context, options);
  }

  delete(key: string, context: RequestContext): Promise<boolean> {
    const tenantId = getTenantId(context);
    encodeStorageKey(tenantId, key);
    return this.provider.delete(tenantId, key, context);
  }

  list(
    prefix: string,
    context: RequestContext,
    options?: ListOptions,
  ): Promise<ListResult> {
    const tenantId = getTenantId(context);
    encodeStoragePrefix(tenantId, prefix);
    return this.provider.list(tenantId, prefix, context, options);
  }

  getMany<T>(keys: string[], context: RequestContext): Promise<Map<string, T>> {
    const tenantId = getTenantId(context);
    for (const key of keys) encodeStorageKey(tenantId, key);
    return this.provider.getMany(tenantId, keys, context);
  }

  setMany(
    entries: Map<string, unknown>,
    context: RequestContext,
    options?: StorageOptions,
  ): Promise<void> {
    const tenantId = getTenantId(context);
    for (const key of entries.keys()) encodeStorageKey(tenantId, key);
    return this.provider.setMany(tenantId, entries, context, options);
  }

  deleteMany(keys: string[], context: RequestContext): Promise<number> {
    const tenantId = getTenantId(context);
    for (const key of keys) encodeStorageKey(tenantId, key);
    return this.provider.deleteMany(tenantId, keys, context);
  }

  clear(context: RequestContext): Promise<number> {
    const tenantId = getTenantId(context);
    return this.provider.clear(tenantId, context);
  }
}
