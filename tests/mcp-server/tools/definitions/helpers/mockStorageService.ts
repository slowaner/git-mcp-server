/**
 * @fileoverview Mock Storage service implementation for testing tools in isolation.
 * @module tests/mcp-server/tools/definitions/helpers/mockStorageService
 */
import type { RequestContext } from '@/utils/index.js';
import { workingDirectoryStore } from '@/storage/core/sessionWorkingDirectoryStore.js';
import type {
  StorageOptions,
  ListOptions,
  ListResult,
} from '@/storage/core/IStorageProvider.js';

/**
 * Get tenant ID from context with graceful degradation (matches real implementation)
 */
function getTenantId(context: RequestContext): string {
  return context.tenantId || 'default-tenant';
}

/**
 * Mock implementation of StorageService for testing.
 * Provides in-memory storage with tenant isolation.
 * Matches the real StorageService API exactly.
 */
export class MockStorageService {
  private store: Map<string, Map<string, unknown>> = new Map();

  async get<T>(key: string, context: RequestContext): Promise<T | null> {
    const tenantId = getTenantId(context);
    const tenantStore = this.store.get(tenantId);
    if (!tenantStore) {
      return null;
    }
    return (tenantStore.get(key) as T) || null;
  }

  async set(
    key: string,
    value: unknown,
    context: RequestContext,
    _options?: StorageOptions,
  ): Promise<void> {
    const tenantId = getTenantId(context);
    let tenantStore = this.store.get(tenantId);
    if (!tenantStore) {
      tenantStore = new Map();
      this.store.set(tenantId, tenantStore);
    }
    tenantStore.set(key, value);
  }

  async delete(key: string, context: RequestContext): Promise<boolean> {
    const tenantId = getTenantId(context);
    const tenantStore = this.store.get(tenantId);
    if (!tenantStore) {
      return false;
    }
    return tenantStore.delete(key);
  }

  async list(
    prefix: string,
    context: RequestContext,
    _options?: ListOptions,
  ): Promise<ListResult> {
    const tenantId = getTenantId(context);
    const tenantStore = this.store.get(tenantId);
    if (!tenantStore) {
      return { keys: [] };
    }
    const keys = Array.from(tenantStore.keys()).filter((key) =>
      key.startsWith(prefix),
    );
    return { keys };
  }

  async getMany<T>(
    keys: string[],
    context: RequestContext,
  ): Promise<Map<string, T>> {
    const tenantId = getTenantId(context);
    const tenantStore = this.store.get(tenantId);
    const result = new Map<string, T>();
    if (!tenantStore) {
      return result;
    }
    for (const key of keys) {
      const value = tenantStore.get(key);
      if (value !== undefined) {
        result.set(key, value as T);
      }
    }
    return result;
  }

  async setMany(
    entries: Map<string, unknown>,
    context: RequestContext,
    _options?: StorageOptions,
  ): Promise<void> {
    const tenantId = getTenantId(context);
    let tenantStore = this.store.get(tenantId);
    if (!tenantStore) {
      tenantStore = new Map();
      this.store.set(tenantId, tenantStore);
    }
    for (const [key, value] of entries.entries()) {
      tenantStore.set(key, value);
    }
  }

  async deleteMany(keys: string[], context: RequestContext): Promise<number> {
    const tenantId = getTenantId(context);
    const tenantStore = this.store.get(tenantId);
    if (!tenantStore) {
      return 0;
    }
    let count = 0;
    for (const key of keys) {
      if (tenantStore.delete(key)) {
        count++;
      }
    }
    return count;
  }

  async clear(context: RequestContext): Promise<number> {
    const tenantId = getTenantId(context);
    const tenantStore = this.store.get(tenantId);
    if (!tenantStore) {
      return 0;
    }
    const count = tenantStore.size;
    this.store.delete(tenantId);
    return count;
  }

  /**
   * Clear all data across all tenants (test utility)
   */
  clearAll(): void {
    this.store.clear();
  }

  /**
   * Get all keys for a tenant (test utility)
   */
  getAllKeys(tenantId: string): string[] {
    const tenantStore = this.store.get(tenantId);
    if (!tenantStore) {
      return [];
    }
    return Array.from(tenantStore.keys());
  }

  /**
   * Check if a tenant exists (test utility)
   */
  hasTenant(tenantId: string): boolean {
    return this.store.has(tenantId);
  }
}

/**
 * Factory function to create a fresh MockStorageService instance
 */
export function createMockStorageService(): MockStorageService {
  return new MockStorageService();
}

/**
 * Creates a MockStorageService with pre-populated session data
 */
export function createMockStorageWithSession(
  tenantId: string,
  workingDir: string,
): MockStorageService {
  const storage = new MockStorageService();
  const context = {
    requestId: 'test-request-id',
    sessionId: 'test-session-id',
    timestamp: new Date().toISOString(),
    tenantId,
  } as RequestContext;

  // Set working directory in session storage
  workingDirectoryStore(storage, context).set(workingDir);

  return storage;
}
