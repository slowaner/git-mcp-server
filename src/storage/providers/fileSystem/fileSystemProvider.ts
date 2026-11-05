/**
 * @fileoverview A filesystem-based storage provider.
 * Persists data to the local filesystem in a specified directory.
 * Each key-value pair is stored as a separate JSON file.
 * @module src/storage/providers/fileSystem/fileSystemProvider
 */
import path from 'node:path';

import type {
  IStorageProvider,
  StorageOptions,
  ListOptions,
  ListResult,
} from '@/storage/core/IStorageProvider.js';
import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import { ErrorHandler, type RequestContext } from '@/utils/index.js';
import {
  decodeStorageComponent,
  encodeStorageComponent,
  encodeStorageKey,
  encodeStoragePrefix,
  storageTenantPrefix,
} from '@/storage/core/storageKeyCodec.js';
import { PrivateFileStore } from './privateFileStore.js';

const DEFAULT_LIST_LIMIT = 1000;

type FileEnvelope = {
  __mcp: { v: 1; expiresAt?: number };
  value: unknown;
};

const FILE_ENVELOPE_VERSION = 1;

/** Private v2 filesystem storage; legacy namespaces are deliberately not read. */
export class FileSystemProvider implements IStorageProvider {
  private readonly files: PrivateFileStore;

  constructor(storagePath: string) {
    if (!storagePath) {
      throw new McpError(
        JsonRpcErrorCode.ConfigurationError,
        'FileSystemProvider requires a valid storagePath.',
      );
    }
    const root = new PrivateFileStore(storagePath);
    this.files = new PrivateFileStore(path.join(root.root, 'v2'));
  }

  private getTenantPath(tenantId: string): string {
    storageTenantPrefix(tenantId);
    return encodeStorageComponent(tenantId);
  }

  private getFilePath(
    tenantId: string,
    key: string,
  ): { tenant: string; key: string } {
    encodeStorageKey(tenantId, key);
    return {
      tenant: this.getTenantPath(tenantId),
      key: encodeStorageComponent(key),
    };
  }

  private buildEnvelope(
    value: unknown,
    options?: StorageOptions,
  ): FileEnvelope {
    if (
      value === undefined ||
      (options?.ttl !== undefined && !Number.isFinite(options.ttl))
    )
      throw new McpError(
        JsonRpcErrorCode.SerializationError,
        'Filesystem storage requires a defined JSON value and finite TTL.',
      );
    const expiresAt = options?.ttl
      ? Date.now() + options.ttl * 1000
      : undefined;
    return {
      __mcp: { v: FILE_ENVELOPE_VERSION, ...(expiresAt ? { expiresAt } : {}) },
      value,
    };
  }

  private parseAndValidate<T>(
    raw: string,
    tenantId: string,
    key: string,
    filePath: { tenant: string; key: string },
    context: RequestContext,
  ): { value: T } | null {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (
        !parsed ||
        typeof parsed !== 'object' ||
        Array.isArray(parsed) ||
        !('__mcp' in parsed) ||
        !Object.hasOwn(parsed, 'value')
      )
        throw new Error('Invalid filesystem storage envelope.');
      const metadata = parsed.__mcp;
      if (
        !metadata ||
        typeof metadata !== 'object' ||
        Array.isArray(metadata) ||
        !('v' in metadata) ||
        metadata.v !== FILE_ENVELOPE_VERSION ||
        ('expiresAt' in metadata &&
          (typeof metadata.expiresAt !== 'number' ||
            !Number.isFinite(metadata.expiresAt)))
      )
        throw new Error('Invalid filesystem storage metadata.');
      const env = parsed as FileEnvelope;
      const expiresAt = env.__mcp.expiresAt;
      if (expiresAt !== undefined && Date.now() > expiresAt) {
        // Expired: best-effort delete and return null
        try {
          this.files.delete(filePath.tenant, filePath.key);
        } catch {
          // ignore
        }
        return null;
      }
      return { value: env.value as T };
    } catch (error) {
      throw new McpError(
        JsonRpcErrorCode.SerializationError,
        `Failed to parse stored JSON for key "${key}" (tenant "${tenantId}").`,
        { ...context, error },
      );
    }
  }

  /** Keep an existing null value distinct from a missing/expired entry internally. */
  private readValue<T>(
    tenantId: string,
    key: string,
    context: RequestContext,
  ): { value: T } | null {
    const filePath = this.getFilePath(tenantId, key);
    const data = this.files.read(filePath.tenant, filePath.key);
    return data === null
      ? null
      : this.parseAndValidate<T>(data, tenantId, key, filePath, context);
  }

  async get<T>(
    tenantId: string,
    key: string,
    context: RequestContext,
  ): Promise<T | null> {
    return ErrorHandler.tryCatch(
      () =>
        Promise.resolve().then(
          () => this.readValue<T>(tenantId, key, context)?.value ?? null,
        ),
      {
        operation: 'FileSystemProvider.get',
        context,
        input: { tenantId, key },
      },
    );
  }

  async set(
    tenantId: string,
    key: string,
    value: unknown,
    context: RequestContext,
    options?: StorageOptions,
  ): Promise<void> {
    const filePath = this.getFilePath(tenantId, key);
    return ErrorHandler.tryCatch(
      () =>
        Promise.resolve().then(() => {
          const envelope = this.buildEnvelope(value, options);
          const content = JSON.stringify(envelope, null, 2);
          this.files.write(filePath.tenant, filePath.key, content);
        }),
      {
        operation: 'FileSystemProvider.set',
        context,
        input: { tenantId, key },
      },
    );
  }

  async delete(
    tenantId: string,
    key: string,
    context: RequestContext,
  ): Promise<boolean> {
    const filePath = this.getFilePath(tenantId, key);
    return ErrorHandler.tryCatch(
      () =>
        Promise.resolve().then(() =>
          this.files.delete(filePath.tenant, filePath.key),
        ),
      {
        operation: 'FileSystemProvider.delete',
        context,
        input: { tenantId, key },
      },
    );
  }

  async list(
    tenantId: string,
    prefix: string,
    context: RequestContext,
    options?: ListOptions,
  ): Promise<ListResult> {
    return ErrorHandler.tryCatch(
      () =>
        Promise.resolve().then(() => {
          encodeStoragePrefix(tenantId, prefix);
          const tenantPath = this.getTenantPath(tenantId);
          const allKeys = this.files
            .list(tenantPath)
            .map(decodeStorageComponent);
          const candidateKeys = allKeys.filter((k) => k.startsWith(prefix));

          // TTL-aware filtering: best-effort; expensive on large stores.
          const validKeys: string[] = [];
          for (const k of candidateKeys) {
            const filePath = this.getFilePath(tenantId, k);
            const raw = this.files.read(filePath.tenant, filePath.key);
            if (raw === null) continue;
            const value = this.parseAndValidate<unknown>(
              raw,
              tenantId,
              k,
              filePath,
              context,
            );
            if (value !== null) {
              validKeys.push(k);
            }
          }

          // Sort for consistent pagination
          validKeys.sort();

          // Apply pagination
          const limit = options?.limit ?? DEFAULT_LIST_LIMIT;
          let startIndex = 0;

          if (options?.cursor) {
            const cursorIndex = validKeys.indexOf(options.cursor);
            if (cursorIndex !== -1) {
              startIndex = cursorIndex + 1;
            }
          }

          const paginatedKeys = validKeys.slice(startIndex, startIndex + limit);
          const nextCursor =
            startIndex + limit < validKeys.length
              ? paginatedKeys[paginatedKeys.length - 1]
              : undefined;

          return {
            keys: paginatedKeys,
            nextCursor,
          };
        }),
      {
        operation: 'FileSystemProvider.list',
        context,
        input: { tenantId, prefix },
      },
    );
  }

  async getMany<T>(
    tenantId: string,
    keys: string[],
    context: RequestContext,
  ): Promise<Map<string, T>> {
    return ErrorHandler.tryCatch(
      () =>
        Promise.resolve().then(() => {
          const results = new Map<string, T>();
          for (const key of keys) {
            const value = this.readValue<T>(tenantId, key, context);
            if (value !== null) {
              results.set(key, value.value);
            }
          }
          return results;
        }),
      {
        operation: 'FileSystemProvider.getMany',
        context,
        input: { tenantId, keyCount: keys.length },
      },
    );
  }

  async setMany(
    tenantId: string,
    entries: Map<string, unknown>,
    context: RequestContext,
    options?: StorageOptions,
  ): Promise<void> {
    return ErrorHandler.tryCatch(
      async () => {
        for (const [key, value] of entries.entries()) {
          await this.set(tenantId, key, value, context, options);
        }
      },
      {
        operation: 'FileSystemProvider.setMany',
        context,
        input: { tenantId, entryCount: entries.size },
      },
    );
  }

  async deleteMany(
    tenantId: string,
    keys: string[],
    context: RequestContext,
  ): Promise<number> {
    return ErrorHandler.tryCatch(
      async () => {
        let deletedCount = 0;
        for (const key of keys) {
          const deleted = await this.delete(tenantId, key, context);
          if (deleted) {
            deletedCount++;
          }
        }
        return deletedCount;
      },
      {
        operation: 'FileSystemProvider.deleteMany',
        context,
        input: { tenantId, keyCount: keys.length },
      },
    );
  }

  async clear(tenantId: string, context: RequestContext): Promise<number> {
    return ErrorHandler.tryCatch(
      async () => {
        const tenantPath = this.getTenantPath(tenantId);
        const allKeys = this.files.list(tenantPath).map(decodeStorageComponent);
        let deletedCount = 0;
        for (const key of allKeys) {
          const deleted = await this.delete(tenantId, key, context);
          if (deleted) {
            deletedCount++;
          }
        }
        return deletedCount;
      },
      {
        operation: 'FileSystemProvider.clear',
        context,
        input: { tenantId },
      },
    );
  }
}
