/**
 * @fileoverview Private local storage primitives with no-follow atomic files.
 * Requires exclusive ownership of the storage tree; same-UID hostile processes
 * require OS isolation, not application path checks.
 * @module storage/providers/fileSystem/privateFileStore
 */
import { randomUUID } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';

import { JsonRpcErrorCode, McpError } from '@/types-global/errors.js';
import { decodeStorageComponent } from '@/storage/core/storageKeyCodec.js';

const MAX_VALUE_BYTES = 16 * 1024 * 1024;
type Identity = { dev: number; ino: number };

function deny(): never {
  throw new McpError(
    JsonRpcErrorCode.Forbidden,
    'Filesystem storage requires an unchanged, private owner-controlled directory and regular unlinked files.',
  );
}

function missing(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'ENOENT'
  );
}

/** No-follow file store; tenant and key components must be canonical codec output. */
export class PrivateFileStore {
  readonly root: string;
  private readonly identity: Identity;
  private readonly parents = new Map<string, Identity>();

  constructor(root: string) {
    if (
      process.platform === 'win32' ||
      !constants.O_NOFOLLOW ||
      !process.getuid
    )
      deny();
    // Resolve existing parent before creation; never recursively mkdir through
    // unknown links. Operators create nested parent directories themselves.
    const absolute = path.resolve(root);
    for (
      let current = path.dirname(absolute);
      ;
      current = path.dirname(current)
    ) {
      const stat = lstatSync(current);
      if (
        stat.isSymbolicLink() &&
        !(stat.uid === 0 && ['/var', '/tmp', '/etc'].includes(current))
      )
        deny();
      if (current === path.dirname(current)) break;
    }
    const parent = realpathSync(path.dirname(absolute));
    for (let current = parent; ; current = path.dirname(current)) {
      const stat = lstatSync(current);
      const publicStickyRoot = stat.uid === 0 && (stat.mode & 0o1000) !== 0;
      if (
        !stat.isDirectory() ||
        (stat.uid !== 0 && stat.uid !== process.getuid()) ||
        ((stat.mode & 0o022) !== 0 && !publicStickyRoot)
      )
        deny();
      this.parents.set(current, { dev: stat.dev, ino: stat.ino });
      if (current === path.dirname(current)) break;
    }
    this.root = path.join(parent, path.basename(absolute));
    try {
      mkdirSync(this.root, { mode: 0o700 });
    } catch (error) {
      if (!(
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        error.code === 'EEXIST'
      ))
        throw error;
    }
    this.identity = this.checkDirectory(this.root);
  }

  private checkDirectory(directory: string, expected?: Identity): Identity {
    const stat = lstatSync(directory);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      stat.uid !== process.getuid!() ||
      (stat.mode & 0o777) !== 0o700 ||
      (expected && (stat.dev !== expected.dev || stat.ino !== expected.ino))
    )
      deny();
    return { dev: stat.dev, ino: stat.ino };
  }

  private component(value: string): void {
    if (!decodeStorageComponent(value)) deny();
  }

  private tenantPath(tenant: string): {
    directory: string;
    identity: Identity;
  } {
    this.component(tenant);
    for (const [directory, expected] of this.parents) {
      const stat = lstatSync(directory);
      if (
        !stat.isDirectory() ||
        stat.dev !== expected.dev ||
        stat.ino !== expected.ino ||
        ((stat.mode & 0o022) !== 0 &&
          !(stat.uid === 0 && (stat.mode & 0o1000) !== 0))
      )
        deny();
    }
    this.checkDirectory(this.root, this.identity);
    const directory = path.join(this.root, tenant);
    try {
      mkdirSync(directory, { mode: 0o700 });
    } catch (error) {
      if (!(
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        error.code === 'EEXIST'
      ))
        throw error;
    }
    return { directory, identity: this.checkDirectory(directory) };
  }

  private checkFile(filename: string): boolean {
    try {
      const stat = lstatSync(filename);
      if (
        !stat.isFile() ||
        stat.nlink !== 1 ||
        stat.uid !== process.getuid!() ||
        (stat.mode & 0o777) !== 0o600
      )
        deny();
      return true;
    } catch (error) {
      if (missing(error)) return false;
      throw error;
    }
  }

  /** Read a bounded regular file by a no-follow descriptor. */
  read(tenant: string, key: string): string | null {
    this.component(key);
    const parent = this.tenantPath(tenant);
    const filename = path.join(parent.directory, key);
    if (!this.checkFile(filename)) return null;
    this.checkDirectory(parent.directory, parent.identity);
    const fd = openSync(
      filename,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    try {
      const stat = fstatSync(fd);
      if (
        !stat.isFile() ||
        stat.nlink !== 1 ||
        stat.uid !== process.getuid!() ||
        (stat.mode & 0o777) !== 0o600 ||
        stat.size > MAX_VALUE_BYTES
      )
        deny();
      const buffer = Buffer.alloc(stat.size + 1);
      let size = 0;
      while (size < buffer.length) {
        const count = readSync(fd, buffer, size, buffer.length - size, size);
        if (!count) break;
        size += count;
      }
      if (size > stat.size) deny();
      try {
        return new TextDecoder('utf-8', {
          fatal: true,
          ignoreBOM: true,
        }).decode(buffer.subarray(0, size));
      } catch {
        throw new McpError(
          JsonRpcErrorCode.SerializationError,
          'Filesystem storage contains invalid UTF-8.',
        );
      }
    } finally {
      closeSync(fd);
    }
  }

  /** Write exclusively to a fresh private inode, then atomically replace entry. */
  write(tenant: string, key: string, value: string): void {
    this.component(key);
    if (Buffer.byteLength(value) > MAX_VALUE_BYTES) deny();
    const parent = this.tenantPath(tenant);
    const filename = path.join(parent.directory, key);
    this.checkFile(filename);
    const temporary = path.join(parent.directory, `.tmp-${randomUUID()}`);
    const fd = openSync(
      temporary,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW,
      0o600,
    );
    try {
      const stat = fstatSync(fd);
      if (
        !stat.isFile() ||
        stat.nlink !== 1 ||
        stat.uid !== process.getuid!() ||
        (stat.mode & 0o777) !== 0o600
      )
        deny();
      writeFileSync(fd, value, 'utf8');
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    try {
      this.checkDirectory(this.root, this.identity);
      this.checkDirectory(parent.directory, parent.identity);
      this.checkFile(filename);
      renameSync(temporary, filename);
      const dir = openSync(
        parent.directory,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      try {
        fsyncSync(dir);
      } finally {
        closeSync(dir);
      }
    } finally {
      try {
        unlinkSync(temporary);
      } catch (error) {
        if (!missing(error)) throw error;
      }
    }
  }

  /** Unlink only a checked private regular entry; links are errors. */
  delete(tenant: string, key: string): boolean {
    this.component(key);
    const parent = this.tenantPath(tenant);
    const filename = path.join(parent.directory, key);
    if (!this.checkFile(filename)) return false;
    this.checkDirectory(parent.directory, parent.identity);
    unlinkSync(filename);
    return true;
  }

  /** Enumerate only canonical codec components; abandoned temp files stay hidden. */
  list(tenant: string): string[] {
    const parent = this.tenantPath(tenant);
    const entries = readdirSync(parent.directory, { withFileTypes: true });
    const result: string[] = [];
    for (const entry of entries) {
      if (entry.name.startsWith('.tmp-')) continue;
      this.component(entry.name);
      this.checkFile(path.join(parent.directory, entry.name));
      result.push(entry.name);
    }
    return result;
  }
}
