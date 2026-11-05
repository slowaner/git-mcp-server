/**
 * @fileoverview Deterministic complete Git-blob export without archive attributes.
 * @module scripts/security/release-source-archive
 */
import { createHash } from 'node:crypto';

/** The reviewed tree permits ordinary files, executable files and safe symlinks. */
export interface SourceBlob {
  path: string;
  mode: '100644' | '100755' | '120000';
  oid: string;
  bytes: Uint8Array;
}

const MAX_ARCHIVE_BYTES = 128 * 1024 * 1024;

function safePath(path: string): void {
  if (
    !path ||
    path.startsWith('/') ||
    /[\x00-\x1f\x7f\\]/.test(path) ||
    path
      .split('/')
      .some(
        (part) =>
          !part ||
          part === '.' ||
          part === '..' ||
          part.toLowerCase() === '.git',
      )
  )
    throw new Error('Unsupported source archive path.');
}

/** Decode exact NUL records; unsupported types and undecodable paths fail closed. */
export function sourceTreeEntries(
  bytes: Uint8Array,
): Omit<SourceBlob, 'bytes'>[] {
  if (!bytes.length || bytes.length > MAX_ARCHIVE_BYTES || bytes.at(-1) !== 0)
    throw new Error('Incomplete or oversized source tree.');
  const records = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
    .decode(bytes)
    .slice(0, -1)
    .split('\0');
  if (records.length > 10_000)
    throw new Error('Source tree entry budget exceeded.');
  return records.map((record) => {
    const match =
      /^(100644|100755|120000) blob ([0-9a-f]{40})\t([^\x00-\x1f\x7f]+)$/.exec(
        record,
      );
    if (!match) throw new Error('Unsupported source entry type or path.');
    safePath(match[3]!);
    return {
      path: match[3]!,
      mode: match[1] as SourceBlob['mode'],
      oid: match[2]!,
    };
  });
}

function octal(header: Buffer, offset: number, length: number, value: number) {
  const text = value.toString(8);
  if (!Number.isSafeInteger(value) || value < 0 || text.length >= length)
    throw new Error('Source tar numeric field overflow.');
  header.write(text.padStart(length - 1, '0') + '\0', offset, length, 'ascii');
}

function tarPath(path: string): { name: string; prefix: string } {
  if (Buffer.byteLength(path) <= 100) return { name: path, prefix: '' };
  for (
    let at = path.lastIndexOf('/');
    at > 0;
    at = path.lastIndexOf('/', at - 1)
  ) {
    const prefix = path.slice(0, at),
      name = path.slice(at + 1);
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(name) <= 100)
      return { prefix, name };
  }
  throw new Error('Source path exceeds lossless ustar bounds.');
}

/** Hash-checked immutable bytes, not a working-tree copy or git archive transformation. */
export function completeSourceArchive(entries: SourceBlob[]): Buffer {
  if (!entries.length || entries.length > 10_000)
    throw new Error('Invalid source inventory.');
  const names = new Set(entries.map((entry) => entry.path));
  if (names.size !== entries.length) throw new Error('Duplicate source path.');
  const chunks: Buffer[] = [];
  let total = 1024;
  for (const entry of [...entries].sort((a, b) =>
    Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)),
  )) {
    safePath(entry.path);
    const parts = entry.path.split('/');
    for (let index = 1; index < parts.length; index++) {
      if (names.has(parts.slice(0, index).join('/')))
        throw new Error('Source file/parent collision.');
    }
    if (!['100644', '100755', '120000'].includes(entry.mode))
      throw new Error('Unsupported source mode.');
    const bytes = Buffer.from(entry.bytes);
    const actual = createHash('sha1')
      .update(`blob ${bytes.length}\0`)
      .update(bytes)
      .digest('hex');
    if (!/^[0-9a-f]{40}$/.test(entry.oid) || actual !== entry.oid)
      throw new Error('Source blob differs from immutable tree.');
    const path = tarPath(entry.path);
    const header = Buffer.alloc(512);
    header.write(path.name, 0, 100, 'utf8');
    octal(
      header,
      100,
      8,
      entry.mode === '100755' ? 0o755 : entry.mode === '120000' ? 0o777 : 0o644,
    );
    octal(header, 108, 8, 0);
    octal(header, 116, 8, 0);
    const symlink = entry.mode === '120000';
    octal(header, 124, 12, symlink ? 0 : bytes.length);
    octal(header, 136, 12, 0);
    header.fill(0x20, 148, 156);
    header[156] = symlink ? 0x32 : 0x30;
    if (symlink) {
      const target = new TextDecoder('utf-8', {
        fatal: true,
        ignoreBOM: true,
      }).decode(bytes);
      safePath(target);
      if (bytes.length > 100)
        throw new Error('Source symlink exceeds lossless tar bounds.');
      header.write(target, 157, 100, 'utf8');
    }
    header.write('ustar\0', 257, 6, 'ascii');
    header.write('00', 263, 2, 'ascii');
    header.write(path.prefix, 345, 155, 'utf8');
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.write(
      checksum.toString(8).padStart(6, '0') + '\0 ',
      148,
      8,
      'ascii',
    );
    const padding = symlink ? 0 : (512 - (bytes.length % 512)) % 512;
    total += 512 + (symlink ? 0 : bytes.length + padding);
    if (total > MAX_ARCHIVE_BYTES)
      throw new Error('Source archive byte budget exceeded.');
    chunks.push(header);
    if (!symlink) chunks.push(bytes, Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks, total);
}
