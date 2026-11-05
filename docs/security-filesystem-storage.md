# Private filesystem storage

The filesystem provider uses a private `v2/xTENANTHEX/xKEYHEX` namespace. Tenant
and key components preserve exact Unicode bytes and case; separators and path
syntax are encoded as data. Each component is limited to 120 UTF-8 bytes.
Control characters and malformed Unicode are rejected.

Storage directories require the server's UID and mode `0700`; stored values
require that UID, mode `0600`, a regular file, and a single hard link. Existing
nonprivate directories fail closed instead of being chmodded automatically. The
configured directory's parent must already exist and be owner-controlled; root
owned sticky temporary directories are permitted. User-created symlink parents,
root/tenant links and linked value files are rejected. Windows/reparse-point
storage is unsupported by this provider and fails closed.

Reads use bounded no-follow descriptors. A serialized value may occupy at most
16 MiB, including its envelope. Writes create a fresh exclusive file, sync it,
atomically rename it, and sync the tenant directory. Interrupted temporary files
are hidden from key enumeration. Bulk operations remain sequential and are not
a transaction across keys.

Stored text must be valid UTF-8. Malformed, truncated, overlong and surrogate
byte sequences are errors, with no replacement or partial value. Valid literal
U+FFFD and BOM characters inside JSON values are preserved. A BOM before the
JSON document is rejected as JSON syntax. Corrupt UTF-8 or JSON causes reads,
bulk reads and listing of the affected key to fail; it is not treated as a
missing value or silently omitted. Failed reads do not migrate, overwrite or
delete corrupted files. The v2 namespace requires a version-1 envelope with an
explicit value and, when present, a finite numeric expiry. Missing/unknown
envelopes, invalid expiry metadata, undefined values and nonfinite TTLs are
errors; none becomes a missing value or an automatic expiry deletion.
Valid null and falsy values remain stored entries: listing includes their keys
and bulk reads distinguish them from missing or expired entries.

Legacy unversioned files are left untouched and are never read automatically.
Existing persisted working-directory state must be set again through the server
or migrated by an operator after reviewing the original data. Do not copy legacy
paths directly into the encoded namespace. An operator may explicitly migrate
valid version-1 envelopes into reviewed v2 keys; raw legacy values and unknown
formats are rejected there. This does not enable lookup in the legacy tree.

Private permissions protect storage from other operating-system users. These
checks are not an OS sandbox and cannot protect against hostile processes with
the server's UID, privileged processes, or attacker-controlled mount semantics.
Use an isolated private storage volume for those threat models. No race-resistant
same-UID containment is claimed by the trusted runtime profile.
