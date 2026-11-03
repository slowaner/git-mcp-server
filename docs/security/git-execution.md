# Native Git execution policy

Native Git is a program execution boundary. Repository configuration can start
hooks, filters, fsmonitor, credential/transport helpers and signing programs.
Configuration flags alone cannot isolate an untrusted repository.

## Profiles and upgrade behavior

| Configuration/platform | Startup and Git behavior | Authority |
| --- | --- | --- |
| Unset `GIT_EXECUTION_PROFILE` | Server can start; Git requests reject with `POLICY_UNSUPPORTED` before repository reads, discovery, or destination creation | Default `restricted` |
| `restricted`, any platform | Rejects before Git or repository filesystem work | No working OS sandbox is supplied |
| Explicit `trusted`, Node or Bun on macOS/Linux | Enables native Git under the configured operator identity and request limits | Only operator-trusted repositories, configuration and helpers |
| Explicit `trusted`, other platforms including Windows | Rejects before spawn; no verified process-group/Job Object implementation | Unsupported |
| Invalid profile, paths or numeric limits | Configuration validation fails at startup | No silent downgrade |

This change does **not** provide a working untrusted-repository sandbox. Do not
enable `trusted` to host malicious or tenant-controlled repositories. Native
global/system configuration and their includes, repository hooks/filters/helpers,
SSH agent and signing keyring remain operator authority. Trusted mode makes no
filesystem, RCE, network-egress or parent-path race confinement guarantee.
Application canonical-root and tenant authorization checks still apply; selecting
trusted mode does not grant a root/tenant exemption. Repository metadata and
effective configuration authorization are separate gates in the remediation stack.

Existing installations must explicitly opt in only after establishing operator
trust. Example for a POSIX installation whose Git is `/usr/bin/git`:

```sh
GIT_EXECUTION_PROFILE=trusted
GIT_BINARY_PATH=/usr/bin/git
GIT_TRUSTED_HOME=/absolute/operator/home
GIT_TRUSTED_PATH=/usr/bin:/bin
```

Server startup itself requires an operator-owned entrypoint, working directory,
environment and runtime configuration. The application consumes inherited
environment variables only and no longer implicitly loads a cwd `.env` file.
Migrate application `.env` deployments to an explicit operator-owned external
environment preparation/launcher; do not source configuration from an imported
repository. The installed executable has a Node shebang. This removal changes no
auth/claims/scope policy and adds no application env-file mode.

Native Bun independently loads cwd `.env` variants and can execute `bunfig.toml`
preloads **before application code**. Use an operator-owned launch cwd/config and
`--no-env-file` when relying only on the supplied environment. That flag disables
automatic env loading; it does not neutralize a malicious preload. The application
cannot attest or contain runtime behavior that precedes it. Do not launch the
server from a repository-controlled cwd or treat restricted Git as a startup
sandbox. Bun's pinned [environment loading documentation](https://github.com/oven-sh/bun/blob/c6da4a4d3010e5553438c60f6bd76d981976867c/docs/runtime/environment-variables.mdx)
and [runtime preload documentation](https://github.com/oven-sh/bun/blob/c6da4a4d3010e5553438c60f6bd76d981976867c/docs/runtime/bunfig.mdx)
describe these separate pre-entry authorities. No launcher, package script or
runtime-wide configuration is changed here.

All paths are operator configuration, never tool parameters. The executable and
HOME must be absolute; every helper PATH entry must be absolute and nonempty.
Git is never selected from inherited PATH. Inherited `GIT_*` routing/config,
loader variables and unrelated server credentials are excluded. Explicit Git
author/committer configuration is applied separately. Operator SSH agent,
GNUPGHOME, proxy and certificate settings are retained in trusted mode. Native
signing and hooks remain enabled according to that controlled native environment;
`GIT_SIGN_COMMITS=false` leaves native signing configuration in control.

## Output and lifecycle contract

| Variable | Default | Valid bounds |
| --- | --- | --- |
| `GIT_MAX_COMMAND_TIMEOUT_MS` | 30000 | Integer 1..2147483647 |
| `GIT_MAX_BUFFER_SIZE_MB` | 10 | Integer 1..128; legacy aggregate MiB fallback |
| `GIT_MAX_OUTPUT_BYTES` | Legacy MiB setting in bytes | Integer 1..134217728 |
| `GIT_MAX_STDOUT_BYTES` | Aggregate byte cap | Integer 1..134217728 per process |
| `GIT_MAX_STDERR_BYTES` | Aggregate byte cap | Integer 1..134217728 per process |
| `GIT_TERMINATION_GRACE_MS` | 250 | Integer 0..5000 |

Raw stdout and stderr drain concurrently. Bytes are charged before retention,
against independent stream caps and one poisoned aggregate budget across every
Git call in the owning SDK request/provider operation, including metadata calls.
No partial output or silent truncation is returned. Nested operations cannot
replenish the request budget. These limits govern native output, not the final
JSON response envelope or record/object-count limits.

Both streams must be valid UTF-8. Strict EOF decoding preserves BOM, literal
U+FFFD, NUL and newline bytes, including split multibyte sequences. Successfully
returned strings round-trip to the original accepted bytes through UTF-8 encoding.
Malformed, overlong, surrogate or incomplete UTF-8 rejects with
`INVALID_OUTPUT_ENCODING`, poisons the request and prevents subsequent Git calls.
There is no lossy replacement fallback or arbitrary-binary/base64 output mode.
This intentionally limits `show`/blob/raw output and legacy-encoded commit,
configuration, filename and diagnostic text: non-UTF8 data is unsupported and
fails closed. Callers must not describe validated text as arbitrary raw bytes.

SDK cancellation and an absolute operation deadline propagate through providers.
The deadline includes stream drain and does not reset for metadata commands.
The same Node-compatible process-control implementation runs on Node and Bun.
A fixed bundled bootstrap anchors a POSIX process group, uses a bounded private
control descriptor not inherited by Git, and reports Git's real exit separately.
Termination escalates from TERM to one final KILL while the anchor is live;
settlement waits for stream/group cleanup. Permission failures and unexpected
anchor loss are `CLEANUP_FAILED`, never success. The anchor is never signaled after
exit or by a reused/unrelated PGID. A deliberately detached session escapes a
process group; trusted programs must not detach. Group supervision is not a
replacement for the missing restricted OS sandbox.

Successful internal executor results always have numeric `exitCode`. An ordinary
nonzero exit may be returned only to internal callers requesting a soft Git exit;
signals always reject. Stable payload-free `McpError.data.reason` values are
`POLICY_UNSUPPORTED`, `INVALID_EXECUTION_OPTIONS`, `OUTPUT_LIMIT`,
`INVALID_OUTPUT_ENCODING`, `CANCELLED`, `DEADLINE`, `SIGNAL_EXIT`, `DESCENDANTS`,
`CLEANUP_FAILED` and `SPAWN_FAILED`. Control errors cannot be converted into
successful formatted tool output by catching an intermediate metadata failure.

The repository gate can call `assertConfiguredGitExecutionPolicy` before any
filesystem operation. `GitOperationContext`/internal executor options carry the
server-derived `repositoryRoots`, signal and deadline. Roots absent and roots
empty are distinct; neither is a public tool capability. Effective native config
inspection must use the same controlled executor environment after local metadata
authorization, including trusted global/system includes; a public recursion-bypass
flag is not part of this API.

Local qualification covers Node 26.12.0 and Bun 1.4.3 on macOS with actual native
Git, private SSH signing and source-built STDIO. Linux/native nonUTF8 filename
qualification and downstream cumulative repository/tenant gates must be assessed
separately; local positives do not establish their acceptance.
