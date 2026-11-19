# Authenticated repository and session authority

HTTP authentication has no environment-dependent downgrade. With `MCP_AUTH_MODE=jwt`, startup requires `MCP_AUTH_SECRET_KEY` (32–4096 UTF-8 bytes), `MCP_AUTH_ISSUER`, and `MCP_AUTH_AUDIENCE`. Generate a random secret outside the repository. Only HS256 is accepted. Missing or invalid settings fail startup in development, test and production alike.

JWT verification requires a verified `iss`, matching `aud`, integer `iat` and `exp`, nonempty `sub`, `tid`, and `cid` or `client_id`. Conflicting client claims are rejected. Tokens must carry nonempty `scp` array or space-separated `scope`. `MCP_AUTH_MAX_TOKEN_LIFETIME_SECONDS` bounds both token age and `exp-iat` (default 3600, maximum 86400); `MCP_AUTH_CLOCK_TOLERANCE_SECONDS` bounds allowed clock skew (default 5, maximum 60). Missing tenant identity never maps to a shared default tenant. Arbitrary claims, request bodies and headers cannot supply identity or repository authority.

`git_remote` list/get-url require `tool:git:read`; add/remove/rename/set-url require `tool:git:write`. Denial precedes provider invocation. Enabled-auth tool/resource/storage access without the verified async-local context fails closed.

## Repository grants

Authenticated HTTP startup requires `MCP_REPOSITORY_GRANTS`, an operator-authored JSON array of exact grants:

```json
[
  {
    "issuer": "https://issuer.example.test",
    "tenantId": "tenant-a",
    "clientId": "client-a",
    "subject": "user-a",
    "roots": ["/srv/git/tenant-a"]
  }
]
```

Every tuple is exact and case-sensitive; there are no wildcard, tenant-union or default grants. Every configured root must be within the canonical operator `GIT_BASE_DIR` ceiling, and all grants are validated before HTTP session timers or factories are created. Request ACL, ambient restrictions and explicit internal restrictions intersect. Empty restrictions deny; absence never expands an existing restriction. All primary/secondary paths, clone destinations/local sources, local remotes, worktrees, metadata, snapshots and persisted cwd reads use the same repository capability. See [repository boundaries](../security-repository-boundaries.md).

Native Git runs with the server's operating-system authority. Use operator-controlled repositories and filesystem parents, and isolate mutually untrusted workloads at the OS level. See [Git execution](git-execution.md).

## Session ownership and working directory

Every HTTP session receives a server-generated UUID. Existing GET/SSE, POST and DELETE require the current verified `(issuer, tenantId, clientId, subject)` owner before expiry lookup, touch, cleanup, request/stream admission or dispatch. Unknown and foreign sessions return 404. Tokens and RPC ids are not owner keys. Refreshing a valid token for the same tuple preserves the session and admission identity; changing any owner component requires a new initialization. Scope changes take effect on each request. SSE reconnect works for the current owner after stream cancellation. Expired/terminated sessions require initialization and receive new UUIDs.

HTTP working-directory state uses a digest of the owner tuple and server UUID. Sessions for the same owner or tenant keep separate directories. Tools, resources, and wrapup share that session state and reauthorize paths on use. The server serializes writes and explicit clears within each HTTP session. A clear waits for earlier writes and fails if the outcome of any earlier write is unknown. Session termination, expiry, and shutdown stop accepting cwd mutations and wait for the active mutation before clearing cwd. HTTP cwd mutations and cleanup deletes each use the `MCP_HTTP_REQUEST_TIMEOUT_MS` deadline. Cleanup proceeds after a mutation completes with a known outcome. A deadline or a storage error that reports an unconfirmed write leaves the outcome unknown. In that case cleanup logs a warning, skips deletion, and releases the session slot. An unconfirmed explicit clear also blocks later writes because the delete could still take effect. Closing sessions count against admission limits until cleanup finishes. A new session starts without a cwd. Legacy `session:workingDir:<tenant>` keys may be removed separately by the operator.

In anonymous HTTP mode, callers share one admission quota and each session has a separate cwd. For STDIO, the host application authorizes the connection. STDIO keeps cwd in memory for that connection even with filesystem storage configured.

## Storage and deployment constraints

StorageService derives enabled-auth tenant authority from the verified store and rejects a conflicting context tenant before backend access. Keys and tenants use the shared canonical UTF-8 component contract: nonempty components, no controls/unpaired UTF-16, maximum 120 UTF-8 bytes each. The filesystem provider uses an injective v2 hex codec to preserve the exact bytes of each component.

Local storage supports `in-memory` and `filesystem`. Use an operator-controlled, private directory for persistent storage.
