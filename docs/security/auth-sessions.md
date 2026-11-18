# Authenticated repository and session authority

HTTP authentication has no environment-dependent downgrade. With `MCP_AUTH_MODE=jwt`, startup requires `MCP_AUTH_SECRET_KEY` (32–4096 UTF-8 bytes), `MCP_AUTH_ISSUER`, and `MCP_AUTH_AUDIENCE`. Generate a random secret outside the repository; length alone does not establish entropy. Only HS256 is accepted. Missing or invalid settings fail startup in development, test and production alike.

OAuth requires an HTTPS issuer, HTTPS JWKS URL when overridden, and `OAUTH_AUDIENCE`. Trust-anchor URLs cannot contain credentials or fragments. Only RS256, ES256 and PS256 are accepted. Remote provider availability remains a deployment prerequisite; no live identity provider or backend settings are modified by this implementation.

Both strategies require a verified `iss`, matching `aud`, integer `iat` and `exp`, nonempty `sub`, `tid`, and `cid` or `client_id`. Conflicting client claims are rejected. Tokens must carry nonempty `scp` array or space-separated `scope`. `MCP_AUTH_MAX_TOKEN_LIFETIME_SECONDS` bounds both token age and `exp-iat` (default 3600, maximum 86400); `MCP_AUTH_CLOCK_TOLERANCE_SECONDS` bounds allowed clock skew (default 5, maximum 60). Missing tenant identity never maps to a shared default tenant. Arbitrary claims, request bodies and headers cannot supply identity or repository authority.

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

HTTP working-directory state uses a digest of the owner tuple and server UUID. Sessions for the same owner or tenant keep separate directories. Tools, resources, and wrapup share that session state and reauthorize paths on use. DELETE, expiry, and shutdown clear the session's cwd through StorageService. A new session starts without a cwd. Legacy `session:workingDir:<tenant>` keys may be removed separately by the operator.

In anonymous HTTP mode, callers share one admission quota and each session has a separate cwd. For STDIO, the host application authorizes the connection. STDIO keeps cwd in memory for that connection, including when HTTP uses a persistent provider.

## Storage and deployment constraints

StorageService derives enabled-auth tenant authority from the verified store and rejects a conflicting context tenant before backend access. Keys and tenants use the shared canonical UTF-8 component contract: nonempty components, no controls/unpaired UTF-16, maximum 120 UTF-8 bytes each. The filesystem provider uses an injective v2 hex codec to preserve the exact bytes of each component.

Supabase uses separate exact `tenant_id` and `key` columns. A deployment must verify a composite unique/primary key on `(tenant_id,key)`, suitable indexes, matching text comparison semantics, service-role credential confinement and appropriate RLS/role policies for every externally accessible database route. Application filters do not establish those database constraints. No live schema, RLS, role, IAM, bucket, namespace or provider configuration was inspected or changed, and no backend isolation certification is claimed.
