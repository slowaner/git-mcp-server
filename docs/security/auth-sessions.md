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

The inherited restricted Git execution profile is unsupported and fails closed. Explicit `trusted` profile still applies repository ACLs, but host-native Git hooks, helpers and configuration retain operator-trusted authority. An application ACL does not provide operating-system tenant isolation. Use isolated instances for mutually hostile native Git workloads; see [Git execution](git-execution.md).

## Session ownership and working directory

Every HTTP session receives a server-generated UUID. Existing GET/SSE, POST and DELETE require the current verified `(issuer, tenantId, clientId, subject)` owner before expiry lookup, touch, cleanup, request/stream admission or dispatch. Unknown and foreign sessions return 404. Tokens and RPC ids are not owner keys. Refreshing a valid token for the same tuple preserves the session and admission identity; changing any owner component requires a new initialization. Scope changes take effect on each request. SSE reconnect works for the current owner after stream cancellation. Expired/terminated sessions require initialization and receive new UUIDs.

Cwd state uses a v2 digest of the framed owner tuple and server UUID. Same-tenant users and same-owner sessions retain separate directories under interleaving set/read/clear. Resource reads and wrapup use that same scope, and paths are reauthorized on use. DELETE/expiry/shutdown delete that session's cwd through StorageService. Legacy `session:workingDir:<tenant>` values are deliberately discarded by lookup, with no automatic migration or fallback. Remove obsolete backend data separately under operator change control. A new session starts without cwd.

`none` HTTP mode is explicitly anonymous and provides no user authentication; all callers share anonymous admission authority, while server session UUIDs separate cwd. STDIO uses an explicit server-owned host identity/session because the host application controls the process. These policies do not supply a fallback to enabled HTTP auth.

## Storage and deployment constraints

StorageService derives enabled-auth tenant authority from the verified store and rejects a conflicting context tenant before backend access. Keys and tenants use the shared canonical UTF-8 component contract: nonempty components, no controls/unpaired UTF-16, maximum 120 UTF-8 bytes each. Filesystem, KV and R2 use the inherited injective v2 hex codec; no delimiter concatenation, case folding, Unicode normalization or legacy-key fallback. Cloud provider listings containing foreign/noncanonical keys fail closed before deleting any item in that page. KV/R2 namespaces are application authority, not provider IAM proof.

Supabase uses separate exact `tenant_id` and `key` columns. A deployment must verify a composite unique/primary key on `(tenant_id,key)`, suitable indexes, matching text comparison semantics, service-role credential confinement and appropriate RLS/role policies for every externally accessible database route. Application filters do not establish those database constraints. No live schema, RLS, role, IAM, bucket, namespace or provider configuration was inspected or changed, and no backend isolation certification is claimed.

Cloudflare KV is eventually consistent and cannot promise immediate read-after-write cwd semantics across workers; R2/SQL consistency, TTL, pagination and connection behavior depend on deployment. The experimental Worker entrypoint is explicitly unsupported and returns 503 for every route/method before reading bindings or importing application services. The available Node/local profile is the qualified runtime; see [Worker profile](worker-profile.md). Backend-specific distributed consistency and RLS/IAM need independent deployment validation.
