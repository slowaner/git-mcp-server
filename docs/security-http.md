# HTTP trust and resource limits

HTTP rejects unapproved Host and Origin headers before authentication or body
access. `MCP_HTTP_ALLOWED_HOSTS` is a comma-separated list of exact authorities,
including ports and IPv6 brackets, for example `git.example:443,[::1]:3015`.
Use the canonical authority (`git.example` for the default HTTP port). Without
this setting only `localhost`, `127.0.0.1` and `[::1]` at the actual listening port
are accepted. Wildcard bind addresses do not extend this allowlist.

`MCP_ALLOWED_ORIGINS` contains exact HTTP(S) origins, without paths or wildcards.
An empty list disables browser clients. Foreign and `null` origins are rejected;
CORS response headers do not grant admission. Native clients without Origin are
allowed by default; set `MCP_HTTP_ALLOW_NATIVE_CLIENTS=false` to reject them.
Only the literal values `true` and `false` are accepted for this option.

Forwarded, X-Forwarded-Host, X-Forwarded-For and X-Forwarded-Proto are never trusted.
A reverse proxy must preserve an explicitly allowed Host, enforce its own ingress
and slow-connection limits, and restrict access to its upstream. Host and Origin
checks complement authentication; they do not identify a caller or authorize a
repository.

## Parsing and tool budgets

The independent `@hono/mcp` parser has been removed. The SDK's Web Standards
transport receives only an already bounded, parsed single JSON-RPC message.
JSON-RPC batch arrays are rejected (400), including one-message arrays.
POST uses JSON responses; standalone GET SSE remains supported.

Authentication failures never read the body to recover a JSON-RPC ID. Their ID
is `null`. Content-Length is checked before authentication, and accepted bodies
are counted incrementally in UTF-8 bytes. Body deadlines include all chunks.
Invalid UTF-8/JSON returns 400; excessive bytes/structure returns 413; body or
operation deadline/disconnect returns 408. Cancellation closes the affected
session's transport correlations; clients reinitialize after losing a session.
No collection is silently truncated.

| Variable | Default | Meaning |
| --- | ---: | --- |
| `MCP_HTTP_MAX_BODY_BYTES` | 262144 | Streamed bytes, including whitespace |
| `MCP_HTTP_BODY_TIMEOUT_MS` | 10000 | Total body-read deadline |
| `MCP_HTTP_REQUEST_TIMEOUT_MS` | 60000 | Factory/operation/response deadline |
| `MCP_HTTP_STREAM_TIMEOUT_MS` | 60000 | Standalone SSE lifetime; reconnect normally |
| `MCP_TOOL_MAX_ELEMENTS` | 4096 | Array elements plus object members |
| `MCP_TOOL_MAX_ARRAY_LENGTH` | 1000 | Entries per tool input array |
| `MCP_TOOL_MAX_RECORD_KEYS` | 256 | Members per input object |
| `MCP_TOOL_MAX_DEPTH` | 16 | Nested containers |
| `MCP_TOOL_MAX_STRING_BYTES` | 65536 | UTF-8 bytes per string or key |

The HTTP structure budget includes the RPC envelope. Tool schemas also advertise
array/string limits, preserve existing stricter checks/defaults/descriptions, and
apply to STDIO as well. `McpServer.maxToolInputElements` is explicitly enabled
before tool-schema validation. The default supports staging/reset arrays of 1000
ordinary paths within the combined byte/string budget. Larger work must be split
into separate calls. A trusted STDIO client remains responsible for transport
message size; HTTP body limits are not a STDIO framing limit.

## Admission, fairness and cleanup

Admission uses an immediate-rejection queue of capacity zero: there is no pending
HTTP work queue. A full share returns 429 with Retry-After; a full identity table
returns 503. Counters have hard bounds and idle identity entries expire after a
minute. No live unrelated principal is evicted to admit another caller.

| Variable | Default |
| --- | ---: |
| `MCP_HTTP_MAX_REQUESTS` | 32 |
| `MCP_HTTP_MAX_REQUESTS_PER_PRINCIPAL` | 4 |
| `MCP_HTTP_MAX_INITIALIZATIONS` | 4 |
| `MCP_HTTP_MAX_SESSIONS` | 128 |
| `MCP_HTTP_MAX_SESSIONS_PER_PRINCIPAL` | 8 |
| `MCP_HTTP_MAX_STREAMS` | 16 |
| `MCP_HTTP_MAX_STREAMS_PER_PRINCIPAL` | 2 |
| `MCP_HTTP_REQUESTS_PER_MINUTE` | 120 |
| `MCP_HTTP_MAX_PRINCIPALS` | 1024 |

Per-principal shares must be below global caps. One principal has at most one
pending initialization. Session caps include pending factories. Invalid
sessionless messages allocate no server. Failed and expired allocations close
their servers/transports; DELETE and shutdown release resources. A timed-out
factory retains its reserved capacity until it settles and closes. Failed cleanup
retains capacity rather than allowing overcommit.

HTTP requests and active tool work have separate bounded accounting. Actual tool
work retains its slot until its promise settles, including after client
cancellation. HTTP disconnect/deadline sends the SDK cancellation notification;
native process termination still depends on the Git execution policy and signal
propagation. Request, session and SSE counts complement OS process/memory limits.

`httpPrincipalKey()` is the identity adapter for admission. Only authenticated
middleware context supplies its tuple; no token, caller header, body field or
forwarded address is an admission identity. All anonymous clients share one
budget. This HTTP foundation does not itself add tenant repository ACLs or session
owner authorization. Deployments requiring those properties also need the auth
and session isolation remediation in the dependent security stack.

## Locked runtime dependencies

The tested security floors are SDK 1.32.2, Zod 4.6.6, Hono 4.13.16 and node-server
2.1.6. Overrides also constrain their transitive copies. Additional bundled or
external runtime patches pin grpc-js 1.14.5, fast-uri 3.1.9, systeminformation
5.33.16 and fast-copy 4.1.0. The project toolchain pin is Bun 1.4.3.

SDK upgrades alone do not enable collection limits, and dependency placement in
devDependencies does not imply exclusion from the production bundle. The HTTP
parser, enabled SDK option, domain budgets and lock updates ship together.
Dependency scan findings from development tools still require explicit
dispositions; this document does not declare the entire dependency graph clean.

Primary security references:

- [SDK collection amplification and required opt-in](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-46jr-4wx8-v453)
- [SDK body/batch parsing](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-f897-62hf-6gxq)
- [Zod constrained collection amplification](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5)
- [Hono wildcard middleware](https://github.com/honojs/hono/security/advisories/GHSA-h7mg-cq63-vhpq)
- [Node adapter path normalization](https://github.com/honojs/node-server/security/advisories/GHSA-jpvv-r467-5p4w)
