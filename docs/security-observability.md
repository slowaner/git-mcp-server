# Security observability contract

The logger, error handler, tool performance wrapper and OpenTelemetry exporters
emit allowlisted operational metadata. Request payloads, commit messages,
repository text, token claims, credentials, raw session identifiers and exception
messages/stacks/causes are excluded. This policy also applies at debug level and
to interaction logging. Existing payload-debug settings do not enable raw data
at these sinks.

## Log fields and correlation

Log records contain a finite event (`operation`, `exception`, `denied`,
`interaction`, `suppressed`), a known tool operation or `internal`, an outcome,
numeric error codes when available, and bounded metrics. Arbitrary context
fields and supplied log message strings are omitted. Standard severity and
timestamp fields remain available.

Request, session, tenant, principal, repository and trace correlation fields use
domain-separated HMACs with a random process-local key. These identifiers are
stable within one server process and change after restart. The key is not
exported. Trace spans contain `audit.trace_correlation`, which matches the log's
`traceCorrelation` for that trace in the same process.

Consumers that previously indexed `requestId`, `sessionId`, `testId`, raw `msg`,
`err`, `input`, `auth` or arbitrary context properties must migrate to the safe
event, operation and correlation fields. Error details returned to an authorized
tool caller remain separate from the observability schema.

## Traces, metrics and diagnostics

Exported spans retain standard trace/span identifiers, timing, outcome and
allowlisted numeric metrics. Exception events, status message text, links,
tracestate, arbitrary attributes, instrumentation scope metadata and auto-detected
host/process resources are excluded. Tool names outside the known operation set
are represented as `internal_operation`.

The exported service name is `git-mcp-server`; arbitrary resource and scope
versions are omitted. The logger's version uses bounded version syntax.
Pino automatic log sending/correlation is disabled so it
cannot append fields around the logger boundary. Diagnostic console output uses
fixed, rate-limited event names on stderr; exporter URLs and failure details do
not become diagnostic messages.

Metrics export is restricted to `http.server.request.duration` and
`http.client.request.duration` explicit histograms from the server and the
HTTP/Undici instrumentation. Method (a fixed HTTP method set) and numeric
status (`100`–`599`) are the only request-derived metric dimensions. The SDK's
boolean `otel.metric.overflow` marker remains visible when its 2,000-series
cardinality limit aggregates further combinations. The SDK applies this policy
before aggregation so private hosts, routes, error names and identifiers cannot
create separate exported series. The export boundary reconstructs the resource,
scope, descriptor, timestamps and numeric histogram; extra fields and exemplars
are excluded. Unsupported streams are omitted; malformed known streams fail the
batch with a fixed diagnostic. Limits are 256 scopes, 256 streams per scope,
2,000 points per stream and 64 bucket boundaries. An export failure does not
produce a partial or truncated result.

Custom direct console writers or exporters outside these components must enforce
their own equivalent policy. A sink schema is not an authorization boundary and
does not make repository-provided instructions trustworthy.

## Payload-size metadata

Performance measurement never serializes or traverses object graphs to calculate
their size. Bounded primitive JSON values can have an exact UTF-8 byte count;
strings are inspected only up to 65,536 UTF-16 code units. Objects, arrays,
unsupported values and larger strings are explicitly unmeasured.

`inputSizeKnown` / `outputSizeKnown` in logs and
`mcp.tool.input_size_known` / `mcp.tool.output_size_known` in traces distinguish
measured values from unknown values. Unknown byte fields are omitted, not set to
zero. An absent tool payload has size zero. These values describe tool payload
metadata, not HTTP or JSON-RPC envelopes; they do not enforce a wire-size cap and
do not truncate tool results.

## Bounds, storage and retention

Local logging uses finite event/operation/outcome/severity keys, at most 256
counters, and a default threshold of ten events per key per minute. Expiry runs
on activity and on a periodic timer, including windows without suppression.
Suppression summaries contain only bounded counts; they do not retain original
messages or identifiers. Shutdown flushes remaining summaries and resets state.

New POSIX log directories use mode `0700` and new log files use `0600`.
Existing locations are not chmodded or deleted automatically. Operators own
their existing permissions, protected log destinations, access controls and
retention. No raw diagnostic dump is created on a sink failure.
