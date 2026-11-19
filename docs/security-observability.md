# Security observability contract

The logger, error handler and tool performance wrapper emit allowlisted
operational metadata locally. Request payloads, commit messages,
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
stable within one server process and change after restart. The correlation key
stays in process memory.

Consumers that previously indexed `requestId`, `sessionId`, `testId`, raw `msg`,
`err`, `input`, `auth` or arbitrary context properties must migrate to the safe
event, operation and correlation fields. Error details returned to an authorized
tool caller remain separate from the observability schema.

## Local output

The standalone server writes structured logs locally. Pino automatic
OpenTelemetry integration is disabled. Embedded runtimes can attach their own
instrumentation through the OpenTelemetry API.

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
