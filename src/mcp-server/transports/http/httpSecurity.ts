/**
 * @fileoverview Validated HTTP and tool-input budgets shared by admission and schemas.
 * @module mcp-server/transports/http/httpSecurity
 */
import { z } from 'zod';

const limit = (value: number, maximum: number, description: string) =>
  z.coerce
    .number()
    .int()
    .min(1)
    .max(maximum)
    .default(value)
    .describe(description);

/** Limits apply before SDK or domain schema validation. Units are UTF-8 bytes. */
export const ToolInputLimitsSchema = z
  .object({
    maxElements: limit(
      4096,
      65536,
      'Combined array elements and object members.',
    ),
    maxArrayLength: limit(1000, 10000, 'Maximum entries per tool array.'),
    maxRecordKeys: limit(256, 4096, 'Maximum members per object.'),
    maxDepth: limit(16, 64, 'Maximum nested containers.'),
    maxStringBytes: limit(
      65536,
      1048576,
      'Maximum UTF-8 bytes per string or key.',
    ),
  })
  .describe('Tool input complexity budgets.');

/** Exact authority entries include ports; no wildcard or forwarded-header trust. */
export const HttpSecuritySchema = z
  .object({
    allowedHosts: z
      .array(
        z
          .string()
          .max(253)
          .refine((host) => {
            try {
              const url = new URL(`http://${host}`);
              return (
                !host.includes('*') &&
                url.host === host.toLowerCase() &&
                url.pathname === '/' &&
                !url.username &&
                !url.password
              );
            } catch {
              return false;
            }
          }, 'Expected exact host[:port], including brackets for IPv6.')
          .transform((host) => host.toLowerCase()),
      )
      .max(64)
      .default([])
      .describe(
        'Allowed Host authorities. Empty uses loopback authorities at MCP_HTTP_PORT.',
      ),
    allowNativeClients: z
      .union([
        z.boolean(),
        z.enum(['true', 'false']).transform((value) => value === 'true'),
      ])
      .default(true)
      .describe('Allow clients without Origin.'),
    maxBodyBytes: limit(262144, 4194304, 'Maximum streamed request bytes.'),
    bodyTimeoutMs: limit(10000, 60000, 'Total body-read deadline.'),
    requestTimeoutMs: limit(
      60000,
      300000,
      'Operation deadline, retained through response completion.',
    ),
    streamTimeoutMs: limit(60000, 300000, 'Maximum standalone SSE lifetime.'),
    maxRequests: limit(32, 1024, 'Global concurrent HTTP requests.'),
    maxRequestsPerPrincipal: limit(
      4,
      128,
      'Concurrent requests per verified principal.',
    ),
    maxInitializations: limit(4, 64, 'Concurrent initialization factories.'),
    maxSessions: limit(128, 4096, 'Global live and pending sessions.'),
    maxSessionsPerPrincipal: limit(
      8,
      256,
      'Live and pending sessions per principal.',
    ),
    maxStreams: limit(16, 256, 'Global open standalone SSE streams.'),
    maxStreamsPerPrincipal: limit(
      2,
      32,
      'Open standalone SSE streams per principal.',
    ),
    requestsPerMinute: limit(
      120,
      10000,
      'Per-principal admissions in a fixed one-minute window.',
    ),
    maxPrincipals: limit(
      1024,
      16384,
      'Bounded admission accounting slots; unknown callers rejected when full.',
    ),
  })
  .superRefine((value, ctx) => {
    for (const [per, total] of [
      ['maxRequestsPerPrincipal', 'maxRequests'],
      ['maxSessionsPerPrincipal', 'maxSessions'],
      ['maxStreamsPerPrincipal', 'maxStreams'],
    ] as const) {
      if (value[per] >= value[total])
        ctx.addIssue({
          code: 'custom',
          path: [per],
          message: `Must be below ${total} to reserve peer capacity.`,
        });
    }
  })
  .describe('HTTP trust, parsing and resource budgets.');

/** Validated HTTP security configuration. */
export type HttpSecurity = z.infer<typeof HttpSecuritySchema>;
/** Validated tool input complexity configuration. */
export type ToolInputLimits = z.infer<typeof ToolInputLimitsSchema>;

/** A bounded, public error; never contains client input. */
export class HttpLimitError extends Error {
  constructor(
    public readonly status: 400 | 403 | 408 | 413 | 429 | 503,
    message: string,
  ) {
    super(message);
  }
}

/** Reject untrusted authorities/origins before any body access or authentication. */
export function validateHttpPeer(
  request: Request,
  hosts: readonly string[],
  origins: readonly string[],
  allowNative: boolean,
): void {
  const host = request.headers.get('host');
  if (!host || !hosts.includes(host.toLowerCase()))
    throw new HttpLimitError(403, 'Host is not allowed.');
  const origin = request.headers.get('origin');
  if (
    origin === null
      ? !allowNative
      : origin === 'null' || !origins.includes(origin)
  )
    throw new HttpLimitError(403, 'Origin is not allowed.');
}

/** Iterative early traversal, with work bounded by the configured element cap. */
export function assertInputBudget(
  input: unknown,
  limits: ToolInputLimits,
): void {
  const pending = [{ value: input, depth: 0 }];
  const encoder = new TextEncoder();
  let elements = 0;
  while (pending.length) {
    const { value, depth } = pending.pop()!;
    if (
      typeof value === 'string' &&
      encoder.encode(value).byteLength > limits.maxStringBytes
    )
      throw new HttpLimitError(413, 'String byte limit exceeded.');
    if (value === null || typeof value !== 'object') continue;
    if (depth >= limits.maxDepth)
      throw new HttpLimitError(413, 'Input depth limit exceeded.');
    const keys = Object.keys(value);
    if (
      keys.length >
      (Array.isArray(value) ? limits.maxArrayLength : limits.maxRecordKeys)
    )
      throw new HttpLimitError(413, 'Collection limit exceeded.');
    elements += keys.length;
    if (elements > limits.maxElements)
      throw new HttpLimitError(413, 'Input element limit exceeded.');
    for (const key of keys) {
      if (encoder.encode(key).byteLength > limits.maxStringBytes)
        throw new HttpLimitError(413, 'Key byte limit exceeded.');
      pending.push({
        value: (value as Record<string, unknown>)[key],
        depth: depth + 1,
      });
    }
  }
}

/** Read at most maxBodyBytes; cancel slow, oversized or aborted streams. */
export async function readBoundedJson(
  request: Request,
  policy: HttpSecurity,
  limits: ToolInputLimits,
): Promise<unknown> {
  checkContentLength(request, policy.maxBodyBytes);
  const reader = request.body?.getReader() as
    ReadableStreamDefaultReader<Uint8Array> | undefined;
  if (!reader) throw new HttpLimitError(400, 'JSON body required.');
  let timer: ReturnType<typeof setTimeout> | undefined;
  let onAbort: (() => void) | undefined;
  const failure = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new HttpLimitError(408, 'Body read deadline exceeded.')),
      policy.bodyTimeoutMs,
    );
    onAbort = () => reject(new HttpLimitError(408, 'Request aborted.'));
    request.signal.addEventListener('abort', onAbort, { once: true });
    if (request.signal.aborted) onAbort();
  });
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const readBody = async (): Promise<string> => {
    let bytes = 0;
    let text = '';
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      if (bytes > policy.maxBodyBytes)
        throw new HttpLimitError(413, 'Request body byte limit exceeded.');
      text += decoder.decode(chunk.value, { stream: true });
    }
    text += decoder.decode();
    return text;
  };
  try {
    // A single race retains only one deadline subscription, regardless of chunks.
    // Cancellation below settles the outstanding read when the deadline wins.
    const text = await Promise.race([readBody(), failure]);
    // Bound nesting before JSON.parse, including objects that have few elements.
    let depth = 0;
    let quoted = false;
    let escaped = false;
    for (const char of text) {
      if (quoted) {
        if (escaped) escaped = false;
        else if (char === '\\') escaped = true;
        else if (char === '"') quoted = false;
      } else if (char === '"') quoted = true;
      else if (char === '{' || char === '[') {
        if (++depth > limits.maxDepth)
          throw new HttpLimitError(413, 'Input depth limit exceeded.');
      } else if (char === '}' || char === ']') depth--;
    }
    const body: unknown = JSON.parse(text);
    // Batching is deliberately unsupported; no per-message SDK allocation.
    if (Array.isArray(body))
      throw new HttpLimitError(400, 'JSON-RPC batches are not supported.');
    assertInputBudget(body, limits);
    return body;
  } catch (error) {
    void reader.cancel().catch(() => {});
    if (error instanceof HttpLimitError) throw error;
    throw new HttpLimitError(400, 'Invalid JSON body.');
  } finally {
    clearTimeout(timer);
    if (onAbort) request.signal.removeEventListener('abort', onAbort);
    reader.releaseLock();
  }
}

/** Content-Length is only an early check; streaming counters remain authoritative. */
export function checkContentLength(request: Request, maximum: number): void {
  const value = request.headers.get('content-length');
  if (value === null) return;
  if (!/^[0-9]+$/.test(value))
    throw new HttpLimitError(400, 'Invalid Content-Length.');
  if (Number(value) > maximum)
    throw new HttpLimitError(413, 'Request body byte limit exceeded.');
}
