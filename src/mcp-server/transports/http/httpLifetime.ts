/**
 * @fileoverview HTTP cancellation and response-stream lifetime ownership.
 * @module mcp-server/transports/http/httpLifetime
 */
import type { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { HttpLimitError } from './httpSecurity.js';
import type { AdmissionRelease } from './httpAdmission.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

/** Keep pending factory capacity reserved after timeout until late construction is closed. */
export async function createServerWithinDeadline(
  factory: () => Promise<McpServer>,
  request: Request,
  timeoutMs: number,
  abandoned: () => void,
  releaseAbandoned: () => void,
): Promise<McpServer> {
  let expired = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let abort: (() => void) | undefined;
  const pending = factory();
  void pending
    .then(
      async (server) => {
        if (expired) {
          await server.close();
          releaseAbandoned();
        }
      },
      () => {
        if (expired) releaseAbandoned();
      },
    )
    .catch(() => {
      // Failed late cleanup keeps capacity reserved, rather than overcommitting.
    });
  const deadline = new Promise<never>((_, reject) => {
    abort = () => {
      expired = true;
      abandoned();
      reject(new HttpLimitError(408, 'Initialization deadline or disconnect.'));
    };
    timer = setTimeout(abort, timeoutMs);
    request.signal.addEventListener('abort', abort, { once: true });
    if (request.signal.aborted) abort();
  });
  try {
    return await Promise.race([pending, deadline]);
  } finally {
    clearTimeout(timer);
    if (abort) request.signal.removeEventListener('abort', abort);
  }
}

/** Translate HTTP disconnect/deadline into the SDK's supported cancellation notification. */
export async function dispatchWithDeadline(
  transport: WebStandardStreamableHTTPServerTransport,
  request: Request,
  body: unknown,
  timeoutMs: number,
): Promise<Response> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let abort: (() => void) | undefined;
  const expired = new Promise<never>((_, reject) => {
    abort = () => {
      if (
        body &&
        typeof body === 'object' &&
        'id' in body &&
        (typeof body.id === 'number' || typeof body.id === 'string')
      ) {
        transport.onmessage?.({
          jsonrpc: '2.0',
          method: 'notifications/cancelled',
          params: { requestId: body.id, reason: 'HTTP request ended' },
        });
      }
      reject(new HttpLimitError(408, 'HTTP operation deadline or disconnect.'));
    };
    timer = setTimeout(abort, timeoutMs);
    request.signal.addEventListener('abort', abort, { once: true });
  });
  try {
    if (request.signal.aborted)
      throw new HttpLimitError(408, 'Request aborted.');
    return await Promise.race([
      transport.handleRequest(request, { parsedBody: body }),
      expired,
    ]);
  } finally {
    clearTimeout(timer);
    if (abort) request.signal.removeEventListener('abort', abort);
  }
}

/** Hold a lease until consumption, cancellation, disconnect or a hard stream deadline. */
export function boundResponseLifetime(
  response: Response,
  release: AdmissionRelease,
  timeoutMs: number,
  signal: AbortSignal,
): Response {
  if (!response.body) {
    release();
    return response;
  }
  const reader =
    response.body.getReader() as ReadableStreamDefaultReader<Uint8Array>;
  let controller: ReadableStreamDefaultController<Uint8Array>;
  let done = false;
  let timer: ReturnType<typeof setTimeout>;
  const finish = () => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    signal.removeEventListener('abort', abort);
    release();
  };
  const abort = () => {
    if (done) return;
    finish();
    void reader.cancel().catch(() => {});
    controller.error(new HttpLimitError(408, 'Response lifetime exceeded.'));
  };
  const stream = new ReadableStream<Uint8Array>({
    start(value) {
      controller = value;
      timer = setTimeout(abort, timeoutMs);
      signal.addEventListener('abort', abort, { once: true });
      if (signal.aborted) abort();
    },
    async pull(value) {
      try {
        const chunk = await reader.read();
        if (done) return;
        if (chunk.done) {
          finish();
          reader.releaseLock();
          value.close();
        } else value.enqueue(chunk.value);
      } catch (error) {
        finish();
        value.error(error);
      }
    },
    async cancel() {
      finish();
      await reader.cancel();
      reader.releaseLock();
    },
  });
  return new Response(stream, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}
