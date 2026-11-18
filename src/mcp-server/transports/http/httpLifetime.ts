/**
 * @fileoverview HTTP cancellation and response-stream lifetime ownership.
 * @module mcp-server/transports/http/httpLifetime
 */
import { randomUUID } from 'node:crypto';
import type { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import {
  CancelledNotificationSchema,
  isJSONRPCRequest,
  JSONRPCResponseSchema,
  type JSONRPCNotification,
  type RequestId,
} from '@modelcontextprotocol/sdk/types.js';
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

type HttpTransport = WebStandardStreamableHTTPServerTransport;
type PendingPost = {
  transportId: RequestId;
  cancelled?: Promise<boolean>;
};

const activePosts = new WeakMap<HttpTransport, Map<RequestId, PendingPost>>();

function pendingPosts(transport: HttpTransport): Map<RequestId, PendingPost> {
  let posts = activePosts.get(transport);
  if (!posts) {
    posts = new Map();
    activePosts.set(transport, posts);
  }
  return posts;
}

/** Free SDK response correlation after the SDK has accepted the cancellation. */
async function finishCancelledPost(
  transport: HttpTransport,
  post: PendingPost,
): Promise<void> {
  // The SDK settles a JSON POST only when send() supplies a response for its id.
  // This internal response is consumed below and is never sent to the client.
  post.cancelled ??= transport
    .send({
      jsonrpc: '2.0',
      id: post.transportId,
      error: { code: -32800, message: 'Request cancelled.' },
    })
    .then(
      () => true,
      () => false, // The request already completed or the transport closed.
    );
  await post.cancelled;
}

/** Separate explicit MCP cancellation from an HTTP deadline or disconnect. */
export async function dispatchWithDeadline(
  transport: HttpTransport,
  request: Request,
  body: unknown,
  timeoutMs: number,
): Promise<Response> {
  const posts = pendingPosts(transport);
  const rpc = isJSONRPCRequest(body) ? body : undefined;
  const requestId = rpc?.method === 'initialize' ? undefined : rpc?.id;
  const notification = CancelledNotificationSchema.safeParse(body).data;
  const cancelledId = notification?.params.requestId;
  const target = cancelledId === undefined ? undefined : posts.get(cancelledId);

  let post: PendingPost | undefined;
  let parsedBody = body;
  if (requestId !== undefined) {
    if (posts.has(requestId))
      throw new HttpLimitError(400, 'JSON-RPC request id is already in use.');
    // The SDK's cancellation handler ignores falsy ids, which JSON-RPC allows.
    post = { transportId: requestId || randomUUID() };
    posts.set(requestId, post);
    if (post.transportId !== requestId)
      parsedBody = { ...rpc, id: post.transportId };
  } else if (target && notification && target.transportId !== cancelledId) {
    parsedBody = {
      ...(body as JSONRPCNotification),
      params: { ...notification.params, requestId: target.transportId },
    };
  }

  let timer: ReturnType<typeof setTimeout> | undefined;
  let abort: (() => void) | undefined;
  const expired = new Promise<never>((_, reject) => {
    abort = () => {
      const id = post?.transportId ?? rpc?.id;
      if (id !== undefined) {
        transport.onmessage?.({
          jsonrpc: '2.0',
          method: 'notifications/cancelled',
          params: { requestId: id, reason: 'HTTP request ended' },
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
    const response = await Promise.race([
      transport.handleRequest(request, { parsedBody }),
      expired,
    ]);
    if (
      response.status === 202 &&
      cancelledId !== undefined &&
      target &&
      posts.get(cancelledId) === target
    ) {
      await finishCancelledPost(transport, target);
    }

    if (await post?.cancelled) {
      const headers = new Headers(response.headers);
      headers.set('content-type', 'text/event-stream');
      return new Response('', { headers });
    }
    if (post && post.transportId !== requestId && response.status === 200) {
      const message = JSONRPCResponseSchema.parse(await response.json());
      return Response.json(
        { ...message, id: requestId },
        { headers: response.headers },
      );
    }
    return response;
  } finally {
    clearTimeout(timer);
    if (abort) request.signal.removeEventListener('abort', abort);
    if (requestId !== undefined) posts.delete(requestId);
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
