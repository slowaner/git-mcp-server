/**
 * @fileoverview Configures and starts the HTTP MCP transport using Hono.
 * This implementation uses the official @hono/mcp package for a fully
 * web-standard, platform-agnostic transport layer.
 *
 * Architecture: Each MCP session gets its own McpServer + StreamableHTTPTransport
 * pair. The StreamableHTTPTransport manages session IDs, protocol version
 * validation, and SSE streams internally. A per-session server map ensures
 * Protocol instances are never shared across connections.
 *
 * Implements MCP Specification 2025-06-18 Streamable HTTP Transport.
 * @see {@link https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http | MCP Streamable HTTP Transport}
 * @module src/mcp-server/transports/http/httpTransport
 */
import { WebStandardStreamableHTTPServerTransport as StreamableHTTPTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { type ServerType, serve } from '@hono/node-server';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import http from 'http';
import { randomUUID } from 'node:crypto';
import { HttpAdmission } from './httpAdmission.js';
import {
  checkContentLength,
  HttpLimitError,
  readBoundedJson,
  validateHttpPeer,
} from './httpSecurity.js';
import {
  boundResponseLifetime,
  createServerWithinDeadline,
  dispatchWithDeadline,
} from './httpLifetime.js';
import { httpPrincipalKey } from './httpPrincipal.js';

import { config } from '@/config/index.js';
import {
  authContext,
  createAuthMiddleware,
  createAuthStrategy,
} from '@/mcp-server/transports/auth/index.js';
import { httpErrorHandler } from '@/mcp-server/transports/http/httpErrorHandler.js';
import { SessionManager } from '@/mcp-server/transports/http/sessionManager.js';
import type { HonoNodeBindings } from '@/mcp-server/transports/http/httpTypes.js';
import {
  type RequestContext,
  logger,
  logStartupBanner,
} from '@/utils/index.js';

/** Factory function that creates a fully-configured McpServer instance. */
export type McpServerFactory = () => Promise<McpServer>;
const appManagers = new WeakMap<
  Hono<{ Bindings: HonoNodeBindings }>,
  SessionManager
>();
const serverManagers = new WeakMap<ServerType, SessionManager>();
const appDisposers = new WeakMap<
  Hono<{ Bindings: HonoNodeBindings }>,
  () => Promise<void>
>();
const serverApps = new WeakMap<
  ServerType,
  Hono<{ Bindings: HonoNodeBindings }>
>();
const defaultAppHosts = new WeakMap<
  Hono<{ Bindings: HonoNodeBindings }>,
  string[]
>();
const loopbackAuthorities = (port: number) =>
  ['localhost', '127.0.0.1', '[::1]'].map(
    (host) => new URL(`http://${host}:${port}`).host,
  );

/** Close every per-app session and timer; used by shutdown and embedded hosts. */
export async function closeHttpApp(
  app: Hono<{ Bindings: HonoNodeBindings }>,
): Promise<void> {
  await appDisposers.get(app)?.();
}

/** Compose an isolated HTTP app with rejecting peer checks and bounded admission. */
export function createHttpApp(
  createMcpServer: McpServerFactory,
  parentContext: RequestContext,
): Hono<{ Bindings: HonoNodeBindings }> {
  const app = new Hono<{ Bindings: HonoNodeBindings }>();
  const transportContext = {
    ...parentContext,
    component: 'HttpTransportSetup',
  };

  // Per-session transport map. Each session gets its own McpServer + Transport pair
  // because Protocol maintains a 1:1 relationship with its transport.
  const transports = new Map<string, StreamableHTTPTransport>();
  const servers = new Map<string, McpServer>();
  const sessionReleases = new Map<string, () => void>();
  const admission = new HttpAdmission(config.httpSecurity);
  const policy = config.httpSecurity;
  const hosts = policy.allowedHosts.length
    ? policy.allowedHosts
    : loopbackAuthorities(config.mcpHttpPort);
  if (!policy.allowedHosts.length) defaultAppHosts.set(app, hosts);
  const principal = httpPrincipalKey;
  let closing = false;
  const cleanupTasks = new Map<string, Promise<void>>();
  const cleanup = (sid: string): Promise<void> => {
    const existing = cleanupTasks.get(sid);
    if (existing) return existing;
    const pending = (async () => {
      const transport = transports.get(sid);
      const server = servers.get(sid);
      transports.delete(sid);
      servers.delete(sid);
      sessionManager.terminateSession(sid);
      // Release only after close completes; failed close must not open new capacity.
      try {
        await server?.close();
        await transport?.close();
        sessionReleases.get(sid)?.();
        sessionReleases.delete(sid);
      } catch {
        logger.warning('HTTP session cleanup failed', transportContext);
      }
    })();
    cleanupTasks.set(sid, pending);
    return pending.finally(() => cleanupTasks.delete(sid));
  };

  // Initialize SessionManager with configurable timeout and transport cleanup
  const sessionManager = new SessionManager(
    config.mcpStatefulSessionStaleTimeoutMs,
    Math.min(60000, config.mcpStatefulSessionStaleTimeoutMs),
  );
  appManagers.set(app, sessionManager);
  appDisposers.set(app, async () => {
    closing = true;
    sessionManager.stopCleanupInterval();
    await Promise.all([...transports.keys()].map(cleanup));
    await Promise.all(cleanupTasks.values());
  });
  sessionManager.onSessionExpired = (sessionId: string) => {
    void cleanup(sessionId);
  };
  logger.info('Session manager initialized', {
    ...transportContext,
    staleTimeoutMs: config.mcpStatefulSessionStaleTimeoutMs,
  });

  // CORS configuration
  const explicitOrigins = config.mcpAllowedOrigins;
  const allowedOrigin = explicitOrigins ?? [];

  let ingress = 0;
  // First middleware: ignore all forwarded headers; Host and Origin are direct.
  app.use('*', async (c, next) => {
    try {
      validateHttpPeer(
        c.req.raw,
        hosts,
        allowedOrigin,
        policy.allowNativeClients,
      );
      checkContentLength(c.req.raw, policy.maxBodyBytes);
      if (ingress >= policy.maxRequests)
        throw new HttpLimitError(429, 'HTTP ingress capacity reached.');
      ingress++;
      try {
        await next();
      } finally {
        ingress--;
      }
      return;
    } catch (error) {
      if (!(error instanceof HttpLimitError)) throw error;
      return c.json(
        {
          jsonrpc: '2.0',
          error: { code: -32000, message: error.message },
          id: null,
        },
        error.status,
      );
    }
  });

  app.use(
    '*',
    cors({
      origin: allowedOrigin,
      allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
      allowHeaders: [
        'Content-Type',
        'Authorization',
        'Mcp-Session-Id',
        'MCP-Protocol-Version',
      ],
      exposeHeaders: ['Mcp-Session-Id'],
      credentials: false,
    }),
  );

  // Centralized error handling
  app.onError(httpErrorHandler);

  // Health check — unprotected
  app.get('/healthz', (c) => c.json({ status: 'ok' }));

  // RFC 9728 Protected Resource Metadata endpoint (MCP 2025-06-18)
  // Must be accessible without authentication for discovery
  app.get('/.well-known/oauth-protected-resource', (c) => {
    if (!config.oauthIssuerUrl) {
      return c.json(
        { error: 'OAuth not configured on this server' },
        { status: 404 },
      );
    }

    return c.json({
      resource: config.mcpServerResourceIdentifier || config.oauthAudience,
      authorization_servers: [config.oauthIssuerUrl],
      bearer_methods_supported: ['header'],
      resource_signing_alg_values_supported: ['RS256', 'ES256', 'PS256'],
      ...(config.oauthJwksUri && { jwks_uri: config.oauthJwksUri }),
    });
  });

  // Create auth strategy and middleware if auth is enabled
  const authStrategy = createAuthStrategy();
  if (authStrategy) {
    const authMiddleware = createAuthMiddleware(authStrategy);
    app.use(config.mcpHttpEndpointPath, authMiddleware);
    logger.info(
      'Authentication middleware enabled for MCP endpoint.',
      transportContext,
    );
  } else {
    logger.info(
      'Authentication is disabled; MCP endpoint is unprotected.',
      transportContext,
    );
  }

  // No queue: admission fails immediately. Leases persist through response streams.
  app.use(config.mcpHttpEndpointPath, async (c, next) => {
    if (closing) throw new HttpLimitError(503, 'HTTP app is closing.');
    const release = admission.acquire('requests', principal());
    try {
      await next();
      c.res = boundResponseLifetime(
        c.res,
        release,
        policy.requestTimeoutMs,
        c.req.raw.signal,
      );
    } catch (error) {
      release();
      throw error;
    }
  });

  // Helper: look up a transport for an existing session, returning a 404 JSON-RPC
  // error response if not found or expired.
  const getSessionTransport = (
    sessionId: string,
  ): StreamableHTTPTransport | Response => {
    if (!sessionManager.isSessionValid(sessionId)) {
      // Clean up stale transport if it exists
      const stale = transports.get(sessionId);
      if (stale) {
        void cleanup(sessionId);
      }
      return Response.json(
        {
          jsonrpc: '2.0',
          error: {
            code: -32001,
            message: 'Session expired or invalid. Please reinitialize.',
          },
          id: null,
        },
        { status: 404 },
      );
    }
    const transport = transports.get(sessionId);
    if (!transport) {
      return Response.json(
        {
          jsonrpc: '2.0',
          error: {
            code: -32001,
            message: 'Session not found. Please reinitialize.',
          },
          id: null,
        },
        { status: 404 },
      );
    }
    sessionManager.touchSession(sessionId);
    return transport;
  };

  // GET /mcp — status page (no session) or SSE stream (with session)
  app.get(config.mcpHttpEndpointPath, async (c) => {
    const sessionId = c.req.header('mcp-session-id');

    // No session ID = server info / status page
    if (!sessionId) {
      return c.json({
        status: 'ok',
        server: {
          name: config.mcpServerName,
          version: config.mcpServerVersion,
          description: config.mcpServerDescription,
          transport: config.mcpTransportType,
          sessionMode: config.mcpSessionMode,
        },
      });
    }

    // With session ID = SSE stream request — delegate to transport
    const transportOrError = getSessionTransport(sessionId);
    if (transportOrError instanceof Response) return transportOrError;

    const release = admission.acquire('streams', principal());
    try {
      const response = await transportOrError.handleRequest(c.req.raw);
      return boundResponseLifetime(
        response,
        release,
        policy.streamTimeoutMs,
        c.req.raw.signal,
      );
    } catch (error) {
      release();
      throw error;
    }
  });

  // DELETE /mcp — session termination (MCP Spec 2025-06-18)
  app.delete(config.mcpHttpEndpointPath, async (c) => {
    const sessionId = c.req.header('mcp-session-id');

    if (!sessionId) {
      return c.json(
        {
          jsonrpc: '2.0',
          error: {
            code: -32600,
            message: 'Mcp-Session-Id header required for DELETE',
          },
          id: null,
        },
        400,
      );
    }

    const transport = transports.get(sessionId);
    if (!transport) {
      return c.json(
        {
          jsonrpc: '2.0',
          error: {
            code: -32001,
            message: 'Session not found or already expired',
          },
          id: null,
        },
        404,
      );
    }

    // Delegate to transport's internal DELETE handling (closes streams)
    const response = await transport.handleRequest(c.req.raw);

    // Clean up our maps
    await cleanup(sessionId);

    logger.info('Session terminated via DELETE', {
      ...transportContext,
      sessionId,
    });

    return response ?? c.body(null, 204);
  });

  // POST /mcp — JSON-RPC over Streamable HTTP
  // Protocol version validation is handled by StreamableHTTPTransport internally
  // using the SDK's SUPPORTED_PROTOCOL_VERSIONS (includes 2025-11-25, 2025-06-18, etc.)
  app.post(config.mcpHttpEndpointPath, async (c) => {
    logger.debug('Handling MCP POST request.', {
      ...transportContext,
      path: c.req.path,
    });

    const sessionId = c.req.header('mcp-session-id');
    const body = await readBoundedJson(
      c.req.raw,
      policy,
      config.toolInputLimits,
    );

    const handleRequest = async (): Promise<Response> => {
      // Existing session — delegate to stored transport
      if (sessionId) {
        const transportOrError = getSessionTransport(sessionId);
        if (transportOrError instanceof Response) return transportOrError;

        try {
          return await dispatchWithDeadline(
            transportOrError,
            c.req.raw,
            body,
            policy.requestTimeoutMs,
          );
        } catch (error) {
          // Close cancelled transport correlations; reconnect requires initialization.
          if (error instanceof HttpLimitError && error.status === 408)
            await cleanup(sessionId);
          throw error;
        }
      }

      // New session — create per-session McpServer + Transport pair.
      // Each Protocol instance supports exactly one transport connection.
      // Validate the full initialization envelope before allocating server/transport.
      const { isInitializeRequest, InitializeRequestSchema } =
        await import('@modelcontextprotocol/sdk/types.js');
      if (
        !isInitializeRequest(body) ||
        !InitializeRequestSchema.safeParse(body).success
      ) {
        throw new HttpLimitError(
          400,
          'A valid initialize request is required.',
        );
      }
      const releaseInit = admission.acquire('initializations', principal());
      let releaseSession: (() => void) | undefined;
      let server: McpServer | undefined;
      let initialized: string | undefined;
      let transport: StreamableHTTPTransport | undefined;
      let abandonedFactory = false;
      try {
        releaseSession = admission.acquire('sessions', principal());
        server = await createServerWithinDeadline(
          createMcpServer,
          c.req.raw,
          policy.requestTimeoutMs,
          () => {
            abandonedFactory = true;
          },
          () => {
            releaseSession?.();
            releaseInit();
          },
        );
        if (closing) throw new HttpLimitError(503, 'HTTP app is closing.');
        const activeServer = server;
        transport = new StreamableHTTPTransport({
          enableJsonResponse: true,
          maxRequestBodySize: policy.maxBodyBytes,
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (sid: string) => {
            initialized = sid;
            transports.set(sid, transport!);
            servers.set(sid, activeServer);
            sessionReleases.set(sid, releaseSession!);
            const store = authContext.getStore();
            sessionManager.createSession(
              sid,
              store?.authInfo.clientId,
              store?.authInfo.tenantId,
            );
            logger.debug('New MCP session initialized', {
              ...transportContext,
              sessionId: sid,
            });
          },
          onsessionclosed: (sid: string) => {
            void cleanup(sid);
            logger.debug('MCP session closed via transport', {
              ...transportContext,
              sessionId: sid,
            });
          },
        });

        await server.connect(transport);
        const response = await dispatchWithDeadline(
          transport,
          c.req.raw,
          body,
          policy.requestTimeoutMs,
        );
        if (!initialized || response.status >= 400) {
          if (initialized) await cleanup(initialized);
          else {
            await server.close();
            await transport.close();
            releaseSession();
          }
        }
        return response;
      } catch (error) {
        if (initialized) await cleanup(initialized);
        else if (!abandonedFactory) {
          await server?.close();
          await transport?.close();
          releaseSession?.();
        }
        throw error;
      } finally {
        if (!abandonedFactory) releaseInit();
      }
    };

    try {
      // Preserve auth context through the async handler
      const store = authContext.getStore();
      if (store) {
        return await authContext.run(store, handleRequest);
      }
      return await handleRequest();
    } catch (err) {
      throw err instanceof Error ? err : new Error(String(err));
    }
  });

  logger.info('Hono application setup complete.', transportContext);
  return app;
}

async function isPortInUse(
  port: number,
  host: string,
  parentContext: RequestContext,
): Promise<boolean> {
  const context = { ...parentContext, operation: 'isPortInUse', port, host };
  logger.debug(`Checking if port ${port} is in use...`, context);
  return new Promise((resolve) => {
    const tempServer = http.createServer();
    tempServer
      .once('error', (err: NodeJS.ErrnoException) =>
        resolve(err.code === 'EADDRINUSE'),
      )
      .once('listening', () => tempServer.close(() => resolve(false)))
      .listen(port, host);
  });
}

function startHttpServerWithRetry(
  app: Hono<{ Bindings: HonoNodeBindings }>,
  initialPort: number,
  host: string,
  maxRetries: number,
  parentContext: RequestContext,
): Promise<ServerType> {
  const startContext = {
    ...parentContext,
    operation: 'startHttpServerWithRetry',
  };
  logger.info(
    `Attempting to start HTTP server on port ${initialPort} with ${maxRetries} retries.`,
    startContext,
  );

  return new Promise((resolve, reject) => {
    const tryBind = (port: number, attempt: number) => {
      if (attempt > maxRetries + 1) {
        const error = new Error(
          `Failed to bind to any port after ${maxRetries} retries.`,
        );
        logger.fatal(error.message, { ...startContext, port, attempt });
        return reject(error);
      }

      isPortInUse(port, host, { ...startContext, port, attempt })
        .then((inUse) => {
          if (inUse) {
            logger.warning(`Port ${port} is in use, retrying...`, {
              ...startContext,
              port,
              attempt,
            });
            setTimeout(
              () => tryBind(port + 1, attempt + 1),
              config.mcpHttpPortRetryDelayMs,
            );
            return;
          }

          try {
            const serverInstance = serve(
              { fetch: app.fetch, port, hostname: host },
              (info) => {
                const serverAddress = `http://${info.address}:${info.port}${config.mcpHttpEndpointPath}`;
                logger.info(`HTTP transport listening at ${serverAddress}`, {
                  ...startContext,
                  port,
                  address: serverAddress,
                });
                logStartupBanner(
                  `\n🚀 MCP Server running at: ${serverAddress}`,
                  'http',
                );
                // Default authorities follow the actual bound retry port.
                const defaults = defaultAppHosts.get(app);
                if (defaults)
                  defaults.splice(
                    0,
                    defaults.length,
                    ...loopbackAuthorities(info.port),
                  );
                resolve(serverInstance);
              },
            );
          } catch (err: unknown) {
            logger.warning(
              `Binding attempt failed for port ${port}, retrying...`,
              { ...startContext, port, attempt, error: String(err) },
            );
            setTimeout(
              () => tryBind(port + 1, attempt + 1),
              config.mcpHttpPortRetryDelayMs,
            );
          }
        })
        .catch((err) =>
          reject(err instanceof Error ? err : new Error(String(err))),
        );
    };

    tryBind(initialPort, 1);
  });
}

export async function startHttpTransport(
  createMcpServer: McpServerFactory,
  parentContext: RequestContext,
): Promise<ServerType> {
  const transportContext = {
    ...parentContext,
    component: 'HttpTransportStart',
  };
  logger.info('Starting HTTP transport.', transportContext);

  const app = createHttpApp(createMcpServer, transportContext);

  const server = await startHttpServerWithRetry(
    app,
    config.mcpHttpPort,
    config.mcpHttpHost,
    config.mcpHttpMaxPortRetries,
    transportContext,
  );
  // serve() uses HTTP/1 here; guard the adapter's broader HTTP/2 union type.
  if (server instanceof http.Server) {
    server.requestTimeout = config.httpSecurity.bodyTimeoutMs;
    server.headersTimeout = Math.min(config.httpSecurity.bodyTimeoutMs, 60000);
    server.setTimeout(config.httpSecurity.requestTimeoutMs, (socket) =>
      socket.destroy(),
    );
  }
  server.maxConnections =
    config.httpSecurity.maxRequests + config.httpSecurity.maxStreams;
  serverManagers.set(server, appManagers.get(app)!);
  serverApps.set(server, app);

  logger.info('HTTP transport started successfully.', transportContext);
  return server;
}

export async function stopHttpTransport(
  server: ServerType,
  parentContext: RequestContext,
): Promise<void> {
  const operationContext = {
    ...parentContext,
    operation: 'stopHttpTransport',
    transportType: 'Http',
  };
  logger.info('Attempting to stop http transport...', operationContext);

  // Stop session cleanup interval
  const sessionManager = serverManagers.get(server);
  sessionManager?.stopCleanupInterval();
  const app = serverApps.get(server);
  if (app) await closeHttpApp(app);
  logger.info('Session cleanup interval stopped', operationContext);

  return new Promise((resolve, reject) => {
    server.close((err) => {
      if (err) {
        logger.error('Error closing HTTP server.', err, operationContext);
        return reject(err);
      }
      logger.info('HTTP server closed successfully.', operationContext);
      resolve();
    });
  });
}
