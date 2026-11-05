/**
 * @fileoverview Fail-closed Worker entrypoint for the unsupported Git CLI deployment.
 * @module src/mcp-server/transports/unsupportedWorker
 */

/**
 * Cloudflare Workers cannot provide this server's required local Git process and
 * filesystem isolation contract. Reject all routes without importing application
 * configuration, composing services or reading runtime bindings. This includes
 * health/discovery so a deployment cannot appear ready under an ignored auth mode.
 */
export const unsupportedWorker = Object.freeze({
  fetch(_request: Request, _bindings: unknown): Response {
    return Response.json(
      {
        error: 'Unsupported deployment profile',
        message:
          'Git CLI deployments require the supported Node.js or Bun server. Cloudflare Worker startup is disabled.',
      },
      {
        status: 503,
        headers: { 'Cache-Control': 'no-store' },
      },
    );
  },
});
