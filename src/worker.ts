/**
 * @fileoverview Fail-closed entrypoint for the unsupported Cloudflare Worker profile.
 * Git CLI execution requires the supported Node.js or Bun server. No application
 * config, bindings, container or transport is initialized in the Worker profile.
 * @module src/worker
 */
export { unsupportedWorker as default } from '@/mcp-server/transports/unsupportedWorker.js';
