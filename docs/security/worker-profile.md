# Cloudflare Worker profile

The Cloudflare Worker deployment is disabled. Every HTTP method and route,
including `/healthz`, `/mcp` and OAuth discovery, returns HTTP 503 with
`Unsupported deployment profile`. The entrypoint does not read bindings, import
application configuration, initialize dependency injection, create a server or
cache an application between requests. Scheduled application work is unavailable.

Use the supported Node.js or Bun server for Git CLI operations. Configure its
authentication and repository policy explicitly before exposing HTTP access.
This change does not provision or deploy either server.

The former experimental Worker entrypoint imported application configuration
before runtime bindings were applied and cached services across requests. Binding
injection cannot establish the local Git process and filesystem boundary required
by this server. Returning a healthy status under that composition would imply
support that has not been established. Auth mode, secrets or storage bindings do
not opt the Worker profile back in.

Re-enabling a Worker deployment requires a supported Git execution provider and
configuration composed from validated bindings before service imports, with
independent authentication, tenant, storage and isolation acceptance evidence.
The current refusal is a compatibility change to the experimental deployment;
it is not proof of a working Cloudflare sandbox or deployed backend permissions.
