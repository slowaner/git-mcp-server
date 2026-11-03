/**
 * @fileoverview Loads, validates, and exports application configuration.
 * This module centralizes configuration management, sourcing values from
 * environment variables. It uses Zod for schema validation to ensure type safety
 * and correctness of configuration parameters, and is designed to be
 * environment-agnostic (e.g., Node.js, Cloudflare Workers).
 *
 * @module src/config/index
 */
import { homedir } from 'os';
import { validateAuthenticationConfiguration } from '@/mcp-server/transports/auth/lib/authConfiguration.js';
import path from 'node:path';

import { z } from 'zod';

import packageJson from '../../package.json' with { type: 'json' };
import { JsonRpcErrorCode, McpError } from '../types-global/errors.js';
import {
  HttpSecuritySchema,
  ToolInputLimitsSchema,
} from '../mcp-server/transports/http/httpSecurity.js';

type PackageManifest = {
  name?: string;
  version?: string;
  description?: string;
};

const packageManifest = packageJson as PackageManifest;
// Authority comes only from the operator-prepared inherited environment.
// Never load configuration implicitly from a repository/current-directory file.

// --- Helper Functions ---
const emptyStringAsUndefined = (val: unknown) => {
  if (typeof val === 'string' && val.trim() === '') {
    return undefined;
  }
  return val;
};

/**
 * Parse a boolean from an env-var string, applying the given default when
 * unset. `z.coerce.boolean()` would treat the literal string "false" as
 * truthy — this helper handles the common string forms correctly so
 * `GIT_SIGN_COMMITS=false` actually opts out.
 */
const parseBoolEnv =
  (defaultValue: boolean) =>
  (val: unknown): boolean => {
    if (typeof val === 'boolean') return val;
    if (typeof val === 'string') {
      const lower = val.trim().toLowerCase();
      if (['true', '1', 'yes', 'on'].includes(lower)) return true;
      if (['false', '0', 'no', 'off', ''].includes(lower)) return false;
    }
    return defaultValue;
  };

/**
 * Expands tilde (~) in paths to the user's home directory.
 * Returns undefined for empty/undefined inputs.
 * Supports both ~/path (expands to homedir/path) and ~ alone (expands to homedir).
 *
 * @param path - Path that may contain tilde prefix
 * @returns Expanded absolute path or undefined
 *
 * @example
 * expandTildePath('~/Developer/') // '/Users/username/Developer/'
 * expandTildePath('~') // '/Users/username'
 * expandTildePath('/absolute/path') // '/absolute/path' (unchanged)
 * expandTildePath('') // undefined
 */
const expandTildePath = (path: unknown): string | undefined => {
  if (typeof path !== 'string' || path.trim() === '') {
    return undefined;
  }

  const trimmed = path.trim();

  // Expand ~/path to homedir/path
  if (trimmed.startsWith('~/')) {
    return `${homedir()}${trimmed.slice(1)}`;
  }

  // Expand ~ alone to homedir
  if (trimmed === '~') {
    return homedir();
  }

  // Return as-is (already absolute or relative)
  return trimmed;
};

/**
 * Cross-platform check for absolute paths.
 * Uses Node's path.isAbsolute which handles:
 * - POSIX: /home/user, /var/www
 * - Windows: C:\Users, D:\Projects, C:/Users
 * - UNC: \\server\share
 *
 * @param p - Path to check
 * @returns true if path is absolute on the current platform
 */
const isAbsolutePath = (p: string): boolean => {
  if (!p) return false;
  return path.isAbsolute(p);
};

// --- Schema Definition ---
const ConfigSchema = z.object({
  // Package information sourced from environment variables
  pkg: z.object({
    name: z.string(),
    version: z.string(),
    description: z.string().optional(),
  }),
  mcpServerName: z.string(), // Will be derived from pkg.name
  mcpServerVersion: z.string(), // Will be derived from pkg.version
  mcpServerDescription: z.string().optional(), // Will be derived from pkg.description
  logLevel: z
    .preprocess(
      (val) => {
        const str = emptyStringAsUndefined(val);
        if (typeof str === 'string') {
          const lower = str.toLowerCase();
          const aliasMap: Record<string, string> = {
            warning: 'warn',
            err: 'error',
            information: 'info',
          };
          return aliasMap[lower] ?? lower;
        }
        return str;
      },
      z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']),
    )
    .default('debug'),
  logsPath: z.preprocess(expandTildePath, z.string().optional()), // Made optional as it's Node-specific
  environment: z
    .preprocess(
      (val) => {
        const str = emptyStringAsUndefined(val);
        if (typeof str === 'string') {
          const lower = str.toLowerCase();
          const aliasMap: Record<string, string> = {
            dev: 'development',
            prod: 'production',
            test: 'testing',
          };
          return aliasMap[lower] ?? lower;
        }
        return str;
      },
      z.enum(['development', 'production', 'testing']),
    )
    .default('development'),
  mcpTransportType: z.preprocess(
    emptyStringAsUndefined,
    z.enum(['stdio', 'http']).default('stdio'),
  ),
  mcpSessionMode: z.preprocess(
    emptyStringAsUndefined,
    z.enum(['stateless', 'stateful', 'auto']).default('auto'),
  ),
  mcpResponseFormat: z.preprocess(
    emptyStringAsUndefined,
    z.enum(['json', 'markdown', 'auto']).default('json'),
  ),
  mcpResponseVerbosity: z.preprocess(
    emptyStringAsUndefined,
    z.enum(['minimal', 'standard', 'full']).default('standard'),
  ),
  mcpHttpPort: z.coerce.number().int().min(1).max(65535).default(3015),
  mcpHttpHost: z.string().default('127.0.0.1'),
  mcpHttpEndpointPath: z.string().default('/mcp'),
  mcpHttpMaxPortRetries: z.coerce.number().default(15),
  mcpHttpPortRetryDelayMs: z.coerce.number().default(50),
  mcpStatefulSessionStaleTimeoutMs: z.coerce
    .number()
    .int()
    .min(1)
    .max(86400000)
    .default(1_800_000),
  mcpAllowedOrigins: z
    .array(
      z.string().refine((origin) => {
        try {
          const url = new URL(origin);
          return (
            ['http:', 'https:'].includes(url.protocol) && url.origin === origin
          );
        } catch {
          return false;
        }
      }, 'Expected an exact HTTP(S) origin, without wildcard, credentials or path.'),
    )
    .max(64)
    .optional(),
  httpSecurity: HttpSecuritySchema,
  toolInputLimits: ToolInputLimitsSchema,
  mcpAuthSecretKey: z.string().optional(),
  mcpAuthIssuer: z
    .string()
    .optional()
    .describe('Expected JWT issuer; enforced by auth policy.'),
  mcpAuthAudience: z
    .string()
    .optional()
    .describe('Expected JWT audience; enforced by auth policy.'),
  mcpAuthMaxTokenLifetimeSeconds: z.coerce
    .number()
    .int()
    .min(1)
    .max(86400)
    .default(3600)
    .describe('Maximum accepted JWT lifetime.'),
  mcpAuthClockToleranceSeconds: z.coerce
    .number()
    .int()
    .min(0)
    .max(60)
    .default(5)
    .describe('JWT clock skew tolerance.'),
  mcpRepositoryGrants: z
    .string()
    .optional()
    .describe(
      'JSON repository grants; validated by the auth repository policy.',
    ),
  mcpAuthMode: z.preprocess(
    emptyStringAsUndefined,
    z.enum(['jwt', 'oauth', 'none']).default('none'),
  ),
  oauthIssuerUrl: z.string().url().optional(),
  oauthJwksUri: z.string().url().optional(),
  oauthAudience: z.string().optional(),
  oauthJwksCooldownMs: z.coerce.number().default(300_000), // 5 minutes
  oauthJwksTimeoutMs: z.coerce.number().default(5_000), // 5 seconds
  mcpServerResourceIdentifier: z.string().url().optional(), // RFC 8707 resource indicator
  devMcpClientId: z.string().optional(),
  devMcpScopes: z.array(z.string()).optional(),
  oauthProxy: z
    .object({
      authorizationUrl: z.string().url().optional(),
      tokenUrl: z.string().url().optional(),
      revocationUrl: z.string().url().optional(),
      issuerUrl: z.string().url().optional(),
      serviceDocumentationUrl: z.string().url().optional(),
      defaultClientRedirectUris: z.array(z.string()).optional(),
    })
    .optional(),
  supabase: z
    .object({
      url: z.string().url(),
      anonKey: z.string(),
      serviceRoleKey: z.string().optional(),
    })
    .optional(),
  storage: z.object({
    providerType: z
      .preprocess(
        (val) => {
          const str = emptyStringAsUndefined(val);
          if (typeof str === 'string') {
            const lower = str.toLowerCase();
            const aliasMap: Record<string, string> = {
              mem: 'in-memory',
              fs: 'filesystem',
            };
            return aliasMap[lower] ?? lower;
          }
          return str;
        },
        z.enum([
          'in-memory',
          'filesystem',
          'supabase',
          'cloudflare-r2',
          'cloudflare-kv',
        ]),
      )
      .default('in-memory'),
    filesystemPath: z.preprocess(
      expandTildePath,
      z.string().default('./.storage'),
    ), // Supports tilde expansion for filesystem storage
  }),
  git: z
    .object({
      executionProfile: z
        .preprocess(
          emptyStringAsUndefined,
          z.enum(['restricted', 'trusted']).default('restricted'),
        )
        .describe(
          'Explicit Git trust profile; restricted requires a verified OS sandbox and otherwise rejects execution.',
        ),
      binaryPath: z
        .preprocess(
          emptyStringAsUndefined,
          z
            .string()
            .default('/usr/bin/git')
            .refine(
              (value) => isAbsolutePath(value) && !value.includes('\0'),
              'Git binary path must be absolute.',
            ),
        )
        .describe('Operator-controlled absolute native Git executable.'),
      trustedHome: z
        .preprocess(
          expandTildePath,
          z
            .string()
            .default(homedir())
            .refine(
              (value) => isAbsolutePath(value) && !value.includes('\0'),
              'Trusted Git HOME must be absolute.',
            ),
        )
        .describe(
          'Operator-owned HOME for explicitly trusted native configuration and signing.',
        ),
      trustedPath: z
        .preprocess(
          emptyStringAsUndefined,
          z
            .string()
            .default('/usr/bin:/bin:/usr/sbin:/sbin')
            .refine(
              (value) =>
                !value.includes('\0') &&
                value
                  .split(path.delimiter)
                  .every((entry) => isAbsolutePath(entry)),
              'Every trusted helper PATH directory must be absolute.',
            ),
        )
        .describe('Explicit helper search path for the trusted Git profile.'),
      provider: z.preprocess(
        emptyStringAsUndefined,
        z.enum(['auto', 'cli', 'isomorphic']).default('auto'),
      ),
      signCommits: z.preprocess(parseBoolEnv(true), z.boolean()),
      authorName: z
        .string()
        .regex(
          /^[^\n\r\0]*$/,
          'Git author name must not contain newlines or null bytes',
        )
        .optional(),
      authorEmail: z.string().email().optional(),
      committerName: z
        .string()
        .regex(
          /^[^\n\r\0]*$/,
          'Git committer name must not contain newlines or null bytes',
        )
        .optional(),
      committerEmail: z.string().email().optional(),
      wrapupInstructionsPath: z.preprocess(
        expandTildePath,
        z.string().optional(),
      ), // Supports tilde expansion for custom wrapup instructions
      baseDirs: z.preprocess(
        (value) =>
          typeof value === 'string'
            ? value.split(',').map((entry) => expandTildePath(entry))
            : value,
        z
          .array(
            z
              .string()
              .refine((root) => isAbsolutePath(root) && !root.includes('\0'), {
                message: 'Every GIT_BASE_DIR entry must be an absolute path',
              }),
          )
          .min(1)
          .transform((roots) => [
            ...new Set(roots.map((root) => path.resolve(root))),
          ])
          .optional(),
      ),
      maxCommandTimeoutMs: z.coerce
        .number()
        .int()
        .min(1)
        .max(2147483647)
        .default(30000)
        .describe('Total native Git operation deadline in milliseconds.'),
      maxBufferSizeMb: z.coerce
        .number()
        .int()
        .min(1)
        .max(128)
        .default(10)
        .describe(
          'Legacy aggregate raw-output budget in MiB when byte limits are unset.',
        ),
      maxOutputBytes: z
        .preprocess(
          emptyStringAsUndefined,
          z.coerce.number().int().min(1).max(134217728).optional(),
        )
        .describe(
          'Aggregate raw stdout/stderr byte budget across every Git call in one request.',
        ),
      maxStdoutBytes: z
        .preprocess(
          emptyStringAsUndefined,
          z.coerce.number().int().min(1).max(134217728).optional(),
        )
        .describe('Independent stdout byte cap for each native Git command.'),
      maxStderrBytes: z
        .preprocess(
          emptyStringAsUndefined,
          z.coerce.number().int().min(1).max(134217728).optional(),
        )
        .describe('Independent stderr byte cap for each native Git command.'),
      terminationGraceMs: z.coerce
        .number()
        .int()
        .min(0)
        .max(5000)
        .default(250)
        .describe('Bounded TERM-to-KILL grace for the owned process group.'),
    })
    .transform((git) => {
      const maxOutputBytes =
        git.maxOutputBytes ?? git.maxBufferSizeMb * 1024 * 1024;
      return {
        ...git,
        maxOutputBytes,
        maxStdoutBytes: git.maxStdoutBytes ?? maxOutputBytes,
        maxStderrBytes: git.maxStderrBytes ?? maxOutputBytes,
      };
    }),
  openTelemetry: z.object({
    enabled: z.coerce.boolean().default(false),
    serviceName: z.string(),
    serviceVersion: z.string(),
    tracesEndpoint: z.string().url().optional(),
    metricsEndpoint: z.string().url().optional(),
    samplingRatio: z.coerce.number().default(1.0),
    logLevel: z
      .preprocess(
        (val) => {
          const str = emptyStringAsUndefined(val);
          if (typeof str === 'string') {
            const lower = str.toLowerCase();
            const aliasMap: Record<string, string> = {
              err: 'ERROR',
              warning: 'WARN',
              information: 'INFO',
            };
            return aliasMap[lower] ?? str.toUpperCase();
          }
          return str;
        },
        z.enum(['NONE', 'ERROR', 'WARN', 'INFO', 'DEBUG', 'VERBOSE', 'ALL']),
      )
      .default('INFO'),
  }),
});

// --- Parsing Logic ---
const parseConfig = () => {
  const env = process.env;

  const rawConfig = {
    pkg: {
      name: env.PACKAGE_NAME ?? packageManifest.name,
      version: env.PACKAGE_VERSION ?? packageManifest.version,
      description: env.PACKAGE_DESCRIPTION ?? packageManifest.description,
    },
    logLevel: env.MCP_LOG_LEVEL,
    logsPath: env.LOGS_DIR,
    environment: env.NODE_ENV,
    mcpTransportType: env.MCP_TRANSPORT_TYPE,
    mcpSessionMode: env.MCP_SESSION_MODE,
    mcpResponseFormat: env.MCP_RESPONSE_FORMAT,
    mcpResponseVerbosity: env.MCP_RESPONSE_VERBOSITY,
    mcpHttpPort: env.MCP_HTTP_PORT,
    mcpHttpHost: env.MCP_HTTP_HOST,
    mcpHttpEndpointPath: env.MCP_HTTP_ENDPOINT_PATH,
    mcpHttpMaxPortRetries: env.MCP_HTTP_MAX_PORT_RETRIES,
    mcpHttpPortRetryDelayMs: env.MCP_HTTP_PORT_RETRY_DELAY_MS,
    mcpStatefulSessionStaleTimeoutMs: env.MCP_STATEFUL_SESSION_STALE_TIMEOUT_MS,
    mcpAllowedOrigins: env.MCP_ALLOWED_ORIGINS?.split(',')
      .map((o) => o.trim())
      .filter(Boolean),
    httpSecurity: {
      allowedHosts: env.MCP_HTTP_ALLOWED_HOSTS?.split(',')
        .map((host) => host.trim())
        .filter(Boolean),
      allowNativeClients: env.MCP_HTTP_ALLOW_NATIVE_CLIENTS,
      maxBodyBytes: env.MCP_HTTP_MAX_BODY_BYTES,
      bodyTimeoutMs: env.MCP_HTTP_BODY_TIMEOUT_MS,
      requestTimeoutMs: env.MCP_HTTP_REQUEST_TIMEOUT_MS,
      streamTimeoutMs: env.MCP_HTTP_STREAM_TIMEOUT_MS,
      maxRequests: env.MCP_HTTP_MAX_REQUESTS,
      maxRequestsPerPrincipal: env.MCP_HTTP_MAX_REQUESTS_PER_PRINCIPAL,
      maxInitializations: env.MCP_HTTP_MAX_INITIALIZATIONS,
      maxSessions: env.MCP_HTTP_MAX_SESSIONS,
      maxSessionsPerPrincipal: env.MCP_HTTP_MAX_SESSIONS_PER_PRINCIPAL,
      maxStreams: env.MCP_HTTP_MAX_STREAMS,
      maxStreamsPerPrincipal: env.MCP_HTTP_MAX_STREAMS_PER_PRINCIPAL,
      requestsPerMinute: env.MCP_HTTP_REQUESTS_PER_MINUTE,
      maxPrincipals: env.MCP_HTTP_MAX_PRINCIPALS,
    },
    toolInputLimits: {
      maxElements: env.MCP_TOOL_MAX_ELEMENTS,
      maxArrayLength: env.MCP_TOOL_MAX_ARRAY_LENGTH,
      maxRecordKeys: env.MCP_TOOL_MAX_RECORD_KEYS,
      maxDepth: env.MCP_TOOL_MAX_DEPTH,
      maxStringBytes: env.MCP_TOOL_MAX_STRING_BYTES,
    },
    mcpAuthSecretKey: env.MCP_AUTH_SECRET_KEY,
    mcpAuthIssuer: env.MCP_AUTH_ISSUER,
    mcpAuthAudience: env.MCP_AUTH_AUDIENCE,
    mcpAuthMaxTokenLifetimeSeconds: env.MCP_AUTH_MAX_TOKEN_LIFETIME_SECONDS,
    mcpAuthClockToleranceSeconds: env.MCP_AUTH_CLOCK_TOLERANCE_SECONDS,
    mcpRepositoryGrants: env.MCP_REPOSITORY_GRANTS,
    mcpAuthMode: env.MCP_AUTH_MODE,
    oauthIssuerUrl: env.OAUTH_ISSUER_URL,
    oauthJwksUri: env.OAUTH_JWKS_URI,
    oauthAudience: env.OAUTH_AUDIENCE,
    oauthJwksCooldownMs: env.OAUTH_JWKS_COOLDOWN_MS,
    oauthJwksTimeoutMs: env.OAUTH_JWKS_TIMEOUT_MS,
    mcpServerResourceIdentifier: env.MCP_SERVER_RESOURCE_IDENTIFIER,
    devMcpClientId: env.DEV_MCP_CLIENT_ID,
    devMcpScopes: env.DEV_MCP_SCOPES?.split(',').map((s) => s.trim()),
    oauthProxy:
      env.OAUTH_PROXY_AUTHORIZATION_URL || env.OAUTH_PROXY_TOKEN_URL
        ? {
            authorizationUrl: env.OAUTH_PROXY_AUTHORIZATION_URL,
            tokenUrl: env.OAUTH_PROXY_TOKEN_URL,
            revocationUrl: env.OAUTH_PROXY_REVOCATION_URL,
            issuerUrl: env.OAUTH_PROXY_ISSUER_URL,
            serviceDocumentationUrl: env.OAUTH_PROXY_SERVICE_DOCUMENTATION_URL,
            defaultClientRedirectUris:
              env.OAUTH_PROXY_DEFAULT_CLIENT_REDIRECT_URIS?.split(',')
                .map((uri) => uri.trim())
                .filter(Boolean),
          }
        : undefined,
    supabase:
      env.SUPABASE_URL && env.SUPABASE_ANON_KEY
        ? {
            url: env.SUPABASE_URL,
            anonKey: env.SUPABASE_ANON_KEY,
            serviceRoleKey: env.SUPABASE_SERVICE_ROLE_KEY,
          }
        : undefined,
    storage: {
      providerType: env.STORAGE_PROVIDER_TYPE,
      filesystemPath: env.STORAGE_FILESYSTEM_PATH,
    },
    git: {
      provider: env.GIT_PROVIDER,
      signCommits: env.GIT_SIGN_COMMITS,
      // Support multiple naming conventions for author/committer
      // Priority: GIT_AUTHOR_NAME > GIT_USERNAME > GIT_USER
      authorName:
        env.GIT_AUTHOR_NAME || env.GIT_USERNAME || env.GIT_USER || undefined,
      authorEmail:
        env.GIT_AUTHOR_EMAIL ||
        env.GIT_EMAIL ||
        env.GIT_USER_EMAIL ||
        undefined,
      committerName:
        env.GIT_COMMITTER_NAME || env.GIT_USERNAME || env.GIT_USER || undefined,
      committerEmail:
        env.GIT_COMMITTER_EMAIL ||
        env.GIT_EMAIL ||
        env.GIT_USER_EMAIL ||
        undefined,
      wrapupInstructionsPath: env.GIT_WRAPUP_INSTRUCTIONS_PATH,
      baseDirs: env.GIT_BASE_DIR,
      executionProfile: env.GIT_EXECUTION_PROFILE,
      binaryPath: env.GIT_BINARY_PATH,
      trustedHome: env.GIT_TRUSTED_HOME,
      trustedPath: env.GIT_TRUSTED_PATH,
      maxCommandTimeoutMs: env.GIT_MAX_COMMAND_TIMEOUT_MS,
      maxBufferSizeMb: env.GIT_MAX_BUFFER_SIZE_MB,
      maxOutputBytes: env.GIT_MAX_OUTPUT_BYTES,
      maxStdoutBytes: env.GIT_MAX_STDOUT_BYTES,
      maxStderrBytes: env.GIT_MAX_STDERR_BYTES,
      terminationGraceMs: env.GIT_TERMINATION_GRACE_MS,
    },
    openTelemetry: {
      enabled: env.OTEL_ENABLED,
      serviceName: env.OTEL_SERVICE_NAME,
      serviceVersion: env.OTEL_SERVICE_VERSION,
      tracesEndpoint: env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,
      metricsEndpoint: env.OTEL_EXPORTER_OTLP_METRICS_ENDPOINT,
      samplingRatio: env.OTEL_TRACES_SAMPLER_ARG,
      logLevel: env.OTEL_LOG_LEVEL,
    },
    // The following fields will be derived and are not directly from env
    mcpServerName: env.MCP_SERVER_NAME,
    mcpServerVersion: env.MCP_SERVER_VERSION,
    mcpServerDescription: env.MCP_SERVER_DESCRIPTION,
  };

  // Use a temporary schema to parse package info and provide defaults
  const pkgSchema = z.object({
    name: z.string(),
    version: z.string(),
    description: z.string().optional(),
  });
  const parsedPkg = pkgSchema.parse(rawConfig.pkg);

  // Now add the derived values to the main rawConfig object to be parsed
  const finalRawConfig = {
    ...rawConfig,
    pkg: parsedPkg,
    logsPath: rawConfig.logsPath,
    mcpServerName: env.MCP_SERVER_NAME ?? parsedPkg.name,
    mcpServerVersion: env.MCP_SERVER_VERSION ?? parsedPkg.version,
    mcpServerDescription: env.MCP_SERVER_DESCRIPTION ?? parsedPkg.description,
    openTelemetry: {
      ...rawConfig.openTelemetry,
      serviceName: env.OTEL_SERVICE_NAME ?? parsedPkg.name,
      serviceVersion: env.OTEL_SERVICE_VERSION ?? parsedPkg.version,
    },
  };

  const parsedConfig = ConfigSchema.safeParse(finalRawConfig);

  if (!parsedConfig.success) {
    // Keep existing TTY error logging for developer convenience.
    if (process.stdout.isTTY) {
      console.error(
        '❌ Invalid configuration found. Please check your environment variables.',
        parsedConfig.error.flatten().fieldErrors,
      );
    }
    // Throw a specific, typed error instead of exiting.
    throw new McpError(
      JsonRpcErrorCode.ConfigurationError,
      'Invalid application configuration.',
      {
        validationErrors: parsedConfig.error.flatten().fieldErrors,
      },
    );
  }

  validateAuthenticationConfiguration(parsedConfig.data);
  return parsedConfig.data;
};

const config = parseConfig();

/**
 * Export the runtime configuration, parser, and schema, plus a static AppConfig type.
 */
export type AppConfig = z.infer<typeof ConfigSchema>;

export { config, ConfigSchema, parseConfig };
