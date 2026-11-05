/**
 * @fileoverview Pino-backed singleton logger with environment-adaptive output.
 * Emits allowlisted audit events, RFC5424 severity, opaque correlation and bounded
 * rate limiting. Raw messages, payloads and errors never enter a logging sink.
 * Newly created log directories/files use private POSIX modes; existing log
 * locations remain operator-owned and require private permissions and retention.
 * @module src/utils/internal/logger
 */
import type { LevelWithSilent, Logger as PinoLogger } from 'pino';
import pino from 'pino';

import { config } from '@/config/index.js';
import {
  requestContextService,
  type RequestContext,
} from '@/utils/internal/requestContext.js';
import { sanitization } from '@/utils/security/sanitization.js';
import {
  AuditLogLimiter,
  auditEvent,
  safeAuditRecord,
  type SafeAuditRecord,
} from './safe-audit.js';

/** MCP severity names translated to their corresponding Pino levels. */
export type McpLogLevel =
  | 'debug'
  | 'info'
  | 'notice'
  | 'warning'
  | 'error'
  | 'crit'
  | 'alert'
  | 'emerg';

const mcpToPinoLevel: Record<McpLogLevel, LevelWithSilent> = {
  emerg: 'fatal',
  alert: 'fatal',
  crit: 'error',
  error: 'error',
  warning: 'warn',
  notice: 'info',
  info: 'info',
  debug: 'debug',
};

const pinoToMcpLevelSeverity: Record<string, number> = {
  fatal: 0,
  error: 2,
  warn: 4,
  info: 6,
  debug: 7,
};

const isServerless =
  typeof process === 'undefined' || process.env.IS_SERVERLESS === 'true';

/**
 * Process-local audit logger. Level methods retain the legacy message parameter
 * for API compatibility but emit only a finite event and safe audit record.
 * initialize/close own transport setup, flush and limiter cleanup; logInteraction
 * applies the identical policy to the interaction sink. Raw input logging cannot
 * be enabled by a caller flag or an arbitrary context field.
 */
export class Logger {
  private static readonly instance: Logger = new Logger();
  private pinoLogger?: PinoLogger;
  private interactionLogger?: PinoLogger | undefined;
  private initialized = false;
  private currentMcpLevel: McpLogLevel = 'info';
  private transportType: 'stdio' | 'http' | undefined;

  private rateLimitWindow = 60000;
  private auditLimiter = new AuditLogLimiter();
  private cleanupTimer?: NodeJS.Timeout;

  private constructor() {
    // The constructor is now safe to call in a global scope.
  }

  public static getInstance(): Logger {
    return Logger.instance;
  }

  private async createPinoLogger(
    level: McpLogLevel,
    transportType?: 'stdio' | 'http',
  ): Promise<PinoLogger> {
    const pinoLevel = mcpToPinoLevel[level] || 'info';

    const pinoOptions: pino.LoggerOptions = {
      level: pinoLevel,
      base: {
        env: config.environment,
        version:
          /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/.test(
            config.mcpServerVersion,
          ) && config.mcpServerVersion.length <= 80
            ? config.mcpServerVersion
            : 'unknown',
        pid: !isServerless ? process.pid : undefined,
      },
      redact: {
        paths: sanitization.getSensitivePinoFields(),
        censor: '[REDACTED]',
      },
    };

    if (isServerless) {
      return pino(pinoOptions);
    }

    // Node.js specific transports
    const { default: fs } = await import('fs');
    const { default: path } = await import('path');

    const transports: pino.TransportTargetOptions[] = [];
    const isDevelopment = config.environment === 'development';
    const isTest = config.environment === 'testing';

    // CRITICAL: STDIO transport MUST NOT output colored logs to stdout.
    // The MCP specification requires clean JSON-RPC on stdout with no ANSI codes.
    // Only use pretty/colored output for HTTP mode or when explicitly debugging.
    // Respect NO_COLOR environment variable (https://no-color.org/)
    const noColorEnv =
      process.env.NO_COLOR === '1' || process.env.FORCE_COLOR === '0';
    const useColoredOutput =
      isDevelopment && transportType !== 'stdio' && !noColorEnv;

    if (useColoredOutput && !isServerless) {
      // Try to resolve 'pino-pretty' robustly even when bundled (e.g., Bun/ESM),
      // falling back to JSON stdout if resolution fails.
      try {
        const { createRequire } = await import('node:module');
        const require = createRequire(import.meta.url);
        const prettyTarget = require.resolve('pino-pretty');
        transports.push({
          target: prettyTarget,
          options: { colorize: true, translateTime: 'yyyy-mm-dd HH:MM:ss' },
        });
      } catch {
        // Only log to console if TTY to avoid polluting stderr in STDIO mode
        if (process.stderr?.isTTY) {
          console.warn(
            '[Logger Init] Pretty transport unavailable; using JSON logging.',
          );
        }
        transports.push({ target: 'pino/file', options: { destination: 1 } });
      }
    } else if (!isTest) {
      // CRITICAL: For STDIO transport, logs MUST go to stderr (fd 2), NOT stdout (fd 1).
      // The MCP specification requires only JSON-RPC messages on stdout.
      // For HTTP transport or production, we also use stderr to avoid polluting stdout.
      transports.push({ target: 'pino/file', options: { destination: 2 } });
    }

    if (config.logsPath) {
      try {
        if (!fs.existsSync(config.logsPath)) {
          fs.mkdirSync(config.logsPath, { recursive: true, mode: 0o700 });
        }
        transports.push({
          level: pinoLevel,
          target: 'pino/file',
          options: {
            destination: path.join(config.logsPath, 'combined.log'),
            mode: 0o600,
            mkdir: true,
          },
        });
        transports.push({
          level: 'error',
          target: 'pino/file',
          options: {
            destination: path.join(config.logsPath, 'error.log'),
            mode: 0o600,
            mkdir: true,
          },
        });
      } catch {
        // Only log to console if TTY to avoid polluting stderr in STDIO mode
        if (process.stderr?.isTTY) {
          console.error('[Logger Init] Failed to configure file logging.');
        }
      }
    }

    return pino({ ...pinoOptions, transport: { targets: transports } });
  }

  private async createInteractionLogger(): Promise<PinoLogger | undefined> {
    if (isServerless || !config.logsPath) return undefined;

    const { default: path } = await import('path');
    return pino({
      base: {},
      transport: {
        target: 'pino/file',
        options: {
          destination: path.join(config.logsPath, 'interactions.log'),
          mode: 0o600,
          mkdir: true,
        },
      },
    });
  }

  public async initialize(
    level: McpLogLevel = 'info',
    transportType?: 'stdio' | 'http',
  ): Promise<void> {
    if (this.initialized) {
      this.warning(
        'Logger already initialized.',
        requestContextService.createRequestContext({
          operation: 'loggerReinit',
        }),
      );
      return;
    }
    this.currentMcpLevel = level;
    this.transportType = transportType;
    this.pinoLogger = await this.createPinoLogger(level, transportType);
    this.interactionLogger = await this.createInteractionLogger();

    // Start the cleanup timer only after initialization and only in Node.js
    if (!isServerless && !this.cleanupTimer) {
      this.cleanupTimer = setInterval(
        () => this.flushSuppressedMessages(),
        this.rateLimitWindow,
      );
      this.cleanupTimer.unref?.();
    }

    this.initialized = true;
    this.info(
      `Logger initialized. MCP level: ${level}.`,
      requestContextService.createRequestContext({ operation: 'loggerInit' }),
    );
  }

  public setLevel(newLevel: McpLogLevel): void {
    if (!this.pinoLogger || !this.initialized) {
      // Only log to console if TTY to avoid polluting stderr in STDIO mode
      if (process.stderr?.isTTY) {
        console.error('Cannot set level: Logger not initialized.');
      }
      return;
    }
    this.currentMcpLevel = newLevel;
    this.pinoLogger.level = mcpToPinoLevel[newLevel] || 'info';
    this.info(
      `Log level changed to ${newLevel}.`,
      requestContextService.createRequestContext({
        operation: 'loggerSetLevel',
      }),
    );
  }

  public async close(): Promise<void> {
    if (!this.initialized) return Promise.resolve();
    this.info(
      'Logger shutting down.',
      requestContextService.createRequestContext({ operation: 'loggerClose' }),
    );
    if (this.cleanupTimer) clearInterval(this.cleanupTimer);
    delete this.cleanupTimer;
    this.flushSuppressedMessages(true);

    // Wait for all pending writes to complete
    await Promise.all([
      new Promise<void>((resolve) => {
        if (this.pinoLogger) {
          this.pinoLogger.flush((err) => {
            // Only log to console if TTY AND not in STDIO mode
            // In STDIO mode, stdout is reserved for MCP JSON-RPC, so avoid polluting stderr with shutdown noise
            if (
              err &&
              process.stderr?.isTTY &&
              this.transportType !== 'stdio'
            ) {
              console.error('Error flushing main logger.');
            }
            resolve();
          });
        } else {
          resolve();
        }
      }),
      new Promise<void>((resolve) => {
        if (this.interactionLogger) {
          this.interactionLogger.flush((err) => {
            // Only log to console if TTY AND not in STDIO mode
            // In STDIO mode, stdout is reserved for MCP JSON-RPC, so avoid polluting stderr with shutdown noise
            if (
              err &&
              process.stderr?.isTTY &&
              this.transportType !== 'stdio'
            ) {
              console.error('Error flushing interaction logger.');
            }
            resolve();
          });
        } else {
          resolve();
        }
      }),
    ]);

    this.initialized = false;
    this.auditLimiter = new AuditLogLimiter();
  }

  public isInitialized(): boolean {
    return this.initialized;
  }

  private flushSuppressedMessages(force = false): void {
    const count = this.auditLimiter.cleanup(force ? Infinity : Date.now());
    if (count > 0) {
      try {
        this.pinoLogger?.warn(
          { ...safeAuditRecord('suppressed'), suppressedCount: count },
          'suppressed',
        );
      } catch {
        // Logging failures never justify serializing raw fallback data.
      }
    }
  }

  private log(
    level: McpLogLevel,
    _msg: string,
    context?: RequestContext | SafeAuditRecord,
    error?: Error,
  ): void {
    if (!this.pinoLogger || !this.initialized) return;

    const pinoLevel = mcpToPinoLevel[level] || 'info';
    const currentPinoLevel = mcpToPinoLevel[this.currentMcpLevel] || 'info';

    const levelSeverity = pinoToMcpLevelSeverity[pinoLevel];
    const currentLevelSeverity = pinoToMcpLevelSeverity[currentPinoLevel];

    if (
      typeof levelSeverity === 'number' &&
      typeof currentLevelSeverity === 'number' &&
      levelSeverity > currentLevelSeverity
    ) {
      return;
    }

    const event = auditEvent(
      context,
      typeof levelSeverity === 'number' && levelSeverity <= 2
        ? 'exception'
        : 'operation',
    );
    const record = safeAuditRecord(event, context, error);
    if (!this.auditLimiter.allow(record, level)) return;
    try {
      this.pinoLogger[pinoLevel](record, record.event);
    } catch {
      // Do not pass sink errors or the original message to another sink.
    }
  }

  public debug(msg: string, context?: RequestContext | SafeAuditRecord): void {
    this.log('debug', msg, context);
  }
  public info(msg: string, context?: RequestContext | SafeAuditRecord): void {
    this.log('info', msg, context);
  }
  public notice(msg: string, context?: RequestContext | SafeAuditRecord): void {
    this.log('notice', msg, context);
  }
  public warning(
    msg: string,
    context?: RequestContext | SafeAuditRecord,
  ): void {
    this.log('warning', msg, context);
  }

  public error(
    msg: string,
    errorOrContext: Error | RequestContext | SafeAuditRecord,
    context?: RequestContext | SafeAuditRecord,
  ): void {
    const errorObj =
      errorOrContext instanceof Error ? errorOrContext : undefined;
    const actualContext =
      errorOrContext instanceof Error ? context : errorOrContext;
    this.log('error', msg, actualContext, errorObj);
  }

  public crit(
    msg: string,
    errorOrContext: Error | RequestContext | SafeAuditRecord,
    context?: RequestContext | SafeAuditRecord,
  ): void {
    const errorObj =
      errorOrContext instanceof Error ? errorOrContext : undefined;
    const actualContext =
      errorOrContext instanceof Error ? context : errorOrContext;
    this.log('crit', msg, actualContext, errorObj);
  }

  public alert(
    msg: string,
    errorOrContext: Error | RequestContext | SafeAuditRecord,
    context?: RequestContext | SafeAuditRecord,
  ): void {
    const errorObj =
      errorOrContext instanceof Error ? errorOrContext : undefined;
    const actualContext =
      errorOrContext instanceof Error ? context : errorOrContext;
    this.log('alert', msg, actualContext, errorObj);
  }

  public emerg(
    msg: string,
    errorOrContext: Error | RequestContext | SafeAuditRecord,
    context?: RequestContext | SafeAuditRecord,
  ): void {
    const errorObj =
      errorOrContext instanceof Error ? errorOrContext : undefined;
    const actualContext =
      errorOrContext instanceof Error ? context : errorOrContext;
    this.log('emerg', msg, actualContext, errorObj);
  }

  public fatal(
    msg: string,
    errorOrContext: Error | RequestContext | SafeAuditRecord,
    context?: RequestContext | SafeAuditRecord,
  ): void {
    this.emerg(msg, errorOrContext, context);
  }

  public logInteraction(
    _interactionName: string,
    data: Record<string, unknown>,
  ): void {
    try {
      const context: unknown =
        Object.getOwnPropertyDescriptor(data, 'context')?.value ?? data;
      const record = safeAuditRecord('interaction', context);
      if (!this.interactionLogger) {
        if (!isServerless)
          this.warning('Interaction logger not available.', record);
        return;
      }
      if (this.auditLimiter.allow(record, 'info'))
        this.interactionLogger.info(record, 'interaction');
    } catch {
      // Logging failure is not permission to expose raw data to a fallback.
    }
  }
}

export const logger = Logger.getInstance();
