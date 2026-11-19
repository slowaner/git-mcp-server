/**
 * @fileoverview Real Pino file-sink privacy, levels, permissions and lifecycle.
 * @module tests/utils/internal/logger.int
 */
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { config } from '@/config/index.js';
import { Logger } from '@/utils/internal/logger.js';
import {
  auditCorrelation,
  safeAuditRecord,
} from '@/utils/internal/safe-audit.js';

type LogEntry = Record<string, unknown>;
const originalLogsPath = config.logsPath;
let root: string;
let logs: string;
const logger = Logger.getInstance();

function entries(file: string): LogEntry[] {
  const path = join(logs, file);
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line) as LogEntry);
}

async function waitForEntry(file: string, request: string): Promise<LogEntry> {
  const correlation = auditCorrelation('requestId', request);
  const until = Date.now() + 3000;
  while (Date.now() < until) {
    const found = entries(file).find(
      (entry) => entry.requestCorrelation === correlation,
    );
    if (found) return found;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('Expected safe audit event did not reach its file sink');
}

describe('Logger real file sinks', () => {
  beforeAll(async () => {
    vi.useRealTimers();
    if (logger.isInitialized()) await logger.close();
    root = mkdtempSync(join(tmpdir(), 'safe-logger-'));
    logs = join(root, 'logs');
    config.logsPath = logs;
    await logger.initialize('debug', 'stdio');
  });

  afterAll(async () => {
    await logger.close();
    config.logsPath = originalLogsPath;
    if (root) rmSync(root, { recursive: true, force: true });
  });

  const levels = [
    ['debug', 20],
    ['info', 30],
    ['notice', 30],
    ['warning', 40],
    ['error', 50],
    ['crit', 50],
    ['alert', 60],
    ['emerg', 60],
    ['fatal', 60],
  ] as const;

  for (const [level, severity] of levels)
    it(`preserves ${level} severity with no raw message or context`, async () => {
      const request = `SYNTHETIC_REQUEST_${level}`;
      const secret = `SYNTHETIC_PRIVATE_${level}`;
      logger[level](secret, {
        requestId: request,
        timestamp: new Date().toISOString(),
        toolName: 'git_status',
        sessionId: secret,
        input: {
          nested: [
            {
              ToKeN: secret,
              url: `https://user:${secret}@example.invalid/?token=${secret}`,
            },
          ],
        },
        auth: {
          sub: secret,
          scopes: ['tool:git:read'],
          claims: { sub: secret },
        },
      });
      const event = await waitForEntry('combined.log', request);
      expect(event.level).toBe(severity);
      expect(event.msg).toBe(severity >= 50 ? 'exception' : 'operation');
      expect(event.operation).toBe('git_status');
      expect(JSON.stringify(event)).not.toContain('SYNTHETIC_');
      expect(event).not.toHaveProperty('input');
      expect(event).not.toHaveProperty('auth');
      if (severity >= 50)
        expect((await waitForEntry('error.log', request)).level).toBe(severity);
      else
        expect(
          entries('error.log').some(
            (entry) => entry.requestCorrelation === event.requestCorrelation,
          ),
        ).toBe(false);
    });

  it('keeps denied events and sealed correlation without hashing twice', async () => {
    const request = 'SYNTHETIC_DENIED_REQUEST';
    const record = safeAuditRecord('denied', {
      requestId: request,
      toolName: 'git_push',
    });
    logger.error('SYNTHETIC_ERROR_MESSAGE', record);
    const event = await waitForEntry('error.log', request);
    expect(event).toMatchObject({
      event: 'denied',
      outcome: 'failure',
      operation: 'git_push',
      requestCorrelation: record.requestCorrelation,
    });
  });

  it('removes error message, stack and cause before either file sink', async () => {
    const request = 'SYNTHETIC_ERROR_REQUEST';
    const secret = 'SYNTHETIC_ERROR_URL_PASSWORD';
    logger.error(secret, new Error(secret, { cause: new Error(secret) }), {
      requestId: request,
      timestamp: '',
      toolName: 'git_commit',
      error: { secret },
    });
    for (const file of ['combined.log', 'error.log']) {
      const event = await waitForEntry(file, request);
      expect(JSON.stringify(event)).not.toContain(secret);
      expect(event).not.toHaveProperty('err');
      expect(event).not.toHaveProperty('stack');
    }
  });

  it('applies identical schema to the interaction logger', async () => {
    const request = 'SYNTHETIC_INTERACTION_REQUEST';
    logger.logInteraction('SYNTHETIC_PRIVATE_INTERACTION', {
      context: {
        requestId: request,
        toolName: 'git_push',
        input: { token: 'SYNTHETIC_TOKEN' },
      },
      payload: 'SYNTHETIC_PAYLOAD',
    });
    const event = await waitForEntry('interactions.log', request);
    expect(event).toMatchObject({
      event: 'interaction',
      operation: 'git_push',
      msg: 'interaction',
    });
    expect(JSON.stringify(event)).not.toContain('SYNTHETIC_');
    expect(event).not.toHaveProperty('interactionName');
  });

  it('filters debug at info and emits STDIO logs as plain JSON', async () => {
    const request = 'SYNTHETIC_FILTERED_REQUEST';
    logger.setLevel('info');
    logger.debug('SYNTHETIC_FILTERED_MESSAGE', {
      requestId: request,
      timestamp: '',
      toolName: 'git_log',
    });
    logger.info('barrier', {
      requestId: 'level-barrier',
      timestamp: '',
      toolName: 'git_log',
    });
    await waitForEntry('combined.log', 'level-barrier');
    expect(
      entries('combined.log').some(
        (entry) =>
          entry.requestCorrelation === auditCorrelation('requestId', request),
      ),
    ).toBe(false);
    const raw = readFileSync(join(logs, 'combined.log'), 'utf8');
    expect(/\x1b\[[0-9;]*m/.test(raw)).toBe(false);
    for (const line of raw.split('\n').filter(Boolean))
      expect(() => JSON.parse(line)).not.toThrow();
    logger.setLevel('debug');
  });

  it('creates private directories and files on the supported POSIX profile', async () => {
    await waitForEntry('combined.log', 'level-barrier');
    expect(statSync(logs).mode & 0o077).toBe(0);
    for (const file of ['combined.log', 'error.log', 'interactions.log'])
      expect(statSync(join(logs, file)).mode & 0o077).toBe(0);
  });

  it('bounds real logger state under unique dynamic error messages', () => {
    for (let i = 0; i < 20_000; i++)
      logger.error(`SYNTHETIC_UNIQUE_${i}`, {
        requestId: `request-${i}`,
        timestamp: '',
        toolName: 'git_rebase',
      });
    const state = logger as unknown as { auditLimiter: { size: number } };
    expect(state.auditLimiter.size).toBeLessThanOrEqual(256);
  });

  it('does not serialize fallback data when a sink fails', () => {
    const state = logger as unknown as { pinoLogger: Record<string, unknown> };
    const original = state.pinoLogger;
    state.pinoLogger = {
      info() {
        throw new Error('SYNTHETIC_SINK_FAILURE');
      },
    };
    try {
      expect(() =>
        logger.info('SYNTHETIC_MESSAGE', {
          requestId: 'sink-failure',
          timestamp: '',
          toolName: 'git_tag',
        }),
      ).not.toThrow();
    } finally {
      state.pinoLogger = original;
    }
  });

  it('can reinitialize HTTP logging after close with fresh limiter/timer state', async () => {
    await logger.close();
    await logger.initialize('info', 'http');
    logger.info('SYNTHETIC_HTTP_MESSAGE', {
      requestId: 'http-after-close',
      timestamp: '',
      toolName: 'git_status',
    });
    expect(
      (await waitForEntry('combined.log', 'http-after-close')).operation,
    ).toBe('git_status');
  });
});
