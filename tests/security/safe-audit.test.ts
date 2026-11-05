/**
 * @fileoverview Privacy and cardinality regressions for observability sinks.
 * @module tests/security/safe-audit
 */
import { describe, expect, it } from 'bun:test';

import {
  type AuditEvent,
  AuditLogLimiter,
  auditOperation,
  safeAuditException,
  safeAuditRecord,
} from '@/utils/internal/safe-audit.js';

describe('allowlisted audit records', () => {
  it('seals issued records and preserves correlation across repeated sink boundaries', () => {
    const first = safeAuditRecord('operation', {
      requestId: 'SYNTHETIC_REQUEST',
      toolName: 'git_push',
    });
    const second = safeAuditRecord('operation', first, undefined, {
      isSuccess: true,
      inputBytes: 9,
    });
    expect(Object.isFrozen(first)).toBe(true);
    expect(Reflect.set(first, 'requestCorrelation', 'SYNTHETIC_FORGED')).toBe(
      false,
    );
    expect(second.requestCorrelation).toBe(first.requestCorrelation);
    expect(second).toMatchObject({
      operation: 'git_push',
      outcome: 'success',
      inputBytes: 9,
    });
  });
  it('retains denied-operation correlation without raw errors or identity', () => {
    const context = {
      toolName: 'git_push',
      requestId: 'SYNTHETIC_REQUEST',
      sessionId: 'SYNTHETIC_SESSION',
      input: { token: 'SYNTHETIC_TOKEN' },
    };
    const denied = safeAuditRecord('denied', context);
    const normal = safeAuditRecord('operation', context);
    expect(denied).toMatchObject({
      event: 'denied',
      operation: 'git_push',
      outcome: 'failure',
    });
    expect(denied.requestCorrelation).toBe(normal.requestCorrelation);
    expect(denied.sessionCorrelation).toBe(normal.sessionCorrelation);
    expect(JSON.stringify(denied)).not.toContain('SYNTHETIC_');
  });
  it('rejects event text even when a JavaScript caller bypasses the type', () => {
    expect(safeAuditRecord('SYNTHETIC_PRIVATE_EVENT' as AuditEvent).event).toBe(
      'operation',
    );
  });
  it('drops nested payloads, URL credentials, claims, error text and raw IDs', () => {
    // Synthetic sentinels, never real credentials.
    const secret = 'SYNTHETIC_PRIVATE_SENTINEL';
    const context = {
      toolName: 'git_push',
      requestId: `${secret}-request`,
      sessionId: `${secret}-session`,
      tenantId: `${secret}-tenant`,
      principal: {
        issuer: `${secret}-issuer`,
        tenantId: `${secret}-tenant`,
        clientId: `${secret}-client`,
        subject: `${secret}-subject`,
      },
      traceId: `${secret}-trace`,
      input: {
        nested: [
          {
            TOKEN: secret,
            url: `https://synthetic:${secret}@example.invalid/?token=${secret}`,
          },
        ],
      },
      auth: { claims: { sub: secret } },
      additionalContext: { error: secret },
      metrics: {
        isSuccess: false,
        durationMs: 4,
        inputBytes: 21,
        outputBytes: 0,
        raw: secret,
      },
    };
    const error = Object.assign(new Error(secret), {
      cause: secret,
      code: -32602,
    });
    const record = safeAuditRecord('operation', context, error);
    const encoded = JSON.stringify([record, safeAuditException(error)]);
    expect(encoded).not.toContain(secret);
    expect(encoded).not.toContain('https:');
    expect(record).toMatchObject({
      operation: 'git_push',
      outcome: 'failure',
      durationMs: 4,
      errorCode: -32602,
    });
    expect(record.requestCorrelation).toHaveLength(64);
    expect(record.sessionCorrelation).not.toBe(record.requestCorrelation);
    expect(record.principalCorrelation).toHaveLength(64);
    expect(safeAuditRecord('operation', context).sessionCorrelation).toBe(
      record.sessionCorrelation,
    );
  });

  it('does not invoke payload getters, toJSON, or serialize non-JSON errors', () => {
    let read = false;
    const hostile = {
      get toolName() {
        read = true;
        throw new Error('private');
      },
      toJSON() {
        read = true;
        throw new Error('private');
      },
    };
    expect(safeAuditRecord('interaction', hostile, [hostile])).toEqual({
      event: 'interaction',
      operation: 'internal',
      outcome: 'failure',
    });
    expect(safeAuditException(hostile)).toEqual({
      name: 'OperationError',
      message: 'Operation failed',
    });
    expect(read).toBe(false);
    const proxy = new Proxy(
      {},
      {
        getOwnPropertyDescriptor() {
          throw new Error('private');
        },
      },
    );
    expect(() => safeAuditRecord('interaction', proxy, proxy)).not.toThrow();
  });

  it('rejects dynamic operation names, invalid counters and nonnumeric codes', () => {
    expect(auditOperation('git_push/token=private')).toBe('internal');
    const record = safeAuditRecord(
      'exception',
      {
        toolName: 'git_push',
        metrics: {
          durationMs: Infinity,
          inputBytes: -1,
          outputBytes: 'private',
        },
      },
      { code: 'private' },
    );
    expect(record).toEqual({
      event: 'exception',
      operation: 'git_push',
      outcome: 'failure',
    });
  });
});

describe('audit limiter', () => {
  it('keeps suppression summaries when a new event expires the old window first', () => {
    const limiter = new AuditLogLimiter(1, 10, 2);
    const record = safeAuditRecord('operation', { toolName: 'git_status' });
    expect(limiter.allow(record, 'info', 0)).toBe(true);
    expect(limiter.allow(record, 'info', 1)).toBe(false);
    expect(limiter.allow(record, 'info', 10)).toBe(true);
    expect(limiter.cleanup(10)).toBe(1);
    expect(limiter.cleanup(10)).toBe(0);
  });
  it('keeps unique errors bounded and cleans unsuppressed windows', () => {
    const limiter = new AuditLogLimiter(2, 100, 8);
    for (let i = 0; i < 20_000; i++) {
      limiter.allow(
        safeAuditRecord(
          'exception',
          { toolName: `unique-${i}` },
          new Error(`unique-${i}`),
        ),
        'error',
        i,
      );
      expect(limiter.size).toBeLessThanOrEqual(8);
    }
    limiter.cleanup(20_100);
    expect(limiter.size).toBe(0);
    limiter.allow(
      safeAuditRecord('operation', { toolName: 'git_status' }),
      'info',
      30_000,
    );
    expect(limiter.cleanup(30_100)).toBe(0);
    expect(limiter.size).toBe(0);
  });

  it('enforces exact window and count boundaries without retaining messages', () => {
    const limiter = new AuditLogLimiter(2, 100, 2);
    const record = safeAuditRecord('operation', { toolName: 'git_status' });
    expect(limiter.allow(record, 'info', 0)).toBe(true);
    expect(limiter.allow(record, 'info', 99)).toBe(true);
    expect(limiter.allow(record, 'info', 99)).toBe(false);
    expect(limiter.cleanup(100)).toBe(1);
    expect(limiter.allow(record, 'info', 100)).toBe(true);
    for (const toolName of ['git_push', 'git_tag', 'git_commit'])
      limiter.allow(safeAuditRecord('operation', { toolName }), 'info', 100);
    expect(limiter.size).toBe(2);
    limiter.cleanup(50); // Clock rollback also releases stale counters.
    expect(limiter.size).toBe(0);
  });
});
