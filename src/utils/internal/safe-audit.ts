/**
 * @fileoverview Allowlisted, payload-free records for every observability sink.
 * @module utils/internal/safe-audit
 */
import { createHmac, randomBytes } from 'node:crypto';

const correlationKey = randomBytes(32);
const issuedRecords = new WeakSet<object>();
const operations = new Set([
  'git_add',
  'git_blame',
  'git_branch',
  'git_checkout',
  'git_cherry_pick',
  'git_changelog_analyze',
  'git_clean',
  'git_clone',
  'git_commit',
  'git_diff',
  'git_fetch',
  'git_init',
  'git_log',
  'git_merge',
  'git_pull',
  'git_push',
  'git_rebase',
  'git_reflog',
  'git_remote',
  'git_reset',
  'git_show',
  'git_stash',
  'git_status',
  'git_tag',
  'git_worktree',
  'git_set_working_dir',
  'git_clear_working_dir',
  'git_wrapup_instructions',
  'git_wrapup',
]);

/** Finite events prevent repository text becoming a log message or limiter key. */
export type AuditEvent =
  'operation' | 'interaction' | 'suppressed' | 'exception' | 'denied';

/** Public sink schema. Arbitrary context fields and exception text are excluded. */
export interface SafeAuditRecord {
  event: AuditEvent;
  operation: string;
  outcome: 'success' | 'failure' | 'observed';
  requestCorrelation?: string;
  sessionCorrelation?: string;
  tenantCorrelation?: string;
  principalCorrelation?: string;
  repositoryCorrelation?: string;
  traceCorrelation?: string;
  durationMs?: number;
  inputBytes?: number;
  outputBytes?: number;
  inputSizeKnown?: boolean;
  outputSizeKnown?: boolean;
  errorCode?: number;
}

// Data descriptors avoid invoking getters/toJSON on untrusted objects. Proxies
// and all other failures produce an empty record, never raw fallback logging.
function own(value: unknown, key: string): unknown {
  if (!value || typeof value !== 'object') return undefined;
  try {
    return Object.getOwnPropertyDescriptor(value, key)?.value;
  } catch {
    return undefined;
  }
}

/** Fixed operation name; unknown names cannot enter spans, metrics or logs. */
export function auditOperation(value: unknown): string {
  return typeof value === 'string' && operations.has(value)
    ? value
    : 'internal';
}

/** Process-local, domain-separated correlation; never a raw session identifier. */
export function auditCorrelation(
  domain: string,
  value: unknown,
): string | undefined {
  if (typeof value !== 'string' || value.length === 0 || value.length > 8192)
    return undefined;
  return createHmac('sha256', correlationKey)
    .update(domain)
    .update('\0')
    .update(value)
    .digest('hex');
}

/** Project arbitrary runtime context onto the only schema allowed at a sink. */
export function safeAuditRecord(
  event: AuditEvent,
  context?: unknown,
  error?: unknown,
  measuredMetrics?: unknown,
): SafeAuditRecord {
  const previous =
    context && typeof context === 'object' && issuedRecords.has(context)
      ? (context as SafeAuditRecord)
      : undefined;
  const metrics = measuredMetrics ?? own(context, 'metrics');
  const ok = own(metrics, 'isSuccess') ?? own(context, 'success');
  const record: SafeAuditRecord = {
    ...previous,
    event: [
      'operation',
      'interaction',
      'suppressed',
      'exception',
      'denied',
    ].includes(event)
      ? event
      : 'operation',
    operation: auditOperation(
      own(context, 'toolName') ?? own(context, 'operation'),
    ),
    outcome:
      event === 'denied' ||
      event === 'exception' ||
      error !== undefined ||
      ok === false
        ? 'failure'
        : ok === true
          ? 'success'
          : (previous?.outcome ?? 'observed'),
  };
  const correlations = [
    ['requestCorrelation', 'requestId'],
    ['sessionCorrelation', 'sessionId'],
    ['tenantCorrelation', 'tenantId'],
    ['repositoryCorrelation', 'repositoryId'],
    ['traceCorrelation', 'traceId'],
  ] as const;
  for (const [target, source] of correlations) {
    const hashed = auditCorrelation(source, own(context, source));
    if (hashed) record[target] = hashed;
  }
  const principal = own(context, 'principal');
  const owner = ['issuer', 'tenantId', 'clientId', 'subject'].map((key) =>
    own(principal, key),
  );
  if (
    owner.every(
      (value) =>
        typeof value === 'string' && value.length > 0 && value.length <= 2048,
    )
  ) {
    const correlation = auditCorrelation('principal', JSON.stringify(owner));
    if (correlation) record.principalCorrelation = correlation;
  }
  for (const key of ['durationMs', 'inputBytes', 'outputBytes'] as const) {
    const value = own(metrics, key);
    if (typeof value === 'number' && Number.isFinite(value) && value >= 0)
      record[key] = value;
  }
  const code = own(error, 'code');
  for (const key of ['inputSizeKnown', 'outputSizeKnown'] as const) {
    const value = own(metrics, key);
    if (typeof value === 'boolean') record[key] = value;
  }
  if (
    typeof code === 'number' &&
    Number.isSafeInteger(code) &&
    code >= -32768 &&
    code <= -32000
  )
    record.errorCode = code;
  Object.freeze(record);
  issuedRecords.add(record);
  return record;
}

/** Preserve only the event of an immutable record issued by this module. */
export function auditEvent(context: unknown, fallback: AuditEvent): AuditEvent {
  return context && typeof context === 'object' && issuedRecords.has(context)
    ? (context as SafeAuditRecord).event
    : fallback;
}

/** Safe exception attributes for traces. No name/message/stack/cause from input. */
export function safeAuditException(error: unknown): {
  name: string;
  message: string;
} {
  const code = safeAuditRecord('exception', undefined, error).errorCode;
  return {
    name: 'OperationError',
    message:
      code === undefined ? 'Operation failed' : `Operation failed (${code})`,
  };
}

/** Finite-key limiter with a hard cardinality cap and unconditional expiry. */
export class AuditLogLimiter {
  private pendingSuppressed = 0;
  private readonly entries = new Map<
    string,
    { started: number; count: number; suppressed: number }
  >();

  constructor(
    private readonly threshold = 10,
    private readonly windowMs = 60_000,
    private readonly maxKeys = 256,
  ) {
    if (
      !Number.isSafeInteger(threshold) ||
      threshold < 1 ||
      !Number.isSafeInteger(windowMs) ||
      windowMs < 1 ||
      !Number.isSafeInteger(maxKeys) ||
      maxKeys < 1
    )
      throw new RangeError('Invalid audit limiter bounds');
  }

  private prune(now: number): void {
    for (const [key, value] of this.entries) {
      if (now - value.started >= this.windowMs || now < value.started) {
        this.pendingSuppressed = Math.min(
          Number.MAX_SAFE_INTEGER,
          this.pendingSuppressed + value.suppressed,
        );
        this.entries.delete(key);
      }
    }
  }

  /** Remove expired counters and drain summaries, even without suppression. */
  cleanup(now = Date.now()): number {
    this.prune(now);
    const count = this.pendingSuppressed;
    this.pendingSuppressed = 0;
    return count;
  }

  /** Accept only a bounded event/operation/outcome/level tuple. */
  allow(record: SafeAuditRecord, level: string, now = Date.now()): boolean {
    this.prune(now);
    const severity = [
      'debug',
      'info',
      'notice',
      'warning',
      'error',
      'crit',
      'alert',
      'emerg',
    ].includes(level)
      ? level
      : 'info';
    const event = [
      'operation',
      'interaction',
      'suppressed',
      'exception',
      'denied',
    ].includes(record.event)
      ? record.event
      : 'operation';
    const outcome = ['success', 'failure', 'observed'].includes(record.outcome)
      ? record.outcome
      : 'observed';
    const key = `${event}:${auditOperation(record.operation)}:${outcome}:${severity}`;
    let entry = this.entries.get(key);
    if (!entry) {
      if (this.entries.size >= this.maxKeys) {
        this.pendingSuppressed = Math.min(
          Number.MAX_SAFE_INTEGER,
          this.pendingSuppressed + 1,
        );
        return false;
      }
      entry = { started: now, count: 0, suppressed: 0 };
      this.entries.set(key, entry);
    }
    if (++entry.count <= this.threshold) return true;
    entry.suppressed = Math.min(Number.MAX_SAFE_INTEGER, entry.suppressed + 1);
    return false;
  }

  /** Number of counters retained; independent of unique input messages. */
  get size(): number {
    return this.entries.size;
  }
}
