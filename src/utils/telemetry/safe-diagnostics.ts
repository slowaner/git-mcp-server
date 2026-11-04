/**
 * @fileoverview Bounded, payload-free OpenTelemetry diagnostic console adapter.
 * @module utils/telemetry/safe-diagnostics
 */
import type { DiagLogger } from '@opentelemetry/api';
import {
  AuditLogLimiter,
  safeAuditRecord,
} from '@/utils/internal/safe-audit.js';

type DiagnosticLevel = 'error' | 'warn' | 'info' | 'debug' | 'verbose';

/** Diagnostics may contain exporter URLs/credentials; retain only finite events. */
export function safeDiagnosticLogger(
  emit: (level: DiagnosticLevel, message: string) => void = (
    level,
    message,
  ) => {
    if (level === 'error') console.error(message);
    else console.warn(message);
  },
): DiagLogger {
  const limiter = new AuditLogLimiter();
  const log = (level: DiagnosticLevel): void => {
    const record = safeAuditRecord(
      level === 'error' ? 'exception' : 'operation',
    );
    if (
      !limiter.allow(
        record,
        level === 'warn' ? 'warning' : level === 'verbose' ? 'debug' : level,
      )
    )
      return;
    try {
      emit(level, `telemetry.${level}`);
    } catch {
      /* A failed sink never falls back to raw exporter diagnostics. */
    }
  };
  return {
    error: (..._args: unknown[]) => log('error'),
    warn: (..._args: unknown[]) => log('warn'),
    info: (..._args: unknown[]) => log('info'),
    debug: (..._args: unknown[]) => log('debug'),
    verbose: (..._args: unknown[]) => log('verbose'),
  };
}
