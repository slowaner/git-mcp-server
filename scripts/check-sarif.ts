#!/usr/bin/env bun
/**
 * @fileoverview Fail-closed local CodeQL SARIF gate; no provider write permission needed.
 * @module scripts/check-sarif
 */
import { readFile } from 'node:fs/promises';

/** Valid clean/low results are distinct from findings and incomplete analyses. */
export type SarifOutcome = 'allowed' | 'findings' | 'error';

/** Fixed diagnostic vocabulary never includes report-controlled strings or paths. */
export interface SarifDiagnostic {
  outcome: SarifOutcome;
  reason:
    | 'allowed'
    | 'security-findings'
    | 'root-shape'
    | 'run-shape'
    | 'unsuccessful-invocation'
    | 'notifications'
    | 'result-shape'
    | 'missing-rule'
    | 'unsupported-severity';
  run?: number;
  result?: number;
  runs?: number;
  results?: number;
  rules?: number;
  invocations?: number;
  present?: {
    invocations: boolean;
    results: boolean;
    driver: boolean;
    rules: boolean;
  };
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Require successful invocation evidence and complete rule metadata for every
 * result. Security severity >=7 (High/Critical) blocks; unknown severity blocks
 * as an incomplete report. Suppression flags do not bypass this gate.
 */
export function evaluateSarif(value: unknown): SarifOutcome {
  return inspectSarif(value).outcome;
}

/** Preserve every gate predicate; expose only finite reasons and bounded counts. */
export function inspectSarif(value: unknown): SarifDiagnostic {
  const count = (value: number) => Math.min(value, 1_000_000);
  if (
    !object(value) ||
    value.version !== '2.1.0' ||
    !Array.isArray(value.runs) ||
    value.runs.length === 0
  )
    return { outcome: 'error', reason: 'root-shape' };
  let blocking = false;
  for (const [runIndex, run] of value.runs.entries()) {
    const position = { run: count(runIndex), runs: count(value.runs.length) };
    const r: Record<string, unknown> = object(run) ? run : {};
    const tool: Record<string, unknown> = object(r.tool) ? r.tool : {};
    const driver: Record<string, unknown> = object(tool.driver)
      ? tool.driver
      : {};
    const schema = {
      ...position,
      present: {
        invocations: Array.isArray(r.invocations),
        results: Array.isArray(r.results),
        driver: object(tool.driver),
        rules: Array.isArray(driver.rules),
      },
      ...(Array.isArray(r.invocations)
        ? { invocations: count(r.invocations.length) }
        : {}),
      ...(Array.isArray(r.results) ? { results: count(r.results.length) } : {}),
      ...(Array.isArray(driver.rules)
        ? { rules: count(driver.rules.length) }
        : {}),
    };
    if (
      !object(run) ||
      !Array.isArray(run.invocations) ||
      run.invocations.length === 0 ||
      !Array.isArray(run.results) ||
      !object(run.tool) ||
      !object(run.tool.driver) ||
      !Array.isArray(run.tool.driver.rules)
    )
      return { outcome: 'error', reason: 'run-shape', ...schema };
    const shape = {
      ...schema,
      results: count(run.results.length),
      rules: count(run.tool.driver.rules.length),
      invocations: count(run.invocations.length),
    };
    for (const invocation of run.invocations) {
      if (!object(invocation) || invocation.executionSuccessful !== true)
        return {
          outcome: 'error',
          reason: 'unsuccessful-invocation',
          ...shape,
        };
      for (const kind of [
        'toolExecutionNotifications',
        'toolConfigurationNotifications',
      ]) {
        const notifications = invocation[kind];
        if (
          notifications !== undefined &&
          (!Array.isArray(notifications) ||
            notifications.some(
              (item) => !object(item) || item.level === 'error',
            ))
        )
          return { outcome: 'error', reason: 'notifications', ...shape };
      }
    }
    for (const [resultIndex, result] of run.results.entries()) {
      const location = { ...shape, result: count(resultIndex) };
      if (!object(result) || typeof result.ruleId !== 'string')
        return { outcome: 'error', reason: 'result-shape', ...location };
      const rule = run.tool.driver.rules.find(
        (entry) => object(entry) && entry.id === result.ruleId,
      );
      if (!object(rule) || !object(rule.properties))
        return { outcome: 'error', reason: 'missing-rule', ...location };
      const text = rule.properties['security-severity'];
      if (
        typeof text !== 'string' ||
        !/^(?:[0-9](?:\.[0-9]+)?|10(?:\.0+)?)$/.test(text)
      )
        return {
          outcome: 'error',
          reason: 'unsupported-severity',
          ...location,
        };
      if (Number(text) >= 7 || result.level === 'error') blocking = true;
    }
  }
  return blocking
    ? { outcome: 'findings', reason: 'security-findings' }
    : { outcome: 'allowed', reason: 'allowed' };
}

if (import.meta.main) {
  const files = process.argv.slice(2);
  if (files.length !== 1) {
    console.error('Usage: bun scripts/check-sarif.ts <complete-codeql.sarif>');
    process.exitCode = 2;
  } else {
    try {
      const diagnostic = inspectSarif(
        JSON.parse(await readFile(files[0]!, 'utf8')),
      );
      console.log(JSON.stringify(diagnostic));
      process.exitCode = diagnostic.outcome === 'allowed' ? 0 : 1;
    } catch {
      console.error(
        'CodeQL SARIF missing or invalid; analysis not proven complete.',
      );
      process.exitCode = 2;
    }
  }
}
