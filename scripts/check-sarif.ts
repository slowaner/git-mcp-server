#!/usr/bin/env bun
/**
 * @fileoverview Fail-closed local CodeQL SARIF gate; no provider write permission needed.
 * @module scripts/check-sarif
 */
import { readFile } from 'node:fs/promises';

/** Valid clean/low results are distinct from findings and incomplete analyses. */
export type SarifOutcome = 'allowed' | 'findings' | 'error';

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Require successful invocation evidence and complete rule metadata for every
 * result. Security severity >=7 (High/Critical) blocks; unknown severity blocks
 * as an incomplete report. Suppression flags do not bypass this gate.
 */
export function evaluateSarif(value: unknown): SarifOutcome {
  if (
    !object(value) ||
    value.version !== '2.1.0' ||
    !Array.isArray(value.runs) ||
    value.runs.length === 0
  )
    return 'error';
  let blocking = false;
  for (const run of value.runs) {
    if (
      !object(run) ||
      !Array.isArray(run.invocations) ||
      run.invocations.length === 0 ||
      !Array.isArray(run.results) ||
      !object(run.tool) ||
      !object(run.tool.driver) ||
      !Array.isArray(run.tool.driver.rules)
    )
      return 'error';
    for (const invocation of run.invocations) {
      if (!object(invocation) || invocation.executionSuccessful !== true)
        return 'error';
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
          return 'error';
      }
    }
    for (const result of run.results) {
      if (!object(result) || typeof result.ruleId !== 'string') return 'error';
      const rule = run.tool.driver.rules.find(
        (entry) => object(entry) && entry.id === result.ruleId,
      );
      if (!object(rule) || !object(rule.properties)) return 'error';
      const text = rule.properties['security-severity'];
      if (
        typeof text !== 'string' ||
        !/^(?:[0-9](?:\.[0-9]+)?|10(?:\.0+)?)$/.test(text)
      )
        return 'error';
      if (Number(text) >= 7 || result.level === 'error') blocking = true;
    }
  }
  return blocking ? 'findings' : 'allowed';
}

if (import.meta.main) {
  const files = process.argv.slice(2);
  if (files.length !== 1) {
    console.error('Usage: bun scripts/check-sarif.ts <complete-codeql.sarif>');
    process.exitCode = 2;
  } else {
    try {
      const outcome = evaluateSarif(
        JSON.parse(await readFile(files[0]!, 'utf8')),
      );
      console.log(`CodeQL security gate: ${outcome}`);
      process.exitCode = outcome === 'allowed' ? 0 : 1;
    } catch {
      console.error(
        'CodeQL SARIF missing or invalid; analysis not proven complete.',
      );
      process.exitCode = 2;
    }
  }
}
