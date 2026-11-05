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
    | 'unsupported-severity'
    | 'limits';
  run?: number;
  result?: number;
  runs?: number;
  results?: number;
  rules?: number;
  invocations?: number;
  reference?: ReferenceEvidence;
  catalogs?: { rules: ValueKind; count?: number }[];
  severity?: { type: ValueKind; valid: boolean; value?: number };
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

const LIMITS = {
  runs: 128,
  components: 256,
  rules: 100_000,
  results: 100_000,
  invocations: 4096,
  notifications: 100_000,
  bytes: 64 * 1024 * 1024,
};
type JsonObject = Record<string, unknown>;
type ValueKind =
  | 'absent'
  | 'undefined'
  | 'null'
  | 'array'
  | 'object'
  | 'string'
  | 'number'
  | 'boolean'
  | 'other';
interface Catalog {
  component: JsonObject;
  rules: JsonObject[];
  ids: Map<string, JsonObject[]>;
  guids: Map<string, JsonObject[]>;
}
interface ReferenceEvidence {
  rule: ValueKind;
  ruleId: ValueKind;
  ruleIndex: ValueKind;
  index: ValueKind;
  guid: ValueKind;
  toolComponent: ValueKind;
  componentIndex: ValueKind;
  componentGuid: ValueKind;
  componentName: ValueKind;
  descriptorIndex?: number;
  extensionIndex?: number;
}
const own = (value: JsonObject, key: string) =>
  Object.prototype.hasOwnProperty.call(value, key);
const nonempty = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0 && value.length <= 4096;
const guid = (value: unknown): value is string =>
  typeof value === 'string' &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value,
  );
const index = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= -1;

function kind(value: JsonObject, key: string): ValueKind {
  if (!own(value, key)) return 'absent';
  const field = value[key];
  if (field === null) return 'null';
  if (Array.isArray(field)) return 'array';
  const type = typeof field;
  return type === 'object' ||
    type === 'string' ||
    type === 'number' ||
    type === 'boolean' ||
    type === 'undefined'
    ? type
    : 'other';
}

function referenceEvidence(result: JsonObject): ReferenceEvidence {
  const rule = object(result.rule) ? result.rule : {};
  const component = object(rule.toolComponent) ? rule.toolComponent : {};
  return {
    rule: kind(result, 'rule'),
    ruleId: kind(result, 'ruleId'),
    ruleIndex: kind(result, 'ruleIndex'),
    index: kind(rule, 'index'),
    guid: kind(rule, 'guid'),
    toolComponent: kind(rule, 'toolComponent'),
    componentIndex: kind(component, 'index'),
    componentGuid: kind(component, 'guid'),
    componentName: kind(component, 'name'),
    ...(index(rule.index) && rule.index < LIMITS.rules
      ? { descriptorIndex: rule.index }
      : {}),
    ...(index(component.index) && component.index < LIMITS.components
      ? { extensionIndex: component.index }
      : {}),
  };
}

function addEntry(
  map: Map<string, JsonObject[]>,
  key: string,
  value: JsonObject,
) {
  const entries = map.get(key);
  if (entries) entries.push(value);
  else map.set(key, [value]);
}

function catalog(component: unknown): Catalog | undefined {
  if (
    !object(component) ||
    (own(component, 'name') && !nonempty(component.name)) ||
    (own(component, 'guid') && !guid(component.guid)) ||
    (own(component, 'rules') && !Array.isArray(component.rules))
  )
    return;
  const values = Array.isArray(component.rules) ? component.rules : [];
  const rules: JsonObject[] = [];
  const ids = new Map<string, JsonObject[]>();
  const guids = new Map<string, JsonObject[]>();
  for (const rule of values) {
    if (
      !object(rule) ||
      !nonempty(rule.id) ||
      (own(rule, 'guid') && !guid(rule.guid))
    )
      return;
    rules.push(rule);
    addEntry(ids, rule.id, rule);
    if (typeof rule.guid === 'string')
      addEntry(guids, rule.guid.toLowerCase(), rule);
  }
  return { component, rules, ids, guids };
}

/** External catalogs/results/invocations cannot establish completeness offline. */
function externalMetadata(run: JsonObject): boolean {
  if (!own(run, 'externalPropertyFileReferences')) return false;
  const references = run.externalPropertyFileReferences;
  if (!object(references) || own(references, 'driver')) return true;
  return ['extensions', 'results', 'invocations'].some(
    (field) =>
      own(references, field) &&
      (!Array.isArray(references[field]) || references[field].length > 0),
  );
}

/**
 * SARIF 2.1 sections 3.27.5-7, 3.52 and 3.54: select the component first,
 * then its descriptor. Never search another catalog after a reference fails.
 */
function resolveRule(
  result: JsonObject,
  catalogs: Catalog[],
): JsonObject | undefined {
  const driver = catalogs[0]!;
  const legacyIndex = own(result, 'ruleIndex');
  if (legacyIndex && !index(result.ruleIndex)) return;
  if (own(result, 'ruleId') && !nonempty(result.ruleId)) return;

  // Project legacy compatibility, NOT normative SARIF metadata lookup.
  // Only an absent rule and unset index permit an exact, unique DRIVER id.
  if (!own(result, 'rule') && (!legacyIndex || result.ruleIndex === -1)) {
    if (!nonempty(result.ruleId)) return;
    const matches = driver.ids.get(result.ruleId);
    return matches?.length === 1 ? matches[0] : undefined;
  }
  if (own(result, 'rule') && !object(result.rule)) return;
  const rule = object(result.rule) ? result.rule : {};
  if (
    (own(rule, 'id') && !nonempty(rule.id)) ||
    (own(rule, 'index') && !index(rule.index)) ||
    (own(rule, 'guid') && !guid(rule.guid)) ||
    (own(rule, 'toolComponent') && !object(rule.toolComponent))
  )
    return;
  if (own(rule, 'id') && own(result, 'ruleId') && rule.id !== result.ruleId)
    return;
  if (own(rule, 'index') && legacyIndex && rule.index !== result.ruleIndex)
    return;
  const descriptorIndex = own(rule, 'index') ? rule.index : result.ruleIndex;
  const id = own(rule, 'id') ? rule.id : result.ruleId;
  const component = object(rule.toolComponent) ? rule.toolComponent : {};
  if (
    (own(component, 'index') && !index(component.index)) ||
    (own(component, 'guid') && !guid(component.guid)) ||
    (own(component, 'name') && !nonempty(component.name))
  )
    return;

  let selected: Catalog | undefined = driver;
  if (typeof component.index === 'number' && component.index >= 0) {
    selected = catalogs[component.index + 1];
  } else if (typeof component.guid === 'string') {
    const key = component.guid.toLowerCase();
    const matches = catalogs.filter(
      (entry) =>
        typeof entry.component.guid === 'string' &&
        entry.component.guid.toLowerCase() === key,
    );
    selected = matches.length === 1 ? matches[0] : undefined;
  }
  if (!selected) return;
  if (typeof component.guid === 'string') {
    const key = component.guid.toLowerCase();
    const matches = catalogs.filter(
      (entry) =>
        typeof entry.component.guid === 'string' &&
        entry.component.guid.toLowerCase() === key,
    );
    if (matches.length !== 1 || matches[0] !== selected) return;
  }
  if (own(component, 'name') && component.name !== selected.component.name)
    return;

  let descriptor: JsonObject | undefined;
  if (typeof descriptorIndex === 'number' && descriptorIndex >= 0) {
    descriptor = selected.rules[descriptorIndex];
  } else if (typeof rule.guid === 'string') {
    const matches = selected.guids.get(rule.guid.toLowerCase());
    descriptor = matches?.length === 1 ? matches[0] : undefined;
  }
  if (!descriptor) return;
  if (typeof rule.guid === 'string') {
    const matches = selected.guids.get(rule.guid.toLowerCase());
    if (matches?.length !== 1 || matches[0] !== descriptor) return;
  }
  if (typeof id === 'string') {
    const descriptorId = descriptor.id;
    if (typeof descriptorId !== 'string') return;
    const suffix = id.slice(descriptorId.length + 1);
    if (
      id !== descriptorId &&
      !(
        id.startsWith(descriptorId + '/') &&
        suffix.length > 0 &&
        !suffix.includes('/')
      )
    )
      return;
  }
  return descriptor;
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
  if (value.runs.length > LIMITS.runs)
    return { outcome: 'error', reason: 'limits' };
  let blocking = false;
  let blockingEvidence: SarifDiagnostic | undefined;
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
    if (
      run.results.length > LIMITS.results ||
      run.invocations.length > LIMITS.invocations
    )
      return { outcome: 'error', reason: 'limits', ...shape };
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
          Array.isArray(notifications) &&
          notifications.length > LIMITS.notifications
        )
          return { outcome: 'error', reason: 'limits', ...shape };
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
    if (externalMetadata(run))
      return { outcome: 'error', reason: 'missing-rule', ...shape };
    const extensions = run.tool.extensions;
    if (own(run.tool, 'extensions') && !Array.isArray(extensions))
      return { outcome: 'error', reason: 'missing-rule', ...shape };
    const components: unknown[] = [
      run.tool.driver,
      ...(Array.isArray(extensions) ? extensions : []),
    ];
    if (components.length > LIMITS.components)
      return { outcome: 'error', reason: 'limits', ...shape };
    let ruleCount = 0;
    for (const component of components) {
      if (object(component) && Array.isArray(component.rules))
        ruleCount += component.rules.length;
    }
    if (ruleCount > LIMITS.rules)
      return { outcome: 'error', reason: 'limits', ...shape };
    const catalogs: Catalog[] = [];
    for (const component of components) {
      const entry = catalog(component);
      if (!entry) return { outcome: 'error', reason: 'missing-rule', ...shape };
      catalogs.push(entry);
    }
    const catalogEvidence = catalogs.map(({ component }) => ({
      rules: kind(component, 'rules'),
      ...(Array.isArray(component.rules)
        ? { count: component.rules.length }
        : {}),
    }));
    for (const [resultIndex, result] of run.results.entries()) {
      const location = { ...shape, result: count(resultIndex) };
      if (
        !object(result) ||
        (own(result, 'ruleId') && !nonempty(result.ruleId))
      )
        return { outcome: 'error', reason: 'result-shape', ...location };
      const evidence =
        own(result, 'rule') ||
        (own(result, 'ruleIndex') && result.ruleIndex !== -1)
          ? { reference: referenceEvidence(result), catalogs: catalogEvidence }
          : {};
      const rule = resolveRule(result, catalogs);
      if (!rule || !object(rule.properties))
        return {
          outcome: 'error',
          reason: 'missing-rule',
          ...location,
          ...evidence,
        };
      const text = rule.properties['security-severity'];
      if (
        typeof text !== 'string' ||
        !/^(?:[0-9](?:\.[0-9]+)?|10(?:\.0+)?)$/.test(text)
      )
        return {
          outcome: 'error',
          reason: 'unsupported-severity',
          ...location,
          ...evidence,
          ...(own(result, 'rule')
            ? {
                severity: {
                  type: kind(rule.properties, 'security-severity'),
                  valid: false,
                },
              }
            : {}),
        };
      if (Number(text) >= 7 || result.level === 'error') {
        blocking = true;
        if (!blockingEvidence && own(result, 'rule'))
          blockingEvidence = {
            outcome: 'findings',
            reason: 'security-findings',
            ...location,
            ...evidence,
            severity: { type: 'string', valid: true, value: Number(text) },
          };
      }
    }
  }
  return blocking
    ? (blockingEvidence ?? { outcome: 'findings', reason: 'security-findings' })
    : { outcome: 'allowed', reason: 'allowed' };
}

if (import.meta.main) {
  const files = process.argv.slice(2);
  if (files.length !== 1) {
    console.error('Usage: bun scripts/check-sarif.ts <complete-codeql.sarif>');
    process.exitCode = 2;
  } else {
    try {
      const bytes = await readFile(files[0]!);
      const diagnostic: SarifDiagnostic =
        bytes.length > LIMITS.bytes
          ? { outcome: 'error', reason: 'limits' }
          : inspectSarif(JSON.parse(bytes.toString('utf8')));
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
