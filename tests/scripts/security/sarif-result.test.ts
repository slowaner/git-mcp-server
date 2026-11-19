/**
 * @fileoverview Complete CodeQL evidence required even when analyzer exits zero.
 * @module tests/scripts/security/sarif-result
 */
import { describe, expect, it } from 'bun:test';
import { evaluateSarif, inspectSarif } from '../../../scripts/check-sarif.js';

function report(severity?: string) {
  return {
    version: '2.1.0',
    runs: [
      {
        invocations: [{ executionSuccessful: true }],
        tool: {
          driver: {
            rules: [
              {
                id: 'js/example',
                properties: { 'security-severity': severity },
              },
            ],
          },
        },
        results: severity === undefined ? [] : [{ ruleId: 'js/example' }],
      },
    ],
  };
}

describe('CodeQL result gate', () => {
  it('accepts complete clean and explicitly lower-severity analyses', () => {
    expect(evaluateSarif(report())).toBe('allowed');
    expect(evaluateSarif(report('6.9'))).toBe('allowed');
  });
  for (const severity of ['7', '7.0', '9.9', '10']) {
    it(`blocks security severity ${severity}`, () => {
      expect(evaluateSarif(report(severity))).toBe('findings');
    });
  }
  for (const severity of ['', '-1', 'NaN', 'unknown', '10.1']) {
    it(`blocks unsupported severity ${severity}`, () => {
      expect(evaluateSarif(report(severity))).toBe('error');
    });
  }
  it('blocks empty, truncated and failed reports', () => {
    expect(evaluateSarif({})).toBe('error');
    expect(evaluateSarif({ version: '2.1.0', runs: [] })).toBe('error');
    const failed = report();
    failed.runs[0]!.invocations[0]!.executionSuccessful = false;
    expect(evaluateSarif(failed)).toBe('error');
    failed.runs[0]!.invocations = [];
    expect(evaluateSarif(failed)).toBe('error');
  });
  it('blocks a result whose rule metadata is missing', () => {
    const partial = report('8.0');
    partial.runs[0]!.tool.driver.rules = [];
    expect(evaluateSarif(partial)).toBe('error');
  });
  it('reports every rejection class with fixed payload-free reasons', () => {
    const clean = report('6');
    const run = clean.runs[0]!;
    const wrap = (value: unknown) => ({ ...clean, runs: [value] });
    const cases: [unknown, ReturnType<typeof inspectSarif>['reason']][] = [
      [{}, 'root-shape'],
      [wrap({ ...run, invocations: [] }), 'run-shape'],
      [
        wrap({ ...run, invocations: [{ executionSuccessful: false }] }),
        'unsuccessful-invocation',
      ],
      [
        wrap({
          ...run,
          invocations: [
            {
              executionSuccessful: true,
              toolExecutionNotifications: [
                { level: 'error', message: { text: 'PRIVATE_FIXTURE_MARKER' } },
              ],
            },
          ],
        }),
        'notifications',
      ],
      [wrap({ ...run, results: [{ ruleId: 9 }] }), 'result-shape'],
      [
        wrap({ ...run, results: [{ ruleId: 'PRIVATE_FIXTURE_MARKER' }] }),
        'missing-rule',
      ],
      [report('PRIVATE_FIXTURE_MARKER'), 'unsupported-severity'],
    ];
    for (const [input, reason] of cases) {
      const diagnostic = inspectSarif(input);
      expect(diagnostic.outcome).toBe('error');
      expect(diagnostic.reason).toBe(reason);
      expect(evaluateSarif(input)).toBe('error');
      expect(JSON.stringify(diagnostic)).not.toContain(
        'PRIVATE_FIXTURE_MARKER',
      );
      expect(JSON.stringify(diagnostic).length).toBeLessThan(512);
    }
    expect(inspectSarif(wrap({ ...run, invocations: [] }))).toMatchObject({
      run: 0,
      invocations: 0,
      present: { invocations: true, results: true, driver: true, rules: true },
    });
    expect(inspectSarif(report())).toEqual({
      outcome: 'allowed',
      reason: 'allowed',
    });
    expect(inspectSarif(report('7'))).toEqual({
      outcome: 'findings',
      reason: 'security-findings',
    });
  });
});

const COMPONENT_GUID = '11111111-1111-4111-8111-111111111111';
const RULE_GUID = '22222222-2222-4222-8222-222222222222';
const OTHER_GUID = '33333333-3333-4333-8333-333333333333';

/** Representative grouped CodeQL layout; all identifiers are synthetic fixtures. */
function grouped(severity: unknown = '6.9') {
  const descriptor: Record<string, unknown> = {
    id: 'js/example',
    guid: RULE_GUID,
    properties: { 'security-severity': severity },
  };
  const extension: Record<string, unknown> = {
    name: 'example/query-pack',
    guid: COMPONENT_GUID,
    rules: [descriptor],
  };
  const driver: Record<string, unknown> = { name: 'CodeQL', rules: [] };
  const result: Record<string, unknown> = {
    ruleId: 'js/example',
    ruleIndex: 0,
    rule: {
      id: 'js/example',
      index: 0,
      toolComponent: {
        index: 0,
        guid: COMPONENT_GUID,
        name: 'example/query-pack',
      },
    },
  };
  const run: Record<string, unknown> = {
    invocations: [{ executionSuccessful: true }],
    tool: { driver, extensions: [extension] },
    results: [result],
  };
  return {
    value: { version: '2.1.0', runs: [run] },
    run,
    result,
    descriptor,
    extension,
    driver,
  };
}

/** Preserve the explicitly supported project legacy DRIVER-ID compatibility. */
function legacy(result: Record<string, unknown>) {
  const base = report('6.9');
  const run = base.runs[0]!;
  return { ...base, runs: [{ ...run, results: [result] }] };
}

describe('selected SARIF rule catalogs', () => {
  for (const [severity, outcome] of [
    ['0', 'allowed'],
    ['6.9', 'allowed'],
    ['7', 'findings'],
    ['9.9', 'findings'],
    ['10', 'findings'],
  ] as const) {
    it('evaluates grouped severity ' + severity, () => {
      expect(evaluateSarif(grouped(severity).value)).toBe(outcome);
    });
  }
  it('retains error-level blocking for a lower numeric severity', () => {
    const fixture = grouped('1.2');
    fixture.result.level = 'error';
    const diagnostic = inspectSarif(fixture.value);
    expect(diagnostic.outcome).toBe('findings');
    expect(diagnostic.severity).toEqual({
      type: 'string',
      valid: true,
      value: 1.2,
    });
  });
  it('uses the selected extension even when the driver has the same ID', () => {
    const fixture = grouped();
    fixture.driver.rules = [
      { id: 'js/example', properties: { 'security-severity': '10' } },
    ];
    expect(evaluateSarif(fixture.value)).toBe('allowed');
    fixture.run.results = [{ ruleId: 'js/example' }];
    expect(evaluateSarif(fixture.value)).toBe('findings');
  });
  it('does not search a different extension with the same ID', () => {
    const fixture = grouped();
    fixture.run.tool = {
      driver: fixture.driver,
      extensions: [
        { ...fixture.extension, rules: [] },
        { ...fixture.extension, guid: OTHER_GUID },
      ],
    };
    expect(evaluateSarif(fixture.value)).toBe('error');
  });
  it('resolves component and descriptor GUIDs with legitimate unset indices', () => {
    const fixture = grouped();
    fixture.result.ruleIndex = -1;
    fixture.result.rule = {
      id: 'js/example',
      index: -1,
      guid: RULE_GUID.toUpperCase(),
      toolComponent: { index: -1, guid: COMPONENT_GUID.toUpperCase() },
    };
    expect(evaluateSarif(fixture.value)).toBe('allowed');
  });
  it('resolves a driver index with legacy defaults and an explicit driver reference', () => {
    expect(evaluateSarif(legacy({ ruleId: 'js/example', ruleIndex: 0 }))).toBe(
      'allowed',
    );
    expect(
      evaluateSarif(
        legacy({ ruleId: 'js/example', ruleIndex: 0, rule: { index: 0 } }),
      ),
    ).toBe('allowed');
    expect(
      evaluateSarif(
        legacy({
          ruleId: 'js/example',
          rule: { index: 0, toolComponent: { index: -1 } },
        }),
      ),
    ).toBe('allowed');
  });
  it('uses a descriptor index to disambiguate duplicate IDs within one catalog', () => {
    const fixture = grouped();
    fixture.extension.rules = [
      { id: 'js/example', properties: { 'security-severity': '10' } },
      { ...fixture.descriptor, guid: OTHER_GUID },
    ];
    fixture.result.ruleIndex = 1;
    fixture.result.rule = { index: 1, toolComponent: { index: 0 } };
    expect(evaluateSarif(fixture.value)).toBe('allowed');
  });
  it('permits only the specified single hierarchical identifier component', () => {
    const fixture = grouped();
    fixture.result.ruleId = 'js/example/subrule';
    fixture.result.rule = {
      id: 'js/example/subrule',
      index: 0,
      toolComponent: { index: 0 },
    };
    expect(evaluateSarif(fixture.value)).toBe('allowed');
    for (const id of ['js/examples', 'js/example/', 'js/example/a/b']) {
      fixture.result.ruleId = id;
      fixture.result.rule = { id, index: 0, toolComponent: { index: 0 } };
      expect(evaluateSarif(fixture.value)).toBe('error');
    }
  });
  for (const field of ['id', 'index'] as const) {
    it('rejects conflicting legacy and explicit ' + field, () => {
      const fixture = grouped();
      fixture.result.rule = {
        id: field === 'id' ? 'different' : 'js/example',
        index: field === 'index' ? 1 : 0,
        toolComponent: { index: 0 },
      };
      expect(evaluateSarif(fixture.value)).toBe('error');
    });
  }
  for (const badIndex of [
    -2,
    0.5,
    1,
    1_000_000,
    '0',
    null,
    undefined,
    NaN,
    Infinity,
  ]) {
    it(
      'rejects an invalid or out-of-range descriptor index ' + String(badIndex),
      () => {
        const fixture = grouped();
        delete fixture.result.ruleIndex;
        fixture.result.rule = { index: badIndex, toolComponent: { index: 0 } };
        expect(evaluateSarif(fixture.value)).toBe('error');
      },
    );
    it(
      'rejects an invalid or out-of-range legacy index ' + String(badIndex),
      () => {
        expect(
          evaluateSarif(legacy({ ruleId: 'js/example', ruleIndex: badIndex })),
        ).toBe('error');
      },
    );
  }
  for (const badIndex of [-2, 0.5, 1, '0', null, undefined, NaN, Infinity]) {
    it(
      'rejects an invalid or out-of-range component index ' + String(badIndex),
      () => {
        const fixture = grouped();
        fixture.result.rule = { index: 0, toolComponent: { index: badIndex } };
        expect(evaluateSarif(fixture.value)).toBe('error');
      },
    );
  }
  for (const toolComponent of [
    null,
    undefined,
    [],
    { index: 0, name: 'different' },
    { index: 0, guid: OTHER_GUID },
    { index: 0, guid: 'invalid' },
    { name: 'example/query-pack' },
  ]) {
    it('rejects malformed, inconsistent or unresolved component references', () => {
      const fixture = grouped();
      fixture.result.rule = { index: 0, toolComponent };
      expect(evaluateSarif(fixture.value)).toBe('error');
    });
  }
  it('rejects ambiguous component GUIDs even with an explicit index', () => {
    const fixture = grouped();
    fixture.run.tool = {
      driver: fixture.driver,
      extensions: [fixture.extension, { ...fixture.extension }],
    };
    expect(evaluateSarif(fixture.value)).toBe('error');
  });
  it('rejects missing, mismatched or ambiguous descriptor GUIDs', () => {
    for (const value of [OTHER_GUID, 'invalid', undefined]) {
      const fixture = grouped();
      fixture.result.rule = {
        index: 0,
        guid: value,
        toolComponent: { index: 0 },
      };
      expect(evaluateSarif(fixture.value)).toBe('error');
    }
    const fixture = grouped();
    fixture.extension.rules = [fixture.descriptor, { ...fixture.descriptor }];
    fixture.result.rule = {
      index: 0,
      guid: RULE_GUID,
      toolComponent: { index: 0 },
    };
    expect(evaluateSarif(fixture.value)).toBe('error');
  });
  it('does not use an ID-only lookup for an explicit rule', () => {
    const fixture = grouped();
    delete fixture.result.ruleIndex;
    fixture.result.rule = { id: 'js/example', toolComponent: { index: 0 } };
    expect(evaluateSarif(fixture.value)).toBe('error');
  });
  for (const rules of [
    undefined,
    null,
    {},
    [null],
    [{ id: '' }],
    [{ id: 7 }],
  ]) {
    it('rejects missing or malformed selected catalogs and descriptors', () => {
      const fixture = grouped();
      fixture.extension.rules = rules;
      expect(evaluateSarif(fixture.value)).toBe('error');
    });
  }
  it('rejects missing extensions and unresolved external metadata without fetching', () => {
    const fixture = grouped();
    fixture.run.tool = { driver: fixture.driver };
    expect(evaluateSarif(fixture.value)).toBe('error');
    for (const field of ['driver', 'extensions', 'results', 'invocations']) {
      const external = grouped();
      external.run.externalPropertyFileReferences = {
        [field]:
          field === 'driver'
            ? {}
            : [{ location: { uri: 'https://example.invalid/catalog' } }],
      };
      expect(evaluateSarif(external.value)).toBe('error');
    }
  });
  for (const severity of [
    undefined,
    null,
    0,
    6.9,
    {},
    [],
    '',
    '-1',
    'NaN',
    'unknown',
    '10.1',
  ]) {
    it(
      'rejects missing or unsupported grouped severity ' + String(severity),
      () => {
        const fixture = grouped();
        fixture.descriptor.properties = { 'security-severity': severity };
        expect(evaluateSarif(fixture.value)).toBe('error');
      },
    );
  }
  it('evaluates later results and invocations after a blocking finding', () => {
    const fixture = grouped('10');
    fixture.run.results = [fixture.result, { ruleId: 'missing', ruleIndex: 0 }];
    expect(evaluateSarif(fixture.value)).toBe('error');
    fixture.run.results = [fixture.result];
    fixture.run.invocations = [
      { executionSuccessful: true },
      { executionSuccessful: false },
    ];
    expect(evaluateSarif(fixture.value)).toBe('error');
  });
  it('does not suppress blocking findings', () => {
    const fixture = grouped('8');
    fixture.result.suppressions = [{ status: 'accepted', kind: 'external' }];
    expect(evaluateSarif(fixture.value)).toBe('findings');
  });
  it('bounds input collections without truncating them to a passing report', () => {
    const fixture = grouped();
    fixture.run.results = Array(100_001).fill(fixture.result);
    expect(inspectSarif(fixture.value).reason).toBe('limits');
    fixture.run.results = [fixture.result];
    fixture.extension.rules = Array(100_001).fill(fixture.descriptor);
    expect(inspectSarif(fixture.value).reason).toBe('limits');
    fixture.extension.rules = [fixture.descriptor];
    fixture.run.tool = {
      driver: fixture.driver,
      extensions: Array(256).fill(fixture.extension),
    };
    expect(inspectSarif(fixture.value).reason).toBe('limits');
    fixture.run.tool = {
      driver: fixture.driver,
      extensions: [fixture.extension],
    };
    fixture.run.invocations = Array(4097).fill({ executionSuccessful: true });
    expect(inspectSarif(fixture.value).reason).toBe('limits');
    fixture.run.invocations = [
      {
        executionSuccessful: true,
        toolExecutionNotifications: Array(100_001).fill({ level: 'note' }),
      },
    ];
    expect(inspectSarif(fixture.value).reason).toBe('limits');
    expect(
      inspectSarif({ version: '2.1.0', runs: Array(129).fill(fixture.run) })
        .reason,
    ).toBe('limits');
  });
  it('projects only fixed field types, catalog counts and validated severity', () => {
    const fixture = grouped('PRIVATE_FIXTURE_MARKER');
    fixture.result.rule = {
      index: 0,
      toolComponent: { index: 0, name: 'PRIVATE_FIXTURE_MARKER' },
    };
    const diagnostic = inspectSarif(fixture.value);
    expect(diagnostic.outcome).toBe('error');
    expect(diagnostic.catalogs).toEqual([
      { rules: 'array', count: 0 },
      { rules: 'array', count: 1 },
    ]);
    expect(diagnostic.reference).toMatchObject({
      rule: 'object',
      componentName: 'string',
    });
    expect(JSON.stringify(diagnostic)).not.toContain('PRIVATE_FIXTURE_MARKER');
    expect(JSON.stringify(diagnostic).length).toBeLessThan(2048);
    fixture.result.rule = { index: 0, toolComponent: { index: 0 } };
    expect(inspectSarif(fixture.value).severity).toEqual({
      type: 'string',
      valid: false,
    });
    expect(JSON.stringify(inspectSarif(fixture.value))).not.toContain(
      'PRIVATE_FIXTURE_MARKER',
    );
  });
});

describe('bounded project legacy DRIVER-ID compatibility', () => {
  it('retains original ID-only policy including legitimate unset -1', () => {
    expect(evaluateSarif(legacy({ ruleId: 'js/example', ruleIndex: -1 }))).toBe(
      'allowed',
    );
    for (const severity of ['7', '9.9', '10']) {
      expect(evaluateSarif(report(severity))).toBe('findings');
    }
  });
  it('rejects exact duplicate IDs instead of selecting the first descriptor', () => {
    const value = legacy({ ruleId: 'js/example' });
    value.runs[0]!.tool.driver.rules.push(value.runs[0]!.tool.driver.rules[0]!);
    expect(evaluateSarif(value)).toBe('error');
  });
  for (const id of [
    '',
    'missing',
    'JS/example',
    ' js/example',
    'js/example/subrule',
  ]) {
    it('rejects missing, nonexact or hierarchical legacy ID ' + id, () => {
      expect(evaluateSarif(legacy({ ruleId: id }))).toBe('error');
    });
  }
  it('does not search extensions when the legacy ID is absent from the driver', () => {
    const fixture = grouped();
    fixture.run.results = [{ ruleId: 'js/example' }];
    expect(evaluateSarif(fixture.value)).toBe('error');
  });
  for (const rule of [
    null,
    undefined,
    {},
    [],
    '',
    0,
    { id: 'js/example' },
    { index: -1 },
    { index: 1 },
    { index: 0, id: 'different' },
  ]) {
    it('never falls back after a present invalid or conflicting explicit rule', () => {
      expect(evaluateSarif(legacy({ ruleId: 'js/example', rule }))).toBe(
        'error',
      );
    });
  }
  it('rejects malformed driver metadata even on the compatibility path', () => {
    const value = legacy({ ruleId: 'js/example' });
    value.runs[0]!.tool.driver.rules = [];
    expect(evaluateSarif(value)).toBe('error');
    value.runs[0]!.tool.driver.rules = [
      { id: '', properties: { 'security-severity': '6' } },
    ];
    expect(evaluateSarif(value)).toBe('error');
  });
});
