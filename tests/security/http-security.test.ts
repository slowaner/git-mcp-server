/**
 * @fileoverview HTTP parsing, peer trust, domain and fair admission boundary regressions.
 * @module tests/security/http-security
 */
import { describe, expect, spyOn, test } from 'bun:test';
import { HttpAdmission } from '../../src/mcp-server/transports/http/httpAdmission.js';
import {
  assertInputBudget,
  HttpSecuritySchema,
  ToolInputLimitsSchema,
  readBoundedJson,
  validateHttpPeer,
} from '../../src/mcp-server/transports/http/httpSecurity.js';
import { boundToolInputSchema } from '../../src/mcp-server/tools/utils/input-budget.js';
import { z } from 'zod';
import { gitAddTool } from '../../src/mcp-server/tools/definitions/git-add.tool.js';
import { gitResetTool } from '../../src/mcp-server/tools/definitions/git-reset.tool.js';

const limits = ToolInputLimitsSchema.parse({});
const policy = HttpSecuritySchema.parse({});
const request = (text: string) =>
  new Request('http://localhost/mcp', { method: 'POST', body: text });

describe('peer trust', () => {
  test('schema canonicalizes DNS/IPv6 authorities before peer comparison', () => {
    const configured = HttpSecuritySchema.parse({
      allowedHosts: [
        'LOCALHOST:3015',
        'MiXeD.ExAmPlE:8443',
        '[2001:DB8::1]:3015',
      ],
    });
    expect(configured.allowedHosts).toEqual([
      'localhost:3015',
      'mixed.example:8443',
      '[2001:db8::1]:3015',
    ]);
    for (const host of [
      'LoCaLhOsT:3015',
      'MIXED.example:8443',
      '[2001:DB8::1]:3015',
    ])
      expect(() =>
        validateHttpPeer(
          new Request('http://localhost/mcp', { headers: { host } }),
          configured.allowedHosts,
          [],
          true,
        ),
      ).not.toThrow();
    for (const host of [
      'mixed.example:3015',
      'mixed.example.evil:8443',
      '[2001:db8::2]:3015',
    ])
      expect(() =>
        validateHttpPeer(
          new Request('http://localhost/mcp', { headers: { host } }),
          configured.allowedHosts,
          [],
          true,
        ),
      ).toThrow('Host');
    for (const host of [
      'user@mixed.example:8443',
      'mixed.example:8443/path',
      '*.example',
    ])
      expect(
        HttpSecuritySchema.safeParse({ allowedHosts: [host] }).success,
      ).toBe(false);
  });
  test('exact authority and approved Origin; native absence explicitly allowed', () => {
    for (const origin of [undefined, 'https://client.example']) {
      const headers = new Headers({ host: '[::1]:3015' });
      if (origin) headers.set('origin', origin);
      expect(() =>
        validateHttpPeer(
          new Request('http://[::1]:3015/mcp', { headers }),
          ['[::1]:3015'],
          ['https://client.example'],
          true,
        ),
      ).not.toThrow();
    }
  });
  test('null, foreign, missing Origin and hostile Host cannot rely on forwarding', () => {
    for (const origin of ['null', 'https://evil.example', undefined]) {
      const headers = new Headers({ host: 'localhost:3015' });
      if (origin) headers.set('origin', origin);
      expect(() =>
        validateHttpPeer(
          new Request('http://localhost/mcp', { headers }),
          ['localhost:3015'],
          ['https://client.example'],
          false,
        ),
      ).toThrow('Origin');
    }
    expect(() =>
      validateHttpPeer(
        new Request('http://evil.example/mcp', {
          headers: {
            host: 'evil.example',
            'x-forwarded-host': 'localhost:3015',
          },
        }),
        ['localhost:3015'],
        [],
        true,
      ),
    ).toThrow('Host');
  });
});

describe('bounded body', () => {
  test('highly fragmented body attaches only one deadline race', async () => {
    const maxBodyBytes = 65536;
    const text = '{"value":0}'.padEnd(maxBodyBytes, ' ');
    let chunks = 0;
    let cancelled = 0;
    const body = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          if (chunks === text.length) controller.close();
          else controller.enqueue(Uint8Array.of(text.charCodeAt(chunks++)));
        },
        cancel() {
          cancelled++;
        },
      },
      { highWaterMark: 0 },
    );
    const race = spyOn(Promise, 'race');
    try {
      expect(
        await readBoundedJson(
          new Request('http://localhost', {
            method: 'POST',
            body,
            duplex: 'half',
          } as RequestInit),
          { ...policy, maxBodyBytes },
          limits,
        ),
      ).toEqual({ value: 0 });
      expect(chunks).toBe(maxBodyBytes);
      // Per-chunk races retain reactions on the same pending deadline promise.
      // One lifecycle race bounds these subscriptions independently of fragmentation.
      expect(race).toHaveBeenCalledTimes(1);
      expect(body.locked).toBe(false);
      expect(cancelled).toBe(0);
    } finally {
      race.mockRestore();
    }
  });

  test('oversized and invalid UTF-8 streams cancel and release their reader', async () => {
    for (const [bytes, message] of [
      [new TextEncoder().encode('{} '), 'byte limit'],
      [Uint8Array.of(0xff), 'Invalid JSON'],
    ] as const) {
      let sent = false;
      let cancelled = 0;
      const body = new ReadableStream<Uint8Array>(
        {
          pull(controller) {
            if (!sent) {
              sent = true;
              controller.enqueue(bytes);
            }
          },
          cancel() {
            cancelled++;
          },
        },
        { highWaterMark: 0 },
      );
      await expect(
        readBoundedJson(
          new Request('http://localhost', {
            method: 'POST',
            body,
            duplex: 'half',
          } as RequestInit),
          { ...policy, maxBodyBytes: 2 },
          limits,
        ),
      ).rejects.toThrow(message);
      expect(cancelled).toBe(1);
      expect(body.locked).toBe(false);
    }
  });

  test('deadline and abort clean listeners and release a reader even if cancellation stalls', async () => {
    for (const abort of [false, true]) {
      let cancelled = 0;
      const controller = new AbortController();
      const body = new ReadableStream<Uint8Array>({
        cancel() {
          cancelled++;
          return new Promise<void>(() => {});
        },
      });
      const input = new Request('http://localhost', {
        method: 'POST',
        body,
        duplex: 'half',
        signal: controller.signal,
      } as RequestInit);
      const removeListener = spyOn(input.signal, 'removeEventListener');
      try {
        const pending = readBoundedJson(
          input,
          { ...policy, bodyTimeoutMs: 15 },
          limits,
        );
        if (abort) controller.abort();
        await expect(pending).rejects.toThrow(abort ? 'aborted' : 'deadline');
        expect(cancelled).toBe(1);
        expect(body.locked).toBe(false);
        expect(removeListener).toHaveBeenCalledTimes(1);
      } finally {
        removeListener.mockRestore();
      }
    }
  });

  test('reader errors release the lock and aborted input cannot continue pulling', async () => {
    const failed = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.error(new Error('Synthetic read failure'));
      },
    });
    await expect(
      readBoundedJson(
        new Request('http://localhost', {
          method: 'POST',
          body: failed,
          duplex: 'half',
        } as RequestInit),
        policy,
        limits,
      ),
    ).rejects.toThrow('Invalid JSON');
    expect(failed.locked).toBe(false);
    let pulls = 0;
    let cancelled = 0;
    const controller = new AbortController();
    const body = new ReadableStream<Uint8Array>(
      {
        pull() {
          pulls++;
          controller.abort();
        },
        cancel() {
          cancelled++;
        },
      },
      { highWaterMark: 0 },
    );
    await expect(
      readBoundedJson(
        new Request('http://localhost', {
          method: 'POST',
          body,
          duplex: 'half',
          signal: controller.signal,
        } as RequestInit),
        policy,
        limits,
      ),
    ).rejects.toThrow('aborted');
    expect(pulls).toBe(1);
    expect(cancelled).toBe(1);
    expect(body.locked).toBe(false);
    await Promise.resolve();
    expect(pulls).toBe(1);
  });
  test('exact UTF-8 byte cap and cap+1, independent of Content-Length', async () => {
    const text = '{"value":"é"}';
    const maxBodyBytes = new TextEncoder().encode(text).byteLength;
    expect(
      await readBoundedJson(request(text), { ...policy, maxBodyBytes }, limits),
    ).toEqual({ value: 'é' });
    await expect(
      readBoundedJson(request(text + ' '), { ...policy, maxBodyBytes }, limits),
    ).rejects.toThrow('byte limit');
    await expect(
      readBoundedJson(
        new Request('http://localhost', {
          method: 'POST',
          headers: { 'content-length': '100' },
          body: '{}',
        }),
        { ...policy, maxBodyBytes },
        limits,
      ),
    ).rejects.toThrow('byte limit');
  });
  test('chunked multibyte split, batches, malformed and deeply nested input', async () => {
    const data = new TextEncoder().encode('{"v":"é"}');
    let index = 0;
    const stream = new ReadableStream({
      pull(c) {
        if (index < data.length) c.enqueue(data.slice(index, index++ + 1));
        else c.close();
      },
    });
    expect(
      await readBoundedJson(
        new Request('http://localhost', {
          method: 'POST',
          body: stream,
          duplex: 'half',
        } as RequestInit),
        policy,
        limits,
      ),
    ).toEqual({ v: 'é' });
    await expect(
      readBoundedJson(
        request('[{"jsonrpc":"2.0","method":"ping","id":1}]'),
        policy,
        limits,
      ),
    ).rejects.toThrow('batches');
    await expect(readBoundedJson(request('{'), policy, limits)).rejects.toThrow(
      'Invalid JSON',
    );
    await expect(
      readBoundedJson(
        request('['.repeat(17) + '0' + ']'.repeat(17)),
        policy,
        limits,
      ),
    ).rejects.toThrow('depth');
  });
  test('slow and disconnected streams cancel within total deadline', async () => {
    let cancelled = 0;
    const body = new ReadableStream({
      cancel() {
        cancelled++;
      },
    });
    await expect(
      readBoundedJson(
        new Request('http://localhost', {
          method: 'POST',
          body,
          duplex: 'half',
        } as RequestInit),
        { ...policy, bodyTimeoutMs: 15 },
        limits,
      ),
    ).rejects.toThrow('deadline');
    expect(cancelled).toBe(1);
    const controller = new AbortController();
    const pending = readBoundedJson(
      new Request('http://localhost', {
        method: 'POST',
        body: new ReadableStream({}),
        duplex: 'half',
        signal: controller.signal,
      } as RequestInit),
      policy,
      limits,
    );
    controller.abort();
    await expect(pending).rejects.toThrow('aborted');
  });
});

describe('domain validation before issue amplification', () => {
  test('production staging and reset schemas accept1000 paths and reject1001', () => {
    for (const tool of [gitAddTool, gitResetTool]) {
      const schema = boundToolInputSchema(tool.inputSchema, limits);
      expect(
        schema.safeParse({ path: '/repo', paths: Array(1000).fill('file.txt') })
          .success,
      ).toBe(true);
      expect(
        schema.safeParse({ path: '/repo', paths: Array(1001).fill('file.txt') })
          .success,
      ).toBe(false);
    }
  });
  test('array, record, depth, element and string exact cap plus one', () => {
    const budget = {
      ...limits,
      maxArrayLength: 2,
      maxRecordKeys: 2,
      maxElements: 4,
      maxDepth: 2,
      maxStringBytes: 2,
    };
    expect(() => assertInputBudget({ a: ['é', 0] }, budget)).not.toThrow();
    for (const value of [
      [0, 0, 0],
      { a: 0, b: 0, c: 0 },
      { a: { b: {} } },
      { a: [0, 0], b: [0, 0] },
      'éa',
    ])
      expect(() => assertInputBudget(value, budget)).toThrow();
  });
  test('schema caps preserve descriptions, defaults and existing stricter checks', () => {
    const schema = boundToolInputSchema(
      z.object({
        paths: z.array(z.string().min(1)).default([]).describe('Paths'),
      }),
      { ...limits, maxArrayLength: 2 },
    );
    expect(schema.parse({})).toEqual({ paths: [] });
    expect(schema.shape.paths.description).toBe('Paths');
    expect(schema.safeParse({ paths: ['a', 'b'] }).success).toBe(true);
    expect(schema.safeParse({ paths: ['a', 'b', 'c'] }).success).toBe(false);
    expect(schema.safeParse({ paths: [''] }).success).toBe(false);
  });
});

describe('fair non-queuing admission', () => {
  test('one principal saturates own share while another retains capacity; release idempotent', () => {
    const gate = new HttpAdmission({
      ...policy,
      maxRequests: 4,
      maxRequestsPerPrincipal: 2,
    });
    const a = gate.acquire('requests', 'a');
    const b = gate.acquire('requests', 'a');
    expect(() => gate.acquire('requests', 'a')).toThrow('Concurrent');
    const peer = gate.acquire('requests', 'b');
    expect(gate.snapshot().requests).toBe(3);
    a();
    a();
    b();
    peer();
    expect(gate.snapshot().requests).toBe(0);
  });
  test('pending init, sessions, SSE, rate and principal slots bounded without eviction', () => {
    const gate = new HttpAdmission({
      ...policy,
      maxPrincipals: 2,
      requestsPerMinute: 1,
    });
    const init = gate.acquire('initializations', 'a');
    expect(() => gate.acquire('initializations', 'a')).toThrow('Concurrent');
    gate.acquire('requests', 'a')();
    expect(() => gate.acquire('requests', 'a')).toThrow('rate');
    const session = gate.acquire('sessions', 'b');
    const streams = [
      gate.acquire('streams', 'b'),
      gate.acquire('streams', 'b'),
    ];
    expect(() => gate.acquire('streams', 'b')).toThrow('Concurrent');
    expect(() => gate.acquire('requests', 'c')).toThrow('accounting');
    init();
    session();
    streams.forEach((release) => release());
  });
  test('invalid zero, infinite and unfair config rejected', () => {
    for (const overrides of [
      { maxBodyBytes: 0 },
      { maxRequests: Infinity },
      { maxRequests: 4, maxRequestsPerPrincipal: 4 },
    ])
      expect(HttpSecuritySchema.safeParse(overrides).success).toBe(false);
  });
});
