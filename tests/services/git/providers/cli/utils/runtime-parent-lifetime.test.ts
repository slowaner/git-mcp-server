/**
 * @fileoverview Qualified cleanup guards for disposable supervisor-parent tests.
 * @module tests/services/git/providers/cli/utils/runtime-parent-lifetime.test
 */
import assert from 'node:assert/strict';
import {
  execFileSync,
  spawn,
  type ChildProcessWithoutNullStreams,
} from 'node:child_process';
import { randomUUID } from 'node:crypto';
import {
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, afterEach, before, describe, it } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

import { GIT_PROCESS_HOST_SOURCE } from '../../../../../../src/services/git/providers/cli/utils/process-host.js';

interface ProcessRow {
  pid: number;
  ppid: number;
  pgid: number;
  uid: number;
  state: string;
  start: string;
  command: string;
}
interface Ready {
  nonce: string;
  pid: number;
  anchor: number;
  runtime: string;
  hardStopAt: number;
}
interface Driver {
  child: ChildProcessWithoutNullStreams;
  directory: string;
  nonce: string;
  closed: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
  ready?: Ready;
  anchor?: ProcessRow;
}

const uid = process.getuid?.();
if (uid === undefined) throw new Error('POSIX fixture profile required');

function processes(group: number): ProcessRow[] {
  const output = execFileSync(
    '/bin/ps',
    [
      '-ww',
      '-p',
      String(process.pid),
      '-g',
      String(group),
      '-o',
      'pid=,ppid=,pgid=,uid=,stat=,lstart=,command=',
    ],
    { encoding: 'utf8', timeout: 1000, maxBuffer: 16384 },
  );
  const rows = output
    .trim()
    .split('\n')
    .map((line) => {
      const match = line
        .trim()
        .match(
          /^(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+)$/,
        );
      assert.ok(match, 'complete process identity row');
      return {
        pid: Number(match[1]),
        ppid: Number(match[2]),
        pgid: Number(match[3]),
        uid: Number(match[4]),
        state: match[5]!,
        start: match[6]!.replace(/\s+/g, ' '),
        command: match[7]!,
      };
    });
  assert.ok(
    rows.some((row) => row.pid === process.pid),
    'positive query control',
  );
  return rows.filter((row) => row.pgid === group);
}

async function jsonIfPresent(file: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(file, 'utf8')) as unknown;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
}

async function waitFor<T>(
  read: () => Promise<T | undefined>,
  timeout: number,
): Promise<T> {
  const end = Date.now() + timeout;
  do {
    const value = await read();
    if (value !== undefined) {
      assert.ok(
        Date.now() <= end,
        'fixture observation completed within bound',
      );
      return value;
    }
    await delay(20);
  } while (Date.now() < end);
  throw new Error('Bounded fixture observation expired');
}

async function within<T>(
  promise: Promise<T>,
  milliseconds: number,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new Error('Disposable driver did not settle')),
          milliseconds,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

describe('qualified parent-lifetime fixtures', { timeout: 60000 }, () => {
  let artifacts: string;
  let driverFile: string;
  let helperFile: string;
  const runtimePaths: Record<string, string> = {};
  const directories: string[] = [];
  const settled = new Set<string>();
  const retained: string[] = [];
  before(async () => {
    // Fail before creating a disposable driver if the supported inspection
    // profile is unavailable. Errors never become process absence.
    processes(process.pid);
    artifacts = await realpath(
      await mkdtemp(path.join(tmpdir(), 'git-parent-build-')),
    );
    driverFile = path.join(artifacts, 'driver.mjs');
    helperFile = path.join(artifacts, 'helper.mjs');
    for (const runtime of ['node', 'bun']) {
      runtimePaths[runtime] = execFileSync('/usr/bin/which', [runtime], {
        encoding: 'utf8',
      }).trim();
    }
    for (const [source, target] of [
      ['parent-lifetime-driver.ts', driverFile],
      ['parent-lifetime-helper.ts', helperFile],
    ]) {
      execFileSync(
        runtimePaths.bun!,
        [
          'build',
          path.resolve(
            'tests/services/git/providers/cli/utils/fixtures',
            source!,
          ),
          '--target=node',
          '--outfile',
          target!,
        ],
        { stdio: 'pipe' },
      );
    }
  });
  afterEach(async () => {
    for (const directory of directories.splice(0)) {
      if (settled.has(directory))
        await rm(directory, { recursive: true, force: true });
      else retained.push(directory);
    }
  });
  after(async () => {
    // Never remove an unconfirmed fixture's armed safety guard or executable.
    if (artifacts && retained.length === 0)
      await rm(artifacts, { recursive: true, force: true });
  });

  const start = async (runtime: string): Promise<Driver> => {
    assert.equal(
      retained.length,
      0,
      'earlier fixture cleanup is still uncertain',
    );
    const directory = await realpath(
      await mkdtemp(path.join(tmpdir(), 'git-parent-life-')),
    );
    directories.push(directory);
    const nonce = randomUUID();
    const child = spawn(
      runtimePaths[runtime]!,
      [driverFile, directory, helperFile, nonce],
      {
        cwd: directory,
        env: {},
        stdio: 'pipe',
      },
    );
    child.stdout.on('data', () => {});
    child.stderr.on('data', () => {});
    const closed = new Promise<{
      code: number | null;
      signal: NodeJS.Signals | null;
    }>((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => resolve({ code, signal }));
    });
    return { child, closed, directory, nonce };
  };

  const prepare = async (driver: Driver) => {
    const ready = (await waitFor(
      () => jsonIfPresent(path.join(driver.directory, 'ready.json')),
      2000,
    )) as Ready;
    assert.equal(ready.nonce, driver.nonce);
    assert.ok(Number.isSafeInteger(ready.anchor) && ready.anchor > 1);
    assert.ok(Number.isSafeInteger(ready.pid) && ready.pid > 1);
    const rows = processes(ready.anchor);
    const anchor = rows.find((row) => row.pid === ready.anchor);
    const helper = rows.find((row) => row.pid === ready.pid);
    assert.ok(anchor && helper);
    assert.equal(anchor.ppid, driver.child.pid);
    assert.equal(anchor.pgid, anchor.pid);
    assert.equal(helper.ppid, anchor.pid);
    assert.equal(helper.pgid, anchor.pid);
    assert.ok(
      rows.every(
        (row) =>
          row.uid === uid &&
          !row.state.includes('Z') &&
          (row.pid === anchor.pid || row.pid === helper.pid),
      ),
    );
    const normalize = (value: string) =>
      value.replaceAll('\\012', '\n').replace(/\s+/g, ' ').trim();
    assert.equal(
      normalize(anchor.command),
      normalize(
        ready.runtime +
          ' -e ' +
          GIT_PROCESS_HOST_SOURCE +
          ' -- ' +
          driver.directory +
          ' ' +
          ready.runtime +
          ' ' +
          helperFile +
          ' ' +
          driver.nonce,
      ),
    );
    assert.equal(
      helper.command,
      ready.runtime + ' ' + helperFile + ' ' + driver.nonce,
    );
    driver.ready = ready;
    driver.anchor = anchor;
    const heartbeat = await readFile(
      path.join(driver.directory, 'heartbeat'),
      'utf8',
    );
    assert.ok(heartbeat.length > 0);
    await delay(150);
    assert.equal(driver.child.exitCode, null, 'driver remains alive');
    assert.equal(driver.child.signalCode, null);
    assert.ok(
      (await readFile(path.join(driver.directory, 'heartbeat'), 'utf8'))
        .length > heartbeat.length,
    );
    await writeFile(
      path.join(driver.directory, 'guard-arm.tmp'),
      JSON.stringify({
        nonce: driver.nonce,
        pid: ready.pid,
        anchor: ready.anchor,
        driver: driver.child.pid,
        uid,
        start: anchor.start,
        command: anchor.command,
      }),
      { flag: 'wx', mode: 0o600 },
    );
    await rename(
      path.join(driver.directory, 'guard-arm.tmp'),
      path.join(driver.directory, 'guard-arm.json'),
    );
  };

  const quiescent = async (driver: Driver, timeout: number) => {
    assert.ok(driver.ready);
    await waitFor(
      async () =>
        processes(driver.ready!.anchor).some((row) => !row.state.includes('Z'))
          ? undefined
          : true,
      timeout,
    );
    const heartbeat = path.join(driver.directory, 'heartbeat');
    const before = await readFile(heartbeat, 'utf8');
    await delay(100);
    assert.equal(await readFile(heartbeat, 'utf8'), before);
  };

  const withDriver = async (
    runtime: string,
    operation: (driver: Driver) => Promise<void>,
  ) => {
    const driver = await start(runtime);
    try {
      await operation(driver);
    } finally {
      // No guessed PID/group fallback: retain a live driver for its established
      // orderly abort, or await the previously armed independent hardstop.
      try {
        if (driver.child.exitCode === null && driver.child.signalCode === null)
          driver.child.stdin.write('abort\n');
        await within(driver.closed, 6000);
        if (driver.ready) await quiescent(driver, 5000);
        else {
          const result = (await jsonIfPresent(
            path.join(driver.directory, 'driver-result.json'),
          )) as { reason: string } | undefined;
          assert.equal(
            result?.reason,
            'CANCELLED',
            'orderly abort before trusted identity',
          );
        }
        settled.add(driver.directory);
      } catch (error) {
        throw new Error(
          'Owned fixture cleanup remains uncertain: ' + driver.directory,
          { cause: error },
        );
      }
    }
  };

  const qualifyFinally = async (runtime: string) => {
    const expected = new Error('controlled assertion-path exit');
    let observed: Driver | undefined;
    await assert.rejects(
      withDriver(runtime, async (driver) => {
        observed = driver;
        await prepare(driver);
        throw expected;
      }),
      (error: unknown) => error === expected,
    );
    assert.ok(observed);
    const result = (await jsonIfPresent(
      path.join(observed.directory, 'driver-result.json'),
    )) as { reason: string };
    assert.equal(result.reason, 'CANCELLED');
    assert.equal(
      await jsonIfPresent(path.join(observed.directory, 'guard-fired.json')),
      undefined,
    );
    assert.equal(
      await jsonIfPresent(path.join(observed.directory, 'guard-error')),
      undefined,
    );
  };

  const qualifyHardstop = async (runtime: string) => {
    await withDriver(runtime, async (driver) => {
      await prepare(driver);
      const result = (await waitFor(
        () => jsonIfPresent(path.join(driver.directory, 'driver-result.json')),
        6000,
      )) as { reason: string };
      assert.equal(result.reason, 'CLEANUP_FAILED');
      const guard = (await jsonIfPresent(
        path.join(driver.directory, 'guard-fired.json'),
      )) as { nonce: string };
      assert.equal(guard.nonce, driver.nonce);
      await quiescent(driver, 1000);
    });
  };

  for (const runtime of ['node', 'bun']) {
    it(
      runtime +
        ': qualifies controller finally with live orderly abort and no guard firing',
      { timeout: 15000 },
      () => qualifyFinally(runtime),
    );

    it(
      runtime +
        ': qualifies the independent hardstop while the supervisor driver stays live',
      { timeout: 15000 },
      () => qualifyHardstop(runtime),
    );

    it(
      runtime +
        ': autonomously tears down after abrupt disposable parent death',
      { timeout: 15000 },
      async () => {
        // Qualify this runtime in the current execution before each destructive
        // case; test ordering or a previous run cannot grant that safety proof.
        await qualifyFinally(runtime);
        await qualifyHardstop(runtime);
        await withDriver(runtime, async (driver) => {
          await prepare(driver);
          assert.ok(driver.ready && driver.anchor);
          const fresh = processes(driver.ready.anchor);
          const freshAnchor = fresh.find(
            (row) => row.pid === driver.ready!.anchor,
          );
          assert.ok(freshAnchor && !/[ZX]/.test(freshAnchor.state));
          const { state: _freshState, ...freshIdentity } = freshAnchor;
          const { state: _readyState, ...readyIdentity } = driver.anchor;
          assert.deepEqual(
            freshIdentity,
            readyIdentity,
            'same live owned anchor immediately before parent death',
          );
          assert.equal(driver.child.exitCode, null);
          assert.equal(driver.child.signalCode, null);
          assert.ok(
            driver.ready.hardStopAt - Date.now() > 2000,
            'independent guard cannot supply the one-second success oracle',
          );

          const started = Date.now();
          // The trusted disposable driver kills only itself. No live MCP/user
          // service or guessed positive PID/group is signalled by this test.
          driver.child.stdin.write('die\n');
          const exit = await within(driver.closed, 1000);
          assert.equal(exit.code, null);
          assert.equal(exit.signal, 'SIGKILL');
          await quiescent(driver, Math.max(1, 1000 - (Date.now() - started)));
          assert.ok(Date.now() - started <= 1000);
          assert.equal(
            await jsonIfPresent(
              path.join(driver.directory, 'driver-result.json'),
            ),
            undefined,
            'the parent could not perform orderly operation cleanup',
          );
          assert.equal(
            await jsonIfPresent(
              path.join(driver.directory, 'guard-fired.json'),
            ),
            undefined,
            'fallback cleanup cannot manufacture production success',
          );
          assert.equal(
            await jsonIfPresent(path.join(driver.directory, 'guard-error')),
            undefined,
          );
          // All success assertions run before withDriver's finally fallback.
        });
      },
    );
  }
});
