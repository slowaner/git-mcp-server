/**
 * @fileoverview Real-process output, lifetime and execution-policy regressions.
 * @module tests/services/git/providers/cli/utils/runtime-security.test
 */
import assert from 'node:assert/strict';
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { GitExecutionError } from '../../../../../../src/services/git/providers/cli/utils/execution-errors.js';
import {
  getGitExecutionContext,
  withGitExecutionContext,
} from '../../../../../../src/services/git/providers/cli/utils/execution-context.js';
import {
  assertGitExecutionPolicy,
  buildTrustedGitEnvironment,
  type GitExecutionPolicy,
} from '../../../../../../src/services/git/providers/cli/utils/execution-policy.js';
import {
  superviseProcess,
  type SupervisedProcessOptions,
} from '../../../../../../src/services/git/providers/cli/utils/process-supervision.js';

const trusted: GitExecutionPolicy = {
  profile: 'trusted',
  binaryPath: '/usr/bin/git',
  homeDirectory: '/tmp',
  helperPath: '/usr/bin:/bin',
};
const reason = (expected: string) => (error: unknown) => {
  assert.ok(error instanceof GitExecutionError);
  assert.equal(error.reason, expected, error.message);
  return true;
};

describe('Git execution policy', () => {
  it('rejects restricted profile on every platform before any child program', () => {
    assert.throws(
      () => assertGitExecutionPolicy({ ...trusted, profile: 'restricted' }),
      reason('POLICY_UNSUPPORTED'),
    );
  });
  it('cannot promote an untrusted canonical repository by selecting trusted mode', () => {
    assert.throws(
      () =>
        assertGitExecutionPolicy(trusted, {
          canonicalWorkingDirectory: '/tmp/repository',
          canonicalRoots: ['/tmp'],
          repositoryTrust: 'untrusted',
        }),
      reason('POLICY_UNSUPPORTED'),
    );
  });
  it('requires absolute binary, HOME and every helper search directory', () => {
    for (const change of [
      { binaryPath: 'git' },
      { homeDirectory: '.' },
      { helperPath: '/bin:.' },
      { helperPath: ':/bin' },
    ]) {
      assert.throws(
        () => assertGitExecutionPolicy({ ...trusted, ...change }),
        reason('INVALID_EXECUTION_OPTIONS'),
      );
    }
  });
  it('removes routing, injected config, loaders and arbitrary server secrets', () => {
    const env = buildTrustedGitEnvironment(trusted, {
      HOME: '/outside',
      PATH: '/outside',
      GIT_DIR: '/outside/.git',
      GIT_WORK_TREE: '/outside',
      GIT_CONFIG_COUNT: '1',
      GIT_CONFIG_KEY_0: 'core.fsmonitor',
      GIT_CONFIG_VALUE_0: 'helper',
      GIT_SSH_COMMAND: 'helper',
      GIT_EXEC_PATH: '/outside',
      GIT_INDEX_FILE: '/outside/index',
      GIT_ALTERNATE_OBJECT_DIRECTORIES: '/outside',
      NODE_OPTIONS: '--require=helper',
      LD_PRELOAD: 'helper',
      DYLD_INSERT_LIBRARIES: 'helper',
      SERVER_TEST_SECRET: 'synthetic-fixture-value',
      SSH_AUTH_SOCK: '/operator-agent',
      GNUPGHOME: '/operator-keyring',
    });
    assert.equal(env.HOME, '/tmp');
    assert.equal(env.PATH, '/usr/bin:/bin');
    assert.equal(env.SSH_AUTH_SOCK, '/operator-agent');
    assert.equal(env.GNUPGHOME, '/operator-keyring');
    for (const key of [
      'GIT_DIR',
      'GIT_WORK_TREE',
      'GIT_CONFIG_COUNT',
      'GIT_CONFIG_KEY_0',
      'GIT_CONFIG_VALUE_0',
      'GIT_SSH_COMMAND',
      'GIT_EXEC_PATH',
      'GIT_INDEX_FILE',
      'GIT_ALTERNATE_OBJECT_DIRECTORIES',
      'NODE_OPTIONS',
      'LD_PRELOAD',
      'DYLD_INSERT_LIBRARIES',
      'SERVER_TEST_SECRET',
    ]) {
      assert.equal(env[key], undefined, key);
    }
  });
});

describe('request lifetime propagation', () => {
  it('keeps concurrent SDK signal/deadline scopes independent across async boundaries', async () => {
    const a = new AbortController();
    const b = new AbortController();
    const deadline = Date.now() + 10000;
    await Promise.all(
      [a, b].map((controller, index) =>
        withGitExecutionContext(
          {
            signal: controller.signal,
            startedAt: index,
            deadline: deadline + index,
          },
          async () => {
            await Promise.resolve();
            assert.equal(
              getGitExecutionContext()?.signal?.aborted,
              controller.signal.aborted,
            );
            assert.equal(getGitExecutionContext()?.deadline, deadline + index);
          },
        ),
      ),
    );
    assert.equal(getGitExecutionContext(), undefined);
  });
});

describe('real process supervision', { timeout: 15000 }, () => {
  let directory: string;
  beforeEach(async () => {
    directory = await mkdtemp(path.join(tmpdir(), 'git-runtime-security-'));
  });
  afterEach(async () => {
    await rm(directory, { recursive: true, force: true });
  });
  const run = (
    source: string,
    options: Partial<SupervisedProcessOptions> = {},
  ) =>
    superviseProcess({
      binaryPath: process.execPath,
      args: ['-e', source],
      cwd: directory,
      env: {},
      timeoutMs: 3000,
      maxStdoutBytes: 4096,
      maxStderrBytes: 4096,
      maxOutputBytes: 8192,
      terminationGraceMs: 30,
      ...options,
    });

  it('returns exact multibyte output split across writes at both stream and combined caps', async () => {
    const result = await run(
      "process.stdout.write(Buffer.from([0xf0,0x9f])); setTimeout(() => { process.stdout.write(Buffer.from([0x98,0x80])); process.stderr.write('xy'); }, 15)",
      {
        maxStdoutBytes: 4,
        maxStderrBytes: 2,
        maxOutputBytes: 6,
      },
    );
    assert.deepEqual(result, { stdout: '😀', stderr: 'xy', exitCode: 0 });
  });

  for (const stream of ['stdout', 'stderr'] as const) {
    it(`rejects ${stream} cap + 1, including an exit/overflow race`, async () => {
      await assert.rejects(
        run(`process.${stream}.write(Buffer.alloc(4097));`),
        reason('OUTPUT_LIMIT'),
      );
    });
    it(`drains large ${stream} without pipe deadlock or retaining unlimited output`, async () => {
      await assert.rejects(
        run(
          `for (let i=0;i<128;i++) process.${stream}.write(Buffer.alloc(65536));`,
        ),
        reason('OUTPUT_LIMIT'),
      );
    });
  }
  it('enforces combined cap independently of individual stream caps', async () => {
    await assert.rejects(
      run("process.stdout.write('abc'); process.stderr.write('def');", {
        maxOutputBytes: 5,
      }),
      reason('OUTPUT_LIMIT'),
    );
  });
  it('drains large simultaneous stdout and stderr', async () => {
    await assert.rejects(
      run(
        'for (let i=0;i<128;i++) { process.stdout.write(Buffer.alloc(65536)); process.stderr.write(Buffer.alloc(65536)); }',
      ),
      reason('OUTPUT_LIMIT'),
    );
  });
  it('counts UTF-8 bytes rather than characters', async () => {
    await assert.rejects(
      run("process.stdout.write('😀');", { maxStdoutBytes: 3 }),
      reason('OUTPUT_LIMIT'),
    );
  });
  for (const stream of ['stdout', 'stderr'] as const) {
    it(`preserves BOM, U+FFFD, NUL and framing bytes on ${stream} across every byte split`, async () => {
      const bytes = Buffer.from('\uFEFF\uFFFD😀é\0line\n\r\t\\');
      const result = await run(
        `const bytes=Buffer.from(${JSON.stringify([...bytes])}); let i=0; const write=()=> { if(i<bytes.length) { process.${stream}.write(bytes.subarray(i,i+1)); i++; setTimeout(write,1); } }; write();`,
      );
      assert.deepEqual(Buffer.from(result[stream], 'utf8'), bytes);
    });
    for (const invalid of [
      [0xff],
      [0xc0, 0xaf],
      [0xed, 0xa0, 0x80],
      [0xf0, 0x9f, 0x98],
      [0xe2, 0x28, 0xa1],
    ]) {
      it(`rejects malformed UTF8 ${invalid.join('-')} on ${stream} at EOF without a partial result`, async () => {
        await assert.rejects(
          run(
            `process.${stream}.write(Buffer.from(${JSON.stringify(invalid)}));`,
            { allowNonZeroExit: true },
          ),
          reason('INVALID_OUTPUT_ENCODING'),
        );
      });
    }
  }
  it('poisons the request after caught invalid encoding and prevents later process creation', async () => {
    await assert.rejects(
      withGitExecutionContext({ startedAt: Date.now() }, async () => {
        await assert.rejects(
          run('process.stdout.write(Buffer.from([0xff]))'),
          reason('INVALID_OUTPUT_ENCODING'),
        );
        await assert.rejects(
          run("require('node:fs').writeFileSync('later','unexpected')"),
          reason('INVALID_OUTPUT_ENCODING'),
        );
      }),
      reason('INVALID_OUTPUT_ENCODING'),
    );
    await assert.rejects(readFile(path.join(directory, 'later')));
  });
  it('shares a non-resettable byte budget across sequential metadata calls and caught overflow', async () => {
    await assert.rejects(
      withGitExecutionContext({ startedAt: Date.now() }, async () => {
        await run("process.stdout.write('abc')", { maxOutputBytes: 5 });
        await assert.rejects(
          run("process.stderr.write('def')", { maxOutputBytes: 5 }),
          reason('OUTPUT_LIMIT'),
        );
        await assert.rejects(
          run("require('node:fs').writeFileSync('later','unexpected')", {
            maxOutputBytes: 8192,
          }),
          reason('OUTPUT_LIMIT'),
        );
      }),
      reason('OUTPUT_LIMIT'),
    );
    await assert.rejects(readFile(path.join(directory, 'later')));
  });
  it('cancels forgotten process promises before settling the request', async () => {
    await assert.rejects(
      withGitExecutionContext({ startedAt: Date.now() }, async () => {
        void run("process.on('SIGTERM',()=>{}); setInterval(()=>{},100)");
        await Promise.resolve();
      }),
      reason('CLEANUP_FAILED'),
    );
  });
  it('allows only ordinary nonzero Git exits as soft failure', async () => {
    assert.deepEqual(
      await run("process.stderr.write('conflict'); process.exitCode=1", {
        allowNonZeroExit: true,
      }),
      { stdout: '', stderr: 'conflict', exitCode: 1 },
    );
    await assert.rejects(
      run("process.kill(process.pid, 'SIGKILL')", { allowNonZeroExit: true }),
      reason('SIGNAL_EXIT'),
    );
  });
  it('does not spawn when cancelled or deadline already expired', async () => {
    const controller = new AbortController();
    controller.abort();
    const source = "require('node:fs').writeFileSync('spawned','unexpected')";
    await assert.rejects(
      run(source, { signal: controller.signal }),
      reason('CANCELLED'),
    );
    await assert.rejects(
      run(source, { deadline: Date.now() - 1 }),
      reason('DEADLINE'),
    );
    await assert.rejects(readFile(path.join(directory, 'spawned')));
  });
  it('cancels after host spawn but before the ready handshake authorizes Git', async () => {
    const controller = new AbortController();
    const task = run(
      "require('node:fs').writeFileSync('spawned','unexpected')",
      { signal: controller.signal },
    );
    controller.abort();
    await assert.rejects(task, reason('CANCELLED'));
    await assert.rejects(readFile(path.join(directory, 'spawned')));
  });
  it('does not let Git forge its private host exit protocol through fd3', async () => {
    const source =
      "try { require('node:fs').writeSync(3, JSON.stringify({type:'exit',code:0,signal:null})+'\\n'); } catch {} process.exitCode=7;";
    assert.equal((await run(source, { allowNonZeroExit: true })).exitCode, 7);
  });
  it('keeps the owned group leader alive as Git parent until final termination', async () => {
    const source =
      "process.stdout.write(require('node:child_process').execFileSync('/bin/ps',['-o','pid=,ppid=,pgid=','-p',String(process.pid)],{encoding:'utf8'}));";
    const result = await run(source);
    const [pid, parent, group] = result.stdout.trim().split(/\s+/).map(Number);
    assert.ok(pid !== parent);
    assert.equal(parent, group);
  });
  it('does not load repository Bun preloads into the trusted process host', async () => {
    await writeFile(
      path.join(directory, 'bunfig.toml'),
      'preload = ["./host-preload.ts"]\n',
    );
    await writeFile(
      path.join(directory, 'host-preload.ts'),
      "require('node:fs').writeFileSync('host-preload-ran','unexpected')",
    );
    await writeFile(path.join(directory, 'package.json'), '{"type":"module"}');
    const result = await run('', {
      binaryPath: '/usr/bin/git',
      args: ['--version'],
    });
    assert.match(result.stdout, /^git version /);
    await assert.rejects(readFile(path.join(directory, 'host-preload-ran')));
  });
  it('anchors relative Git cwd to the server cwd rather than the bootstrap directory', async () => {
    const result = await run('', {
      binaryPath: '/bin/pwd',
      args: [],
      cwd: path.relative(process.cwd(), directory),
    });
    assert.equal(result.stdout.trim(), await realpath(directory));
  });
  it('rejects invalid timer/output bounds before execution', async () => {
    for (const options of [
      { timeoutMs: 0 },
      { timeoutMs: 2 ** 32 },
      { maxOutputBytes: Infinity },
      { maxStdoutBytes: -1 },
      { maxStderrBytes: 1.1 },
      { terminationGraceMs: 5001 },
    ]) {
      await assert.rejects(
        run('', options),
        reason('INVALID_EXECUTION_OPTIONS'),
      );
    }
  });
  it('escalates past ignored SIGTERM after cancellation and removes listener', async () => {
    const controller = new AbortController();
    const source =
      "process.on('SIGTERM',()=>{}); require('node:fs').writeFileSync('ready',String(process.pid)); setInterval(()=>{},100)";
    const task = run(source, { signal: controller.signal });
    let pid = 0;
    for (let i = 0; i < 100; i++) {
      try {
        pid = Number(await readFile(path.join(directory, 'ready'), 'utf8'));
        break;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
    }
    assert.ok(pid > 0);
    controller.abort();
    await assert.rejects(task, reason('CANCELLED'));
    assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
  });
  it('honors the configured deadline instead of a fixed 60 seconds', async () => {
    const start = Date.now();
    await assert.rejects(
      run("process.on('SIGTERM',()=>{}); setInterval(()=>{},100)", {
        timeoutMs: 100,
      }),
      reason('DEADLINE'),
    );
    assert.ok(Date.now() - start < 2000);
  });
  it('kills pipe-holding descendants even after leader exits', async () => {
    const helper =
      "process.on('SIGTERM',()=>{}); require('node:fs').writeFileSync('helper-pid',String(process.pid)); setInterval(()=>require('node:fs').appendFileSync('heartbeat','x'),10)";
    const source = `const {spawn}=require('node:child_process'); const child=spawn(process.execPath,['-e',${JSON.stringify(helper)}],{stdio:['ignore','inherit','inherit']}); setTimeout(()=>process.exit(0),150);`;
    const failure = await run(source, { timeoutMs: 500 }).then(
      () => undefined,
      (error: unknown) => error,
    );
    const before = await readFile(path.join(directory, 'heartbeat'), 'utf8');
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(
      await readFile(path.join(directory, 'heartbeat'), 'utf8'),
      before,
    );
    reason('DEADLINE')(failure);
  });
  it('kills quiet TERM-ignoring descendants whose output descriptors already closed', async () => {
    const helper =
      "process.on('SIGTERM',()=>{}); setInterval(()=>require('node:fs').appendFileSync('quiet-heartbeat','x'),10)";
    const source = `require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify(helper)}],{stdio:'ignore'}); setTimeout(()=>process.exit(0),200);`;
    assert.equal((await run(source)).exitCode, 0);
    const before = await readFile(
      path.join(directory, 'quiet-heartbeat'),
      'utf8',
    );
    assert.ok(before.length > 0);
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(
      await readFile(path.join(directory, 'quiet-heartbeat'), 'utf8'),
      before,
    );
  });
  it('fails boundedly when the controlled binary cannot spawn', async () => {
    await assert.rejects(
      run('', { binaryPath: path.join(directory, 'missing') }),
      reason('SPAWN_FAILED'),
    );
  });
});
