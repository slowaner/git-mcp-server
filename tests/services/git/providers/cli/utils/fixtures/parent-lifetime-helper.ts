/**
 * @fileoverview Heartbeat fixture with an independently verified group hardstop.
 * @module tests/services/git/providers/cli/utils/fixtures/parent-lifetime-helper
 */
import { execFileSync } from 'node:child_process';
import {
  appendFileSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'node:fs';

const nonce = process.argv[2];
const anchor = process.ppid;
if (!nonce || anchor <= 1) throw new Error('Invalid fixture identity');
process.on('SIGTERM', () => {});
appendFileSync('heartbeat', 'x');
writeFileSync(
  'ready.tmp',
  JSON.stringify({
    nonce,
    pid: process.pid,
    anchor,
    runtime: process.execPath,
    hardStopAt: Date.now() + 4000,
  }),
  { flag: 'wx', mode: 0o600 },
);
renameSync('ready.tmp', 'ready.json');
const heartbeat = setInterval(() => appendFileSync('heartbeat', 'x'), 20);

// This guard is test-only and independent of the production parent/EOF guard.
// The controller arms it only after checking the live owned group. It never
// signals a missing, exited, reused or differently owned anchor.
setTimeout(() => {
  try {
    const arm = JSON.parse(readFileSync('guard-arm.json', 'utf8')) as {
      nonce: string;
      pid: number;
      anchor: number;
      driver: number;
      uid: number;
      start: string;
      command: string;
    };
    if (
      arm.nonce !== nonce ||
      arm.pid !== process.pid ||
      arm.anchor !== anchor ||
      process.ppid !== anchor
    )
      throw new Error('Unverified fixture guard');
    const snapshot = execFileSync(
      '/bin/ps',
      [
        '-ww',
        '-p',
        String(anchor),
        '-o',
        'pid=,ppid=,pgid=,uid=,stat=,lstart=,command=',
      ],
      { encoding: 'utf8', timeout: 1000, maxBuffer: 16384 },
    );
    const row = snapshot
      .trim()
      .match(
        /^(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+)$/,
      );
    if (
      !row ||
      Number(row[1]) !== anchor ||
      ![arm.driver, 1].includes(Number(row[2])) ||
      Number(row[3]) !== anchor ||
      Number(row[4]) !== arm.uid ||
      /[ZX]/.test(row[5]!) ||
      row[6]!.replace(/\s+/g, ' ') !== arm.start ||
      row[7] !== arm.command
    )
      throw new Error('Anchor identity changed');
    writeFileSync(
      'guard-fired.json',
      JSON.stringify({ nonce, anchor, at: Date.now() }),
      { flag: 'wx', mode: 0o600 },
    );
    process.kill(-anchor, 'SIGKILL');
  } catch {
    writeFileSync('guard-error', 'Fixture hardstop was not verified');
    clearInterval(heartbeat);
    process.exitCode = 78;
  }
}, 4000);
