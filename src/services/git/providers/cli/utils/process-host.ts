/**
 * @fileoverview Fixed internal bootstrap that anchors one Git process group.
 * @module services/git/providers/cli/utils/process-host
 */

/**
 * Trusted server code, never constructed from repository/tool content. The host
 * keeps its session/group ID allocated until the parent sends the final KILL.
 * Git gets only fd 0/1/2, so it cannot forge the private fd3 exit protocol. The
 * parent grants startup over stdin only after receiving the ready handshake,
 * then keeps that private lifecycle channel open until group termination.
 * This is lifecycle supervision, not an untrusted-repository sandbox.
 */
export const GIT_PROCESS_HOST_SOURCE = String.raw`
const { spawn } = require('node:child_process');
const { writeSync, closeSync } = require('node:fs');
process.on('SIGTERM', () => {});
setInterval(() => {}, 3600000);
const report = (message) => writeSync(3, JSON.stringify(message) + '\n');
let reported = false;
const complete = (message) => {
  if (!reported) {
    reported = true;
    if (message.type === 'exit') {
      closeSync(1);
      closeSync(2);
    }
    report(message);
  }
};
let ownerGone = false;
const terminateOwnedGroup = () => {
  if (ownerGone) return;
  ownerGone = true;
  if (process.pid <= 1) throw new Error('Invalid Git group anchor');
  process.kill(-process.pid, 'SIGKILL');
};
process.stdin.on('end', terminateOwnedGroup);
process.stdin.on('close', terminateOwnedGroup);
process.stdin.on('error', terminateOwnedGroup);
let started = false;
process.stdin.on('data', () => {
  if (started) return;
  started = true;
  try {
    const [cwd, binary, ...args] = process.argv.slice(1);
    const git = spawn(binary, args, {
      cwd, env: process.env,
      stdio: ['ignore', 1, 2], shell: false, detached: false,
    });
    git.once('error', () => complete({ type: 'spawn-error' }));
    git.once('exit', (code, signal) => complete({ type: 'exit', code, signal }));
  } catch {
    complete({ type: 'spawn-error' });
  }
});
process.stdin.resume();
report({ type: 'ready', pid: process.pid });
`;
