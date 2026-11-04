/**
 * @fileoverview Disposable real-supervisor driver with an orderly control path.
 * @module tests/services/git/providers/cli/utils/fixtures/parent-lifetime-driver
 */
import { writeFileSync } from 'node:fs';
import path from 'node:path';

import { GitExecutionError } from '../../../../../../../src/services/git/providers/cli/utils/execution-errors.js';
import { superviseProcess } from '../../../../../../../src/services/git/providers/cli/utils/process-supervision.js';

const [directory, helper, nonce] = process.argv.slice(2);
if (!directory || !helper || !nonce)
  throw new Error('Missing fixture arguments');
const controller = new AbortController();
const abort = () => controller.abort();
process.on('SIGTERM', abort);
process.stdin.on('end', abort);
let input = '';
process.stdin.on('data', (chunk: Buffer) => {
  input += chunk.toString('utf8');
  if (input.length > 32) abort();
  let end: number;
  while ((end = input.indexOf('\n')) !== -1) {
    const command = input.slice(0, end);
    input = input.slice(end + 1);
    if (command === 'die') process.kill(process.pid, 'SIGKILL');
    else abort();
  }
});

const startedAt = Date.now();
void superviseProcess({
  binaryPath: process.execPath,
  args: [helper, nonce],
  cwd: directory,
  env: {},
  timeoutMs: 10000,
  maxStdoutBytes: 4096,
  maxStderrBytes: 4096,
  maxOutputBytes: 8192,
  terminationGraceMs: 30,
  signal: controller.signal,
}).then(
  () => finish('SUCCESS'),
  (error: unknown) =>
    finish(
      error instanceof GitExecutionError ? error.reason : 'OTHER',
      error instanceof GitExecutionError
        ? error.message.slice(0, 256)
        : undefined,
      error instanceof GitExecutionError,
    ),
);

function finish(
  reason: string,
  message?: string,
  rejectedWithGitExecutionError = false,
): void {
  const finishedAt = Date.now();
  writeFileSync(
    path.join(directory!, 'driver-result.json'),
    JSON.stringify({
      nonce,
      reason,
      message,
      rejectedWithGitExecutionError,
      finishedAt,
      finishedAfterStartMs: finishedAt - startedAt,
    }),
    { flag: 'wx', mode: 0o600 },
  );
  process.exit(0);
}
