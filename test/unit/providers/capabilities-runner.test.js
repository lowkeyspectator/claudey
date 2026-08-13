import assert from 'node:assert/strict';
import process from 'node:process';
import test from 'node:test';

import { runFixedCommand } from '../../../src/providers/capabilities.js';

test('runs only an absolute executable with shell disabled, closes stdin, and bounds timeout and output', async () => {
  const success = await runFixedCommand({
    executablePath: process.execPath,
    args: ['-p', '123'],
    shell: false,
    stdin: null,
    env: {},
    timeoutMs: 1_000,
    maxStdoutBytes: 16,
    maxStderrBytes: 16
  });
  assert.deepEqual(success, { code: 0, stdout: '123\n', stderr: '' });

  const startedAt = Date.now();
  const timedOut = await runFixedCommand({
    executablePath: process.execPath,
    args: ['-e', 'setInterval(() => {}, 10)'],
    shell: false,
    stdin: null,
    env: {},
    timeoutMs: 30,
    maxStdoutBytes: 16,
    maxStderrBytes: 16
  });
  assert.equal(timedOut.code, -1);
  assert.ok(Date.now() - startedAt < 1_000);

  const oversized = await runFixedCommand({
    executablePath: process.execPath,
    args: ['-e', 'process.stdout.write("x".repeat(64))'],
    shell: false,
    stdin: null,
    env: {},
    timeoutMs: 1_000,
    maxStdoutBytes: 16,
    maxStderrBytes: 16
  });
  assert.ok(Buffer.byteLength(oversized.stdout) <= 17);
});
