import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

function runCli(args) {
  return spawnSync(process.execPath, ['bin/claudeyctl.js', ...args], {
    cwd: root,
    encoding: 'utf8'
  });
}

test('CLI emits exactly one JSON error envelope and usage exit for an invalid JSON command', () => {
  const child = runCli(['unknown-command', '--json']);
  assert.equal(child.status, 2);
  assert.equal(child.stderr, '');
  const lines = child.stdout.trimEnd().split('\n');
  assert.equal(lines.length, 1);
  assert.deepEqual(JSON.parse(lines[0]), {
    ok: false,
    code: 'USAGE_ERROR',
    message: 'Unknown command: unknown-command.',
    details: {}
  });
});

test('CLI emits one human success document for the dependency-free help invocation', () => {
  const child = runCli(['--help']);
  assert.equal(child.status, 0);
  assert.equal(child.stderr, '');
  assert.match(child.stdout, /claudey setup/);
  assert.match(child.stdout, /claudey cursor/);
  const wrapped = runCli(['launcher', 'claudey', '--help']);
  assert.equal(wrapped.status, 0);
  assert.match(wrapped.stdout, /claudey setup/);
});

test('CLI emits a human error envelope and usage exit without a Node stack', () => {
  const child = runCli(['unknown-command']);
  assert.equal(child.status, 2);
  assert.equal(child.stdout, '');
  assert.equal(child.stderr, 'error[USAGE_ERROR]: Unknown command: unknown-command.\n');
});
