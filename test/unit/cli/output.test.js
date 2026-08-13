import assert from 'node:assert/strict';
import test from 'node:test';

import { emitError, emitSuccess } from '../../../src/cli/output.js';
import { ClaudexError } from '../../../src/core/errors.js';

function capture() {
  const stdout = [];
  const stderr = [];
  return {
    io: { stdout: { write: (text) => stdout.push(text) }, stderr: { write: (text) => stderr.push(text) } },
    stdout,
    stderr
  };
}

test('JSON success writes exactly one schema-1 envelope to stdout', () => {
  const captured = capture();
  emitSuccess({ model: 'gpt-test' }, { json: true, progress: 'started' }, captured.io);
  assert.deepEqual(captured.stdout, ['{"ok":true,"schemaVersion":1,"result":{"model":"gpt-test"}}\n']);
  assert.deepEqual(captured.stderr, ['started\n']);
});

test('JSON error writes exactly one redacted schema-1 envelope to stdout', () => {
  const captured = capture();
  emitError(new ClaudexError('MODEL_NOT_FOUND', 'The requested model is not currently available.', { hint: 'Run claudexctl models codex.' }), { json: true }, captured.io);
  assert.deepEqual(JSON.parse(captured.stdout[0]), {
    ok: false,
    code: 'MODEL_NOT_FOUND',
    message: 'The requested model is not currently available.',
    hint: 'Run claudexctl models codex.',
    details: {}
  });
  assert.equal(captured.stdout.length, 1);
  assert.deepEqual(captured.stderr, []);
});

test('human errors present a code and next action on stderr', () => {
  const captured = capture();
  emitError(new ClaudexError('MODEL_NOT_FOUND', 'The requested model is not currently available.', { hint: 'Run claudexctl models codex.' }), {}, captured.io);
  assert.deepEqual(captured.stdout, []);
  assert.deepEqual(captured.stderr, [
    'error[MODEL_NOT_FOUND]: The requested model is not currently available.\nnext: Run claudexctl models codex.\n'
  ]);
});
