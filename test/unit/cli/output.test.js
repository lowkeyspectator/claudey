import assert from 'node:assert/strict';
import test from 'node:test';

import { emitError, emitSuccess } from '../../../src/cli/output.js';
import { ClaudeyError } from '../../../src/core/errors.js';

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
  emitError(new ClaudeyError('MODEL_NOT_FOUND', 'The requested model is not currently available.', { hint: 'Run claudeyctl models codex.' }), { json: true }, captured.io);
  assert.deepEqual(JSON.parse(captured.stdout[0]), {
    ok: false,
    code: 'MODEL_NOT_FOUND',
    message: 'The requested model is not currently available.',
    hint: 'Run claudeyctl models codex.',
    details: {}
  });
  assert.equal(captured.stdout.length, 1);
  assert.deepEqual(captured.stderr, []);
});

test('human errors present a code and next action on stderr', () => {
  const captured = capture();
  emitError(new ClaudeyError('MODEL_NOT_FOUND', 'The requested model is not currently available.', { hint: 'Run claudeyctl models codex.' }), {}, captured.io);
  assert.deepEqual(captured.stdout, []);
  assert.deepEqual(captured.stderr, [
    'error[MODEL_NOT_FOUND]: The requested model is not currently available.\nnext: Run claudeyctl models codex.\n'
  ]);
});

test('human success writes one bounded result document', () => {
  const captured = capture();
  emitSuccess({ operation: 'status', state: 'healthy' }, {}, captured.io);
  assert.deepEqual(captured.stdout, ['{"operation":"status","state":"healthy"}\n']);
  assert.deepEqual(captured.stderr, []);
});
