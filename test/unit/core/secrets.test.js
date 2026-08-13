import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import test from 'node:test';

import { Secret, normalizePromptForApproval } from '../../../src/core/secrets.js';

test('Secret cannot cross serialization boundaries', () => {
  const secret = Secret.fromBytes(Buffer.alloc(32, 0x5a));
  assert.throws(() => JSON.stringify({ secret }), /SECRET_SERIALIZATION_REFUSED/);
  assert.throws(() => String(secret), /SECRET_ACCESS_REFUSED/);
  assert.throws(() => inspect(secret), /SECRET_INSPECTION_REFUSED/);
  assert.throws(() => structuredClone(secret), /SECRET_SERIALIZATION_REFUSED/);
  assert.equal(secret.withValue((value) => value.length), 32);
});

test('Secret refuses disposal and callback misuse without revealing bytes', () => {
  const secret = Secret.fromBytes(Buffer.from('canary-secret'));
  secret.dispose();
  assert.throws(() => secret.withValue(() => 'unused'), /SECRET_DISPOSED/);
});

test('approval prompt normalization preserves exact UTF-8 scalar input', () => {
  const crlf = normalizePromptForApproval('line\r\nnext');
  const lf = normalizePromptForApproval('line\nnext');
  const composed = normalizePromptForApproval('é');
  const decomposed = normalizePromptForApproval('e\u0301');
  assert.notEqual(crlf.sha256, lf.sha256);
  assert.notEqual(composed.sha256, decomposed.sha256);
  assert.equal(normalizePromptForApproval(' keep ').utf8.toString('utf8'), ' keep ');
});

test('approval prompt normalization rejects NUL and non-string input', () => {
  assert.throws(() => normalizePromptForApproval('bad\0prompt'), (error) => error.code === 'USAGE_ERROR');
  assert.throws(() => normalizePromptForApproval(Buffer.from('prompt')), (error) => error.code === 'USAGE_ERROR');
});
