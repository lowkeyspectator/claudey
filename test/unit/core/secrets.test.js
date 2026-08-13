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

test('Secret refuses access after disposal', () => {
  const secret = Secret.fromBytes(Buffer.from('canary-secret'));
  secret.dispose();
  assert.throws(() => secret.withValue(() => 'unused'), /SECRET_DISPOSED/);
});

test('Secret wipes the callback-scoped byte copy after the callback returns', () => {
  const secret = Secret.fromBytes(Buffer.from('canary-secret'));
  let retained;
  assert.equal(secret.withValue((value) => {
    retained = value;
    return value.length;
  }), 13);
  assert.deepEqual(retained, Buffer.alloc(13));
});

test('approval prompt normalization preserves exact UTF-8 scalar input', () => {
  const crlf = normalizePromptForApproval('line\r\nnext');
  const lf = normalizePromptForApproval('line\nnext');
  const composed = normalizePromptForApproval('\u00e9');
  const decomposed = normalizePromptForApproval('e\u0301');
  assert.notEqual(crlf.sha256, lf.sha256);
  assert.notEqual(composed.sha256, decomposed.sha256);
  assert.deepEqual(composed.utf8, Buffer.from([0xc3, 0xa9]));
  assert.equal(normalizePromptForApproval(' keep ').utf8.toString('utf8'), ' keep ');
  assert.notEqual(normalizePromptForApproval('keep').sha256, normalizePromptForApproval(' keep').sha256);
  assert.notEqual(normalizePromptForApproval('keep').sha256, normalizePromptForApproval('keep ').sha256);
});

test('approval prompt normalization rejects NUL and non-string input', () => {
  assert.throws(() => normalizePromptForApproval('bad\0prompt'), (error) => error.code === 'USAGE_ERROR');
  assert.throws(() => normalizePromptForApproval(Buffer.from('prompt')), (error) => error.code === 'USAGE_ERROR');
});
