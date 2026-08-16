import assert from 'node:assert/strict';
import test from 'node:test';

import { ClaudeyError, ClaudexError, exitCodeFor } from '../../../src/core/errors.js';
import { Secret } from '../../../src/core/secrets.js';

test('maps every documented public error class to its stable exit code', () => {
  const cases = {
    USAGE_ERROR: 2,
    PLATFORM_UNSUPPORTED: 3,
    PREREQUISITE_MISSING: 3,
    CAPABILITY_UNSUPPORTED: 3,
    NOT_INSTALLED: 3,
    AUTH_REQUIRED: 4,
    INTERACTION_REQUIRED: 4,
    MODEL_REQUIRED: 4,
    MODEL_NOT_FOUND: 4,
    NETWORK_FAILURE: 5,
    CHECKSUM_MISMATCH: 5,
    ARCHIVE_UNSAFE: 5,
    LOCK_BUSY: 6,
    PORT_IN_USE: 6,
    GATEWAY_UNHEALTHY: 6,
    PROCESS_IDENTITY_MISMATCH: 6,
    CONFIG_MODIFIED: 7,
    MCP_OWNERSHIP_COLLISION: 7,
    APPROVAL_REQUIRED: 7,
    APPROVAL_INVALID: 7,
    SAFETY_REFUSAL: 7,
    UPDATE_ROLLED_BACK: 8,
    ROLLBACK_UNAVAILABLE: 8
  };
  for (const [code, exitCode] of Object.entries(cases)) {
    assert.equal(exitCodeFor(new ClaudeyError(code, 'message')), exitCode, code);
    assert.equal(exitCodeFor(new ClaudexError(code, 'message')), exitCode, code);
  }
});

test('uses usage exit code for unknown errors', () => {
  assert.equal(exitCodeFor(new Error('unexpected')), 2);
});

test('refuses secret-bearing error details', () => {
  assert.throws(
    () => new ClaudeyError('NETWORK_FAILURE', 'download failed', { details: { token: Secret.fromBytes(Buffer.alloc(32)) } }),
    /SECRET_SERIALIZATION_REFUSED/
  );
});
