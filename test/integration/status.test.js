import assert from 'node:assert/strict';
import test from 'node:test';

import { runStatusCommand } from '../../src/cli/commands/status.js';

const UUID = '11111111-1111-4111-8111-111111111111';

function context(overrides = {}) {
  const calls = [];
  return { calls, value: {
    inspectInstallation: async () => (calls.push('installation'), overrides.installation ?? {
      state: 'installed', version: '7.2.130', installationId: UUID
    }),
    inspectGateway: async () => (calls.push('gateway'), overrides.gateway ?? { state: 'healthy', port: 8317 }),
    inspectProviders: async () => (calls.push('providers'), overrides.providers ?? {
      codex: 'authenticated', antigravity: 'missing'
    }),
    inspectCursor: async () => (calls.push('cursor'), overrides.cursor ?? {
      registration: 'disabled', login: 'unavailable', writes: 'disabled', pendingWorktrees: 0
    }),
    inspectRecovery: async () => (calls.push('recovery'), overrides.recovery ?? {
      journal: 'clear', rollback: 'available'
    })
  } };
}

test('healthy status returns a frozen schema-1 aggregate using read-only inspectors', async () => {
  const f = context();
  const result = await runStatusCommand(f.value);
  assert.equal(result.schemaVersion, 1);
  assert.equal(result.healthy, true);
  assert.equal(result.installation.installationId, UUID);
  assert.equal(result.gateway.port, 8317);
  assert.deepEqual(f.calls, ['installation', 'gateway', 'providers', 'cursor', 'recovery']);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.cursor), true);
});

test('nonhealthy and hostile status states return a mapped nonzero error with bounded status details', async () => {
  const stopped = context({ gateway: { state: 'stopped', port: 8317 } });
  await assert.rejects(runStatusCommand(stopped.value), (error) => {
    assert.equal(error.code, 'GATEWAY_UNHEALTHY');
    assert.equal(error.details.status.healthy, false);
    assert.equal(error.details.status.gateway.state, 'stopped');
    return true;
  });
  const absent = context({ installation: { state: 'not-installed', version: null, installationId: null },
    gateway: { state: 'not-installed', port: null } });
  await assert.rejects(runStatusCommand(absent.value), (error) => error.code === 'NOT_INSTALLED');
  const hostile = context({ providers: { codex: 'authenticated', antigravity: 'missing', token: 'private-canary' } });
  await assert.rejects(runStatusCommand(hostile.value), (error) => error.code === 'SAFETY_REFUSAL'
    && !JSON.stringify(error).includes('private-canary'));
  const thrown = context();
  thrown.value.inspectInstallation = async () => {
    const error = new Error('private-thrown-canary'); error.code = 'NOT_INSTALLED'; throw error;
  };
  await assert.rejects(runStatusCommand(thrown.value), (error) => error.code === 'SAFETY_REFUSAL'
    && !JSON.stringify(error).includes('private-thrown-canary'));
});
