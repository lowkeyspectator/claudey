import assert from 'node:assert/strict';
import test from 'node:test';

import { DOCTOR_CHECKS, runDoctorCommand } from '../../src/cli/commands/doctor.js';

function fixture(overrides = {}) {
  const calls = [];
  const checks = Object.fromEntries(DOCTOR_CHECKS.map((name) => [name, async () => {
    calls.push(name);
    return overrides[name] ?? { status: 'ok' };
  }]));
  const mutations = [];
  return { calls, mutations, context: {
    checks,
    startGateway: async () => mutations.push('start'),
    repairPermissions: async () => mutations.push('permissions'),
    rewriteConfig: async () => mutations.push('config')
  } };
}

test('doctor runs every required inspection, returns schema-1 health, and invokes zero mutators', async () => {
  const f = fixture();
  const result = await runDoctorCommand(f.context);
  assert.deepEqual(f.calls, DOCTOR_CHECKS);
  assert.deepEqual(f.mutations, []);
  assert.equal(result.schemaVersion, 1);
  assert.equal(result.healthy, true);
  assert.equal(result.checks.length, DOCTOR_CHECKS.length);
  assert.equal(Object.isFrozen(result.checks), true);
});

test('doctor preserves exact remediation commands in bounded findings and exits nonzero without repair', async () => {
  const f = fixture({ gateway: { status: 'error', code: 'GATEWAY_UNHEALTHY' } });
  await assert.rejects(runDoctorCommand(f.context), (error) => {
    assert.equal(error.code, 'GATEWAY_UNHEALTHY');
    assert.equal(error.details.doctor.healthy, false);
    assert.deepEqual(error.details.doctor.findings, [{
      name: 'gateway', status: 'error', message: 'The gateway is unhealthy.', remediation: 'claudexctl restart'
    }]);
    return true;
  });
  assert.deepEqual(f.calls, DOCTOR_CHECKS);
  assert.deepEqual(f.mutations, []);

  const hostile = fixture({ manifest: { status: 'error', code: 'SAFETY_REFUSAL', diagnostic: 'private-token-canary' } });
  await assert.rejects(runDoctorCommand(hostile.context), (error) => error.code === 'SAFETY_REFUSAL'
    && !JSON.stringify(error).includes('private-token-canary'));
});
