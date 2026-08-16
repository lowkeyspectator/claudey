import assert from 'node:assert/strict';
import test from 'node:test';

import { main, run } from '../../src/cli/main.js';

function captured() {
  const stdout = [];
  const stderr = [];
  return { stdout, stderr, io: { stdout: { write: (value) => stdout.push(value) },
    stderr: { write: (value) => stderr.push(value) } } };
}

function container() {
  const calls = [];
  const handler = (name) => async ({ command, options, context }) => {
    calls.push({ name, command, options, context });
    return { operation: name, command };
  };
  return { calls, value: {
    handlers: Object.fromEntries(['setup', 'install', 'auth', 'lifecycle', 'status', 'update', 'rollback',
      'models', 'doctor', 'config', 'cursor', 'cursorMcpServe', 'uninstall'].map((name) => [name, handler(name)])),
    contexts: Object.fromEntries(['setup', 'install', 'auth', 'lifecycle', 'status', 'update', 'rollback',
      'models', 'doctor', 'config', 'cursor', 'cursorMcpServe', 'uninstall'].map((name) => [name, { name }]))
  } };
}

test('wired router dispatches the complete core command matrix with typed options and family contexts', async () => {
  const cases = [
    [['setup', '--yes'], 'setup'], [['install', '--yes'], 'install'], [['auth', 'codex', '--no-browser'], 'auth'],
    [['start'], 'lifecycle'], [['stop'], 'lifecycle'], [['restart'], 'lifecycle'], [['status'], 'status'],
    [['update', '--check'], 'update'], [['rollback', '--version', '7.2.130', '--yes'], 'rollback'],
    [['models', 'codex'], 'models'], [['doctor'], 'doctor'], [['config', 'set', 'port', '8317', '--yes'], 'config'],
    [['uninstall', '--dry-run'], 'uninstall']
  ];
  const f = container();
  for (const [argv, expected] of cases) {
    const result = await main(argv, {}, f.value);
    assert.equal(result.operation, expected, argv.join(' '));
    assert.equal(f.calls.at(-1).context.name, expected);
    assert.equal(Object.isFrozen(f.calls.at(-1).command), true);
    assert.equal(Object.isFrozen(f.calls.at(-1).options), true);
  }
});

test('async run emits exactly one JSON envelope, maps errors, and renders help/human success without stacks', async () => {
  const f = container();
  const json = captured();
  assert.equal(await run(['status', '--json'], {}, json.io, f.value), 0);
  assert.equal(json.stdout.length, 1);
  assert.equal(JSON.parse(json.stdout[0]).ok, true);
  assert.deepEqual(json.stderr, []);

  const invalid = captured();
  assert.equal(await run(['unknown', '--json'], {}, invalid.io, f.value), 2);
  assert.equal(invalid.stdout.length, 1);
  assert.equal(JSON.parse(invalid.stdout[0]).code, 'USAGE_ERROR');
  assert.deepEqual(invalid.stderr, []);

  const help = captured();
  assert.equal(await run(['--help'], {}, help.io, f.value), 0);
  assert.equal(help.stdout.length, 1);
  assert.match(help.stdout[0], /claudey setup/);
  assert.deepEqual(help.stderr, []);

  const human = captured();
  assert.equal(await run(['status'], {}, human.io, f.value), 0);
  assert.equal(human.stdout.length, 1);
  assert.match(human.stdout[0], /status/);
});

test('healthy and unhealthy status/doctor preserve schema-1 JSON and mapped exit semantics', async () => {
  const statusContext = (gatewayState = 'healthy') => ({
    inspectInstallation: async () => ({ state: 'installed', version: '7.2.130',
      installationId: '11111111-1111-4111-8111-111111111111' }),
    inspectGateway: async () => ({ state: gatewayState, port: 8317 }),
    inspectProviders: async () => ({ codex: 'authenticated', antigravity: 'missing', grok: 'missing' }),
    inspectCursor: async () => ({ registration: 'disabled', login: 'unavailable', writes: 'disabled', pendingWorktrees: 0 }),
    inspectRecovery: async () => ({ journal: 'clear', rollback: 'unavailable' })
  });
  const healthy = captured();
  assert.equal(await run(['status', '--json'], {}, healthy.io, { contexts: { status: statusContext() } }), 0);
  assert.equal(JSON.parse(healthy.stdout[0]).result.schemaVersion, 1);

  const unhealthy = captured();
  assert.equal(await run(['status', '--json'], {}, unhealthy.io,
    { contexts: { status: statusContext('unhealthy') } }), 6);
  const statusError = JSON.parse(unhealthy.stdout[0]);
  assert.equal(statusError.code, 'GATEWAY_UNHEALTHY');
  assert.equal(statusError.details.status.schemaVersion, 1);

  const doctorChecks = Object.fromEntries([
    'platform', 'node', 'claude', 'git', 'manifest', 'config', 'permissions', 'token', 'gateway',
    'auth', 'models', 'path', 'cursor', 'journal', 'rollback'
  ].map((name) => [name, async () => name === 'gateway'
    ? { status: 'error', code: 'GATEWAY_UNHEALTHY' } : { status: 'ok' }]));
  const doctor = captured();
  assert.equal(await run(['doctor', '--json'], {}, doctor.io, { contexts: { doctor: { checks: doctorChecks } } }), 6);
  const doctorError = JSON.parse(doctor.stdout[0]);
  assert.equal(doctorError.code, 'GATEWAY_UNHEALTHY');
  assert.equal(doctorError.details.doctor.schemaVersion, 1);
});
