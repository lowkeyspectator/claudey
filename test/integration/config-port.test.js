import assert from 'node:assert/strict';
import test from 'node:test';

import { ClaudexError } from '../../src/core/errors.js';
import { runConfigCommand } from '../../src/cli/commands/config.js';
import { runLifecycleCommand } from '../../src/cli/commands/lifecycle.js';

function portFixture({ priorRunning = true, occupied = false, failAt } = {}) {
  const events = [];
  const state = { port: 8317, running: priorRunning, manifestPort: 8317, launcherWrites: 0 };
  const original = structuredClone(state);
  const call = async (name, result) => {
    events.push(name);
    if (failAt === name) throw new Error(`${name} private secret-canary`);
    return typeof result === 'function' ? result() : result;
  };
  const transaction = {
    current: { phase: 'prepared' },
    checkpoint: async (phase) => call(`checkpoint:${phase}`, () => { transaction.current = { phase }; }),
    cleanup: async () => call('cleanup'),
    clear: async () => call('clear-journal')
  };
  const context = {
    acquireLock: async () => ({ assertHeld: async () => call('lock-held'), release: async () => call('release') }),
    recoverInterrupted: async () => call('recover'),
    preflight: async () => call('preflight', {
      platform: 'linux', priorRunning: state.running, port: state.port,
      activation: { schemaVersion: 1, active: { version: '7.2.130', relativePath: 'releases/7.2.130/CLIProxyAPI', sha256: 'a'.repeat(64) }, rollback: null, retained: [{ version: '7.2.130', relativePath: 'releases/7.2.130/CLIProxyAPI', sha256: 'a'.repeat(64) }] }
    }),
    inspectPort: async ({ host, port }) => call(`inspect:${host}:${port}`, occupied ? { state: 'occupied' } : { state: 'free' }),
    beginJournal: async () => call('journal', transaction),
    stageConfig: async ({ port }) => call('stage-config', { port }),
    stopPrior: async () => call('stop', () => { state.running = false; }),
    activateConfig: async ({ port }) => call('activate-config', () => { state.port = port; }),
    startCandidate: async () => call('spawn', () => { state.running = true; }),
    authenticateReadiness: async () => call('readiness'),
    commitManifest: async ({ port }) => call('manifest', () => { state.manifestPort = port; }),
    rollbackTransaction: async () => call('rollback', () => Object.assign(state, structuredClone(original))),
    stageLaunchers: async () => { state.launcherWrites += 1; }
  };
  return { context, events, state, original };
}

test('port change rejects collisions before config mutation and never adopts or signals the unrelated listener', async () => {
  const f = portFixture({ occupied: true });
  await assert.rejects(runConfigCommand(['config', 'set', 'port'], { port: 9400 }, f.context),
    (error) => error.code === 'PORT_IN_USE');
  assert.deepEqual(f.state, f.original);
  assert.deepEqual(f.events, ['lock-held', 'recover', 'preflight', 'inspect:127.0.0.1:9400', 'release']);
});

test('port change stages and activates config transactionally, preserves running state, and never rewrites launchers', async () => {
  const f = portFixture();
  const result = await runConfigCommand(['config', 'set', 'port'], { port: 9400, yes: true }, f.context);
  assert.deepEqual(result, { operation: 'config-port', port: 9400, running: true, changed: true });
  assert.equal(f.state.port, 9400);
  assert.equal(f.state.manifestPort, 9400);
  assert.equal(f.state.running, true);
  assert.equal(f.state.launcherWrites, 0);
  assert.deepEqual(f.events, [
    'lock-held', 'recover', 'preflight', 'inspect:127.0.0.1:9400', 'journal',
    'checkpoint:release-staged', 'stage-config', 'checkpoint:config-staged', 'stop',
    'activate-config', 'checkpoint:activated', 'spawn', 'checkpoint:candidate-started',
    'readiness', 'checkpoint:ready', 'manifest', 'checkpoint:committed', 'cleanup', 'clear-journal', 'release'
  ]);
});

test('port change preserves stopped state, same-port is an exit-zero no-op, and readiness failure restores the old state', async () => {
  const stopped = portFixture({ priorRunning: false });
  const changed = await runConfigCommand(['config', 'set', 'port'], { port: 9400 }, stopped.context);
  assert.equal(changed.running, false);
  assert.equal(stopped.state.running, false);
  assert.equal(stopped.events.includes('spawn'), false);

  const same = portFixture();
  const unchanged = await runConfigCommand(['config', 'set', 'port'], { port: 8317 }, same.context);
  assert.deepEqual(unchanged, { operation: 'config-port', port: 8317, running: true, changed: false });
  assert.equal(same.events.includes('inspect:127.0.0.1:8317'), false);
  assert.equal(same.events.includes('journal'), false);

  const failed = portFixture({ failAt: 'readiness' });
  await assert.rejects(runConfigCommand(['config', 'set', 'port'], { port: 9400 }, failed.context),
    (error) => error.code === 'SAFETY_REFUSAL' && !error.message.includes('secret-canary'));
  assert.deepEqual(failed.state, failed.original);
  assert.deepEqual(failed.events.slice(-2), ['rollback', 'release']);
});

test('port post-commit cleanup failure preserves the committed port for journal recovery', async () => {
  const f = portFixture({ failAt: 'cleanup' });
  await assert.rejects(runConfigCommand(['config', 'set', 'port'], { port: 9400 }, f.context),
    (error) => error.code === 'SAFETY_REFUSAL');
  assert.equal(f.state.port, 9400);
  assert.equal(f.state.manifestPort, 9400);
  assert.equal(f.state.running, true);
  assert.equal(f.events.includes('checkpoint:committed'), true);
  assert.equal(f.events.includes('rollback'), false);
  assert.equal(f.events.at(-1), 'release');
});

test('lifecycle commands lock every mutation, preserve exact idempotent states, sanitize failures, and keep status read-only', async () => {
  const events = [];
  const context = {
    acquireLock: async ({ kind }) => {
      events.push(`lock:${kind}`);
      return { assertHeld: async () => events.push('held'), release: async () => events.push('release') };
    },
    recoverInterrupted: async () => events.push('recover'),
    startGateway: async ({ foreground }) => ({ state: foreground ? 'foreground' : 'already-running', private: 'secret-canary' }),
    stopGateway: async () => ({ state: 'already-stopped', private: 'secret-canary' }),
    restartGateway: async () => ({ state: 'started', private: 'secret-canary' }),
    statusGateway: async () => ({ state: 'healthy', private: 'secret-canary' })
  };
  assert.deepEqual(await runLifecycleCommand(['start'], { foreground: true }, context), { operation: 'start', state: 'foreground' });
  assert.deepEqual(await runLifecycleCommand(['stop'], {}, context), { operation: 'stop', state: 'already-stopped' });
  assert.deepEqual(await runLifecycleCommand(['restart'], {}, context), { operation: 'restart', state: 'started' });
  const beforeStatus = events.length;
  assert.deepEqual(await runLifecycleCommand(['status'], {}, context), { operation: 'status', state: 'healthy' });
  assert.equal(events.length, beforeStatus);

  await assert.rejects(runLifecycleCommand(['start'], {}, {
    ...context,
    startGateway: async () => { throw new ClaudexError('PORT_IN_USE', 'listener secret-canary'); }
  }), (error) => error.code === 'PORT_IN_USE' && !error.message.includes('secret-canary'));
  assert.equal(events.at(-1), 'release');
});
