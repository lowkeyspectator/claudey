import assert from 'node:assert/strict';
import test from 'node:test';

import { createActivationState, planActivation, planRollback } from '../../src/core/activation.js';
import { runRollbackCommand } from '../../src/cli/commands/rollback.js';
import { runUpdateCommand } from '../../src/cli/commands/update.js';
import { Secret } from '../../src/core/secrets.js';

const OLD = Object.freeze({ version: '7.2.129', relativePath: 'releases/7.2.129/CLIProxyAPI', sha256: 'a'.repeat(64) });
const CURRENT = Object.freeze({ version: '7.2.130', relativePath: 'releases/7.2.130/CLIProxyAPI', sha256: 'b'.repeat(64) });
const NEXT = Object.freeze({ version: '7.2.131', relativePath: 'releases/7.2.131/CLIProxyAPI', sha256: 'c'.repeat(64) });

function activation(active = CURRENT, rollback = OLD) {
  return { schemaVersion: 1, active, rollback, retained: [OLD, CURRENT, NEXT] };
}

test('activation records are closed, bounded, deeply frozen, and hostile accessors fail as sanitized safety refusals', () => {
  const state = createActivationState(activation(), { platform: 'linux' });
  const planned = planActivation(state, NEXT, { platform: 'linux' });
  assert.equal(Object.isFrozen(state), true);
  assert.equal(Object.isFrozen(state.retained), true);
  assert.equal(Object.isFrozen(state.active), true);
  assert.equal(Object.isFrozen(planned), true);
  assert.throws(() => { state.active.version = '9.9.9'; });

  const inherited = Object.assign(Object.create({ polluted: true }), activation());
  const tooMany = {
    schemaVersion: 1, active: null, rollback: null,
    retained: Array.from({ length: 65 }, (_, index) => ({
      version: `1.0.${index}`, relativePath: `releases/1.0.${index}/CLIProxyAPI`, sha256: index.toString(16).padStart(64, '0')
    }))
  };
  const hostile = new Proxy({}, { ownKeys: () => { throw new Error('state secret-canary'); } });
  const revokedRetained = Proxy.revocable([], {});
  revokedRetained.revoke();
  const revokedArray = { schemaVersion: 1, active: null, rollback: null, retained: revokedRetained.proxy };
  const foreignTarget = {
    ...activation(),
    active: { ...CURRENT, relativePath: 'config/config.yaml' },
    retained: [{ ...CURRENT, relativePath: 'config/config.yaml' }, OLD, NEXT]
  };
  const mismatchedVersionTarget = {
    ...activation(),
    active: { ...CURRENT, relativePath: 'releases/7.2.999/CLIProxyAPI' },
    retained: [{ ...CURRENT, relativePath: 'releases/7.2.999/CLIProxyAPI' }, OLD, NEXT]
  };
  for (const value of [inherited, tooMany, hostile, revokedArray, foreignTarget, mismatchedVersionTarget]) {
    assert.throws(() => createActivationState(value, { platform: 'linux' }),
      (error) => error.code === 'SAFETY_REFUSAL' && !error.message.includes('secret-canary'));
  }
});

test('update --check is read-only, takes no installation lock, and reports the verified available release', async () => {
  const events = [];
  const result = await runUpdateCommand({ check: true }, {
    checkForUpdate: async ({ requestedVersion }) => {
      events.push(`check:${requestedVersion ?? 'latest'}`);
      return { currentVersion: CURRENT.version, availableVersion: NEXT.version, updateAvailable: true };
    },
    acquireLock: async () => assert.fail('read-only check must not lock or mutate')
  });
  assert.deepEqual(result, {
    operation: 'update-check', currentVersion: '7.2.130', availableVersion: '7.2.131', updateAvailable: true
  });
  assert.deepEqual(events, ['check:latest']);
});

test('hostile update option accessors are sanitized before a lock, check, or mutation', async () => {
  const hostile = new Proxy({ check: true }, {
    get: () => { throw new Error('update option secret-canary'); }
  });
  await assert.rejects(runUpdateCommand(hostile, {
    checkForUpdate: async () => assert.fail('hostile options must not reach update checks'),
    acquireLock: async () => assert.fail('hostile options must not acquire the lock')
  }), (error) => error.code === 'SAFETY_REFUSAL' && !error.message.includes('secret-canary'));
});

test('candidate readiness failure restores the prior update state and returns UPDATE_ROLLED_BACK without private diagnostics', async () => {
  const events = [];
  const state = { active: CURRENT, running: true, configPort: 8317, token: 'preserved', launchers: 'preserved' };
  const original = structuredClone(state);
  const transaction = {
    current: { phase: 'prepared' },
    checkpoint: async (phase) => { events.push(`checkpoint:${phase}`); transaction.current = { phase }; },
    cleanup: async () => events.push('cleanup'),
    clear: async () => events.push('clear-journal')
  };
  const context = {
    acquireLock: async () => ({ assertHeld: async () => {}, release: async () => events.push('release') }),
    recoverInterrupted: async () => {},
    preflight: async () => ({ platform: 'linux', priorRunning: true, port: 8317, activation: activation() }),
    beginJournal: async () => transaction,
    resolveRelease: async () => ({ version: NEXT.version }),
    downloadVerifiedRelease: async () => ({ archive: true }),
    extractVerifiedRelease: async () => ({ extracted: true }),
    withCandidate: async (_descriptor, consumer) => consumer(Object.freeze({ read: async () => Buffer.from('candidate') })),
    probeCandidate: async () => NEXT,
    revalidateCandidate: async () => true,
    loadOrCreateInstallation: async () => ({
      installationId: '33333333-3333-4333-8333-333333333333',
      bearerToken: Secret.fromBytes(Buffer.alloc(32, 0x41)),
      manifestKey: Secret.fromBytes(Buffer.alloc(32, 0x42))
    }),
    stageConfig: async () => ({ changed: false, port: state.configPort }),
    stageLaunchers: async () => ({ changed: false, value: state.launchers }),
    stopPrior: async () => { state.running = false; },
    writeActivation: async (next) => { state.active = next.active; },
    startCandidate: async () => { state.running = true; },
    authenticateReadiness: async () => { throw new Error('candidate diagnostic secret-canary'); },
    commitManifest: async () => assert.fail('failed candidate must not commit'),
    rollbackTransaction: async ({ stage }) => { events.push(`rollback:${stage}`); Object.assign(state, structuredClone(original)); }
  };
  await assert.rejects(runUpdateCommand({}, context), (error) => error.code === 'UPDATE_ROLLED_BACK'
    && !error.message.includes('secret-canary'));
  assert.deepEqual(state, original);
  assert.deepEqual(events.slice(-2), ['rollback:readiness', 'release']);
  assert.equal(events.includes('checkpoint:committed'), false);
});

test('journal checkpoint failure after successful readiness rolls back but is not misclassified as candidate readiness failure', async () => {
  const state = { active: CURRENT, running: true };
  const original = structuredClone(state);
  const transaction = {
    current: { phase: 'prepared' },
    checkpoint: async (phase) => {
      if (phase === 'ready') throw new Error('checkpoint secret-canary');
      transaction.current = { phase };
    },
    cleanup: async () => undefined,
    clear: async () => undefined
  };
  const context = {
    acquireLock: async () => ({ assertHeld: async () => {}, release: async () => {} }),
    recoverInterrupted: async () => {},
    preflight: async () => ({ platform: 'linux', priorRunning: true, port: 8317, activation: activation() }),
    beginJournal: async () => transaction,
    resolveRelease: async () => ({ version: NEXT.version }),
    downloadVerifiedRelease: async () => ({}),
    extractVerifiedRelease: async () => ({}),
    withCandidate: async (_descriptor, consumer) => consumer(Object.freeze({ read: async () => Buffer.from('candidate') })),
    probeCandidate: async () => NEXT,
    revalidateCandidate: async () => true,
    loadOrCreateInstallation: async () => ({
      installationId: '44444444-4444-4444-8444-444444444444',
      bearerToken: Secret.fromBytes(Buffer.alloc(32, 0x51)),
      manifestKey: Secret.fromBytes(Buffer.alloc(32, 0x52))
    }),
    stageConfig: async () => ({ changed: false }),
    stageLaunchers: async () => ({ changed: false }),
    stopPrior: async () => { state.running = false; },
    writeActivation: async (next) => { state.active = next.active; },
    startCandidate: async () => { state.running = true; },
    authenticateReadiness: async () => true,
    commitManifest: async () => assert.fail('ready checkpoint failure must not commit'),
    rollbackTransaction: async () => Object.assign(state, structuredClone(original))
  };
  await assert.rejects(runUpdateCommand({}, context), (error) => error.code === 'SAFETY_REFUSAL'
    && !error.message.includes('secret-canary'));
  assert.deepEqual(state, original);
});

test('rollback planning selects only verified retained releases, consumes the default point once, and treats the active explicit version as a no-op', () => {
  const first = planRollback(activation(), undefined, { platform: 'linux' });
  assert.equal(first.changed, true);
  assert.equal(first.target.version, OLD.version);
  assert.equal(first.state.active.version, OLD.version);
  assert.equal(first.state.rollback, null);
  assert.throws(() => planRollback(first.state, undefined, { platform: 'linux' }), (error) => error.code === 'ROLLBACK_UNAVAILABLE');
  const noop = planRollback(activation(), CURRENT.version, { platform: 'linux' });
  assert.equal(noop.changed, false);
  assert.equal(noop.state.active.version, CURRENT.version);
  assert.equal(noop.state.rollback.version, OLD.version);
  assert.throws(() => planRollback(activation(), '7.2.999', { platform: 'linux' }), (error) => error.code === 'ROLLBACK_UNAVAILABLE');
});

function rollbackFixture({ cleanupFails = false } = {}) {
  const events = [];
  const state = { activation: activation(), running: true, manifestVersion: CURRENT.version };
  const original = structuredClone(state);
  const transaction = {
    current: { phase: 'prepared' },
    checkpoint: async (phase) => { events.push(`checkpoint:${phase}`); transaction.current = { phase }; },
    cleanup: async () => {
      events.push('cleanup');
      if (cleanupFails) throw new Error('cleanup secret-canary');
    },
    clear: async () => events.push('clear-journal')
  };
  const context = {
    acquireLock: async () => ({ assertHeld: async () => events.push('lock-held'), release: async () => events.push('release') }),
    recoverInterrupted: async () => events.push('recover'),
    preflight: async () => ({ platform: 'linux', priorRunning: state.running, port: 8317, activation: state.activation }),
    beginJournal: async () => { events.push('journal'); return transaction; },
    revalidateRetainedRelease: async ({ target }) => { events.push(`revalidate:${target.version}`); return target; },
    stopPrior: async () => { events.push('stop'); state.running = false; },
    writeActivation: async (next) => { events.push('activate'); state.activation = next; },
    startCandidate: async () => { events.push('spawn'); state.running = true; },
    authenticateReadiness: async () => events.push('readiness'),
    commitManifest: async ({ candidate }) => { events.push('manifest'); state.manifestVersion = candidate.version; },
    rollbackTransaction: async () => { events.push('restore'); Object.assign(state, structuredClone(original)); }
  };
  return { context, events, state };
}

test('default rollback activates only the retained verified target, preserves running state, and repeated default rollback mutates nothing', async () => {
  const f = rollbackFixture();
  const first = await runRollbackCommand({}, f.context);
  assert.deepEqual(first, { operation: 'rollback', version: OLD.version, port: 8317, running: true, changed: true });
  assert.equal(f.state.activation.active.version, OLD.version);
  assert.equal(f.state.activation.rollback, null);
  assert.equal(f.state.running, true);
  assert.equal(f.events.includes('download'), false);
  const before = structuredClone(f.state);
  const eventCount = f.events.length;
  await assert.rejects(runRollbackCommand({}, f.context), (error) => error.code === 'ROLLBACK_UNAVAILABLE');
  assert.deepEqual(f.state, before);
  assert.deepEqual(f.events.slice(eventCount), ['lock-held', 'recover', 'release']);
});

test('explicit rollback to the active version is an exit-zero no-op without journal or process mutation', async () => {
  const f = rollbackFixture();
  const result = await runRollbackCommand({ version: CURRENT.version }, f.context);
  assert.deepEqual(result, { operation: 'rollback', version: CURRENT.version, port: 8317, running: true, changed: false });
  assert.equal(f.events.includes('journal'), false);
  assert.equal(f.events.includes('stop'), false);
  assert.equal(f.events.includes('activate'), false);
});

test('rollback post-commit cleanup failure preserves the consumed rollback point and active retained release', async () => {
  const f = rollbackFixture({ cleanupFails: true });
  await assert.rejects(runRollbackCommand({}, f.context), (error) => error.code === 'SAFETY_REFUSAL');
  assert.equal(f.state.activation.active.version, OLD.version);
  assert.equal(f.state.activation.rollback, null);
  assert.equal(f.state.running, true);
  assert.equal(f.events.includes('checkpoint:committed'), true);
  assert.equal(f.events.includes('restore'), false);
  assert.equal(f.events.at(-1), 'release');
});
