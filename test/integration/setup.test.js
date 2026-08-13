import assert from 'node:assert/strict';
import test from 'node:test';

import { runSetupCommand } from '../../src/cli/commands/setup.js';
import { Secret } from '../../src/core/secrets.js';

const RELEASE = Object.freeze({ version: '7.2.130', relativePath: 'releases/7.2.130/CLIProxyAPI', sha256: 'c'.repeat(64) });

function setupFixture() {
  const events = [];
  const journalKinds = [];
  const state = { pathEntries: 0, cursorEnabled: false, running: false, token: 'preserved-token', starts: 0 };
  const transaction = {
    current: { phase: 'prepared' },
    checkpoint: async (phase) => { events.push(`checkpoint:${phase}`); transaction.current = { phase }; },
    cleanup: async () => events.push('cleanup'),
    clear: async () => events.push('clear-journal')
  };
  const context = {
    acquireLock: async () => ({ assertHeld: async () => events.push('lock-held'), release: async () => events.push('lock-release') }),
    recoverInterrupted: async () => events.push('recover'),
    preflight: async () => ({ platform: 'linux', priorRunning: state.running, port: 8317, activation: { schemaVersion: 1, active: RELEASE, rollback: null, retained: [RELEASE] } }),
    beginJournal: async ({ kind }) => { journalKinds.push(kind); return transaction; },
    resolveRelease: async () => ({ version: RELEASE.version }),
    downloadVerifiedRelease: async () => ({ archive: true }),
    extractVerifiedRelease: async () => ({ candidate: true }),
    withCandidate: async (_descriptor, consumer) => consumer(Object.freeze({ read: async () => Buffer.from('candidate') })),
    probeCandidate: async () => RELEASE,
    revalidateCandidate: async () => true,
    loadOrCreateInstallation: async () => ({
      installationId: '22222222-2222-4222-8222-222222222222',
      bearerToken: Secret.fromBytes(Buffer.alloc(32, 0x31)),
      manifestKey: Secret.fromBytes(Buffer.alloc(32, 0x32))
    }),
    stageConfig: async () => ({ port: 8317 }),
    stageLaunchers: async () => ({ count: 3 }),
    stopPrior: async () => { events.push('stop-prior'); state.running = false; },
    writeActivation: async () => events.push('activate'),
    stagePathIntent: async () => {
      events.push('path-intent');
      const changed = state.pathEntries === 0;
      state.pathEntries = 1;
      return { changed };
    },
    stagePluginIntent: async () => {
      events.push('plugin-intent');
      const changed = state.cursorEnabled === false;
      state.cursorEnabled = true;
      return { changed };
    },
    startCandidate: async () => { events.push('spawn'); state.running = true; state.starts += 1; },
    authenticateReadiness: async () => events.push('readiness'),
    commitManifest: async () => events.push('manifest'),
    rollbackTransaction: async () => events.push('rollback')
  };
  return { context, events, journalKinds, state };
}

test('setup adds one PATH intent, optionally enables Cursor, starts by default, and remains idempotent', async () => {
  const f = setupFixture();
  const first = await runSetupCommand({ withCursor: true }, f.context);
  const second = await runSetupCommand({ withCursor: true }, f.context);
  assert.deepEqual(first, { operation: 'setup', version: '7.2.130', port: 8317, running: true, changed: true });
  assert.deepEqual(second, { ...first, changed: false });
  assert.equal(f.state.pathEntries, 1);
  assert.equal(f.state.cursorEnabled, true);
  assert.equal(f.state.running, true);
  assert.equal(f.state.token, 'preserved-token');
  assert.equal(f.state.starts, 1);
  assert.equal(f.events.filter((event) => event === 'path-intent').length, 2);
  assert.equal(f.events.filter((event) => event === 'plugin-intent').length, 2);
  assert.deepEqual(f.journalKinds, ['update', 'update']);
});

test('fresh setup uses the existing install journal kind rather than inventing an incompatible setup phase', async () => {
  const f = setupFixture();
  f.context.preflight = async () => ({
    platform: 'linux', priorRunning: false, port: 8317,
    activation: { schemaVersion: 1, active: null, rollback: null, retained: [] }
  });
  await runSetupCommand({ noStart: true }, f.context);
  assert.deepEqual(f.journalKinds, ['install']);
});

test('setup --no-path --no-start writes neither intent and preserves a stopped state', async () => {
  const f = setupFixture();
  const result = await runSetupCommand({ noPath: true, noStart: true }, f.context);
  assert.equal(result.running, false);
  assert.equal(f.state.pathEntries, 0);
  assert.equal(f.state.cursorEnabled, false);
  assert.equal(f.events.includes('path-intent'), false);
  assert.equal(f.events.includes('plugin-intent'), false);
  assert.equal(f.events.includes('spawn'), false);
  assert.equal(f.events.includes('readiness'), false);
});

test('setup --no-start reports stopped after activating over a previously running release', async () => {
  const f = setupFixture();
  f.state.running = true;
  const prior = { version: '7.2.129', relativePath: 'releases/7.2.129/CLIProxyAPI', sha256: 'd'.repeat(64) };
  f.context.preflight = async () => ({
    platform: 'linux', priorRunning: true, port: 8317,
    activation: { schemaVersion: 1, active: prior, rollback: null, retained: [prior] }
  });
  const result = await runSetupCommand({ noStart: true }, f.context);
  assert.equal(result.changed, true);
  assert.equal(result.running, false);
  assert.equal(f.state.running, false);
  assert.equal(f.events.includes('stop-prior'), true);
  assert.equal(f.events.includes('spawn'), false);
});
