import assert from 'node:assert/strict';
import test from 'node:test';

import { runInstallCommand } from '../../src/cli/commands/install.js';
import { Secret } from '../../src/core/secrets.js';

const OLD = Object.freeze({ version: '7.2.129', relativePath: 'releases/7.2.129/CLIProxyAPI.exe', sha256: 'a'.repeat(64) });
const NEXT = Object.freeze({ version: '7.2.130', relativePath: 'releases/7.2.130/CLIProxyAPI.exe', sha256: 'b'.repeat(64) });

function installationFixture({ priorRunning = true, failAt, candidate = NEXT, installation } = {}) {
  const events = [];
  const state = {
    active: OLD,
    rollback: null,
    retained: [OLD],
    configPort: 8317,
    token: 'opaque-old-token',
    installationId: '11111111-1111-4111-8111-111111111111',
    running: priorRunning,
    manifestVersion: OLD.version,
    pathEntries: 0,
    cursorEnabled: false
  };
  const original = structuredClone(state);
  const call = async (name, result) => {
    events.push(name);
    if (failAt === name) throw new Error(`${name} secret-canary`);
    return typeof result === 'function' ? result() : result;
  };
  const transaction = {
    current: { phase: 'prepared' },
    checkpoint: async (phase) => call(`checkpoint:${phase}`, () => { transaction.current = { phase }; }),
    cleanup: async () => call('cleanup'),
    clear: async () => call('clear-journal')
  };
  const context = {
    acquireLock: async ({ kind }) => call(`lock:${kind}`, {
      assertHeld: async () => call('lock-held'),
      release: async () => call('lock-release')
    }),
    recoverInterrupted: async () => call('recover'),
    preflight: async () => call('preflight', {
      platform: 'win32', priorRunning, port: state.configPort,
      activation: { schemaVersion: 1, active: state.active, rollback: state.rollback, retained: [...state.retained] }
    }),
    beginJournal: async () => call('journal:prepared', transaction),
    resolveRelease: async ({ requestedVersion }) => call(`resolve:${requestedVersion ?? 'latest'}`, { version: requestedVersion ?? NEXT.version }),
    downloadVerifiedRelease: async () => call('download', { archive: 'verified-archive' }),
    extractVerifiedRelease: async () => call('extract', { candidate: 'extracted-candidate' }),
    withCandidate: async (_descriptor, consumer) => {
      await call('candidate-scope:open');
      try { return await consumer(Object.freeze({ read: async () => Buffer.from('candidate') })); }
      finally { await call('candidate-scope:close'); }
    },
    probeCandidate: async () => call('probe', candidate),
    revalidateCandidate: async () => call('revalidate-candidate', true),
    loadOrCreateInstallation: async () => call('installation', installation ?? {
      installationId: state.installationId,
      bearerToken: Secret.fromBytes(Buffer.alloc(32, 0x21)),
      manifestKey: Secret.fromBytes(Buffer.alloc(32, 0x22))
    }),
    stageConfig: async ({ port }) => call('stage-config', { port }),
    stageLaunchers: async () => call('stage-launchers', { count: 3 }),
    stopPrior: async () => call('stop-prior', () => { state.running = false; }),
    writeActivation: async (activation) => call('activate', () => {
      state.active = activation.active;
      state.rollback = activation.rollback;
      state.retained = [...activation.retained];
      state.configPort = 8317;
    }),
    startCandidate: async () => call('spawn', () => { state.running = true; return { state: 'started' }; }),
    authenticateReadiness: async () => call('readiness', { state: 'healthy' }),
    commitManifest: async ({ candidate }) => call('manifest', () => { state.manifestVersion = candidate.version; }),
    rollbackTransaction: async () => call('rollback', () => Object.assign(state, structuredClone(original))),
    stagePathIntent: async () => call('path-intent', () => { state.pathEntries = 1; }),
    stagePluginIntent: async () => call('plugin-intent', () => { state.cursorEnabled = true; }),
    authenticateProvider: async () => call('oauth')
  };
  return { context, events, state, original };
}

test('install executes the exact verified transaction and preserves a prior running state without PATH, OAuth, or Cursor mutation', async () => {
  const f = installationFixture();
  const result = await runInstallCommand({ version: '7.2.130', port: 8317, yes: true }, f.context);
  assert.deepEqual(result, { operation: 'install', version: '7.2.130', port: 8317, running: true, changed: true });
  assert.deepEqual(f.events, [
    'lock:install', 'lock-held', 'recover', 'preflight', 'journal:prepared', 'resolve:7.2.130',
    'download', 'extract', 'candidate-scope:open', 'probe', 'checkpoint:release-staged', 'installation', 'stage-config',
    'stage-launchers', 'checkpoint:config-staged', 'revalidate-candidate', 'stop-prior', 'activate', 'checkpoint:activated', 'candidate-scope:close',
    'spawn', 'checkpoint:candidate-started', 'readiness', 'checkpoint:ready', 'manifest',
    'checkpoint:committed', 'cleanup', 'clear-journal', 'lock-release'
  ]);
  assert.equal(f.state.active.version, '7.2.130');
  assert.equal(f.state.rollback.version, '7.2.129');
  assert.equal(f.state.token, f.original.token);
  assert.equal(f.state.installationId, f.original.installationId);
  assert.equal(f.state.running, true);
  assert.equal(f.state.pathEntries, 0);
  assert.equal(f.state.cursorEnabled, false);
  assert.equal(f.events.includes('oauth'), false);
});

test('explicit release identity mismatch, malformed protected installation state, and final candidate revalidation failure stop before activation', async () => {
  const cases = [
    installationFixture({ candidate: { ...NEXT, version: '7.2.999' } }),
    installationFixture({ installation: { installationId: 'not-a-uuid', bearerToken: 'plain', manifestKey: 'plain' } }),
    installationFixture({ failAt: 'revalidate-candidate' })
  ];
  for (const f of cases) {
    await assert.rejects(runInstallCommand({ version: '7.2.130' }, f.context), (error) => error.code === 'SAFETY_REFUSAL');
    assert.deepEqual(f.state, f.original);
    assert.equal(f.events.includes('activate'), false);
    assert.equal(f.events.includes('stop-prior'), false);
    assert.equal(f.events.at(-1), 'lock-release');
  }
});

test('install leaves a stopped installation stopped', async () => {
  const f = installationFixture({ priorRunning: false });
  const result = await runInstallCommand({}, f.context);
  assert.equal(result.running, false);
  assert.equal(f.state.running, false);
  assert.equal(f.events.includes('spawn'), false);
  assert.equal(f.events.includes('readiness'), false);
  assert.equal(f.events.includes('stop-prior'), false);
});

test('every injected precommit failure restores the complete prior install state and releases the lock without leaking diagnostics', async () => {
  for (const failAt of ['download', 'extract', 'probe', 'stage-config', 'activate', 'spawn', 'readiness']) {
    const f = installationFixture({ failAt });
    await assert.rejects(runInstallCommand({}, f.context), (error) => error.code === 'SAFETY_REFUSAL'
      && !error.message.includes('secret-canary'), failAt);
    assert.deepEqual(f.state, f.original, failAt);
    assert.equal(f.events.includes('rollback'), true, failAt);
    assert.equal(f.events.at(-1), 'lock-release', failAt);
    assert.equal(f.events.includes('checkpoint:committed'), false, failAt);
  }
});

test('post-commit cleanup failure preserves the committed activation for journal recovery and never rolls it back', async () => {
  const f = installationFixture({ failAt: 'cleanup' });
  await assert.rejects(runInstallCommand({}, f.context), (error) => error.code === 'SAFETY_REFUSAL');
  assert.equal(f.state.active.version, NEXT.version);
  assert.equal(f.state.rollback.version, OLD.version);
  assert.equal(f.state.running, true);
  assert.equal(f.events.includes('checkpoint:committed'), true);
  assert.equal(f.events.includes('rollback'), false);
  assert.equal(f.events.at(-1), 'lock-release');
});

test('post-commit journal-clear failure also preserves committed state for the next recovery pass', async () => {
  const f = installationFixture({ failAt: 'clear-journal' });
  await assert.rejects(runInstallCommand({}, f.context), (error) => error.code === 'SAFETY_REFUSAL');
  assert.equal(f.state.active.version, NEXT.version);
  assert.equal(f.events.includes('cleanup'), true);
  assert.equal(f.events.includes('rollback'), false);
  assert.equal(f.events.at(-1), 'lock-release');
});

test('hostile option and dependency accessors fail as sanitized safety refusals before mutation', async () => {
  const hostileOptions = new Proxy({}, { ownKeys: () => { throw new Error('option secret-canary'); } });
  const f = installationFixture();
  await assert.rejects(runInstallCommand(hostileOptions, f.context),
    (error) => error.code === 'SAFETY_REFUSAL' && !error.message.includes('secret-canary'));
  assert.deepEqual(f.events, []);

  const hostileContext = new Proxy({}, { get: () => { throw new Error('context secret-canary'); } });
  await assert.rejects(runInstallCommand({}, hostileContext),
    (error) => error.code === 'SAFETY_REFUSAL' && !error.message.includes('secret-canary'));
});

test('programmatic command options require exact Boolean types before acquiring the lock', async () => {
  for (const options of [{ yes: 'true' }, { noStart: 1 }, { noPath: null }, { withCursor: 'false' }, { nonInteractive: 0 }]) {
    const f = installationFixture();
    await assert.rejects(runInstallCommand(options, f.context), (error) => error.code === 'SAFETY_REFUSAL');
    assert.deepEqual(f.events, []);
  }
});
