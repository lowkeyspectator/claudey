import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { runUninstallCommand } from '../../src/cli/commands/uninstall.js';
import { canonicalManifestBytes, verifyManifest } from '../../src/core/manifest.js';
import { Secret } from '../../src/core/secrets.js';

const ROOT = 'C:\\Users\\Casey\\AppData\\Local\\claudexctl';
const PATHS = Object.freeze({
  managerRoot: ROOT,
  stateRoot: `${ROOT}\\state`,
  userBinRoot: `${ROOT}\\bin`,
  ownedPluginRoots: [`${ROOT}\\plugins\\owned`],
  authRoot: 'C:\\Users\\Casey\\AppData\\Roaming\\claudexctl\\auth',
  homeRoot: 'C:\\Users\\Casey',
  repositoryRoot: 'C:\\src\\claudex'
});
const FILE = Object.freeze({
  relativePath: 'releases/7.2.130/CLIProxyAPI.exe', type: 'file', sha256: 'a'.repeat(64)
});
const KEY = Secret.fromBytes(Buffer.alloc(32, 0x52));
const UNSIGNED = {
  schemaVersion: 1,
  installationId: '11111111-1111-4111-8111-111111111111',
  platform: { family: 'windows', runtimeArch: 'x64' },
  managedRoots: {
    managerRoot: PATHS.managerRoot,
    stateRoot: PATHS.stateRoot,
    userBinRoot: PATHS.userBinRoot,
    ownedPluginRoots: PATHS.ownedPluginRoots
  },
  files: [FILE]
};
const HMAC = KEY.withValue((bytes) => crypto.createHmac('sha256', bytes)
  .update(canonicalManifestBytes({ ...UNSIGNED, hmac: '' })).digest('base64url'));
const MANIFEST = verifyManifest({ ...UNSIGNED, hmac: HMAC }, KEY, { fixedPaths: PATHS });

function fixture({ manifest = MANIFEST, plan, runtime = { state: 'owned', identity: 'pid:42:create:99' }, failAt } = {}) {
  const events = [];
  const removed = [];
  const defaultPlan = [
    { path: `${PATHS.ownedPluginRoots[0]}\\registration.json`, action: 'remove', reason: 'owned', category: 'plugin' },
    { path: PATHS.userBinRoot, action: 'restore', reason: 'owned', category: 'path' },
    { path: `${ROOT}\\config.yaml`, action: 'preserve', reason: 'modified', category: 'managed-file' },
    { path: PATHS.authRoot, action: 'preserve', reason: 'oauth', category: 'auth' },
    { path: `${ROOT}\\notes.txt`, action: 'preserve', reason: 'unlisted', category: 'unlisted' },
    { path: 'C:\\src\\project', action: 'preserve', reason: 'dirty-worktree', category: 'worktree' },
    { path: `${ROOT}\\plugins\\foreign`, action: 'preserve', reason: 'unknown-plugin', category: 'plugin' }
  ];
  const call = async (name, value) => {
    events.push(name);
    if (failAt === name) throw new Error(`private ${name} canary`);
    return typeof value === 'function' ? value() : value;
  };
  const journal = {
    checkpoint: async (phase) => call(`checkpoint:${phase}`),
    cleanup: async () => call('cleanup'),
    clear: async () => call('clear-journal')
  };
  const context = {
    paths: PATHS,
    acquireLock: async () => call('lock', {
      assertHeld: async () => call('lock-held'),
      release: async () => call('lock-release')
    }),
    recoverInterrupted: async () => call('recover'),
    loadAuthenticatedManifest: async () => call('manifest', manifest),
    beginJournal: async () => call('journal:prepared', journal),
    planRemoval: async () => call('plan', plan ?? defaultPlan),
    inspectCandidate: async ({ target, expectedSha256 }) => call('inspect-owned-file', {
      exists: true, canonicalPath: target, type: 'file', sha256: expectedSha256
    }),
    inspectOwnedGateway: async () => call('inspect-gateway', runtime),
    recheckOwnedGateway: async (identity) => call('recheck-gateway', identity === runtime?.identity),
    stopOwnedGateway: async () => call('stop-gateway'),
    revalidateRemovalTarget: async (item) => call(`recheck:${item.category}:${item.reason}`, true),
    removeOwnedTarget: async (item) => call(`remove:${item.path}`, () => removed.push(item.path)),
    restoreOwnedPath: async () => call('restore-path', { action: 'restored', reason: 'owned-change' }),
    removeOwnedPlugin: async () => call('remove-plugin', { action: 'removed', reason: 'owned' }),
    inspectAuthRoot: async () => call('inspect-auth', {
      canonicalPath: PATHS.authRoot, exists: true, type: 'directory', isLink: false, isJunction: false, isReparsePoint: false
    }),
    recheckAuthRoot: async () => call('recheck-auth', true),
    confirmPurgeAuth: async () => call('confirm-auth', true),
    purgeAuthRoot: async () => call('purge-auth')
  };
  return { context, events, removed };
}

test('default uninstall locks, recovers, identity-rechecks before stop, removes only unchanged owned targets, and reports preservation', async () => {
  const f = fixture();
  const result = await runUninstallCommand({}, f.context);
  assert.equal(result.operation, 'uninstall');
  assert.equal(result.changed, true);
  assert.equal(result.dryRun, false);
  assert.deepEqual(f.removed, [`${ROOT}\\releases\\7.2.130\\CLIProxyAPI.exe`]);
  assert.deepEqual(result.preserved.map(({ reason }) => reason),
    ['modified', 'oauth', 'unlisted', 'dirty-worktree', 'unknown-plugin']);
  assert.ok(f.events.indexOf('recheck-gateway') < f.events.indexOf('stop-gateway'));
  assert.ok(f.events.indexOf('stop-gateway') < f.events.indexOf(`recheck:managed-file:unchanged`));
  assert.deepEqual(f.events.slice(-4), ['checkpoint:committed', 'cleanup', 'clear-journal', 'lock-release']);
  assert.equal(f.events.includes('inspect-auth'), false);
  assert.equal(f.events.includes('purge-auth'), false);
});

test('dry run lists canonical targets and reasons without stopping or mutating', async () => {
  const f = fixture();
  const result = await runUninstallCommand({ dryRun: true }, f.context);
  assert.equal(result.dryRun, true);
  assert.equal(result.targets.length, 8);
  for (const forbidden of ['recover', 'journal:prepared', 'stop-gateway', 'restore-path', 'remove-plugin', 'purge-auth']) {
    assert.equal(f.events.includes(forbidden), false, forbidden);
  }
  assert.deepEqual(f.removed, []);
  assert.equal(f.events.at(-1), 'lock-release');
});

test('a plain manifest-shaped object is refused because it lacks the manifest verifier private brand', async () => {
  const f = fixture({ manifest: JSON.parse(JSON.stringify(MANIFEST)) });
  await assert.rejects(runUninstallCommand({}, f.context), (error) => error.code === 'SAFETY_REFUSAL');
  assert.equal(f.events.includes('plan'), false);
  assert.equal(f.events.includes('inspect-gateway'), false);
  assert.equal(f.events.at(-1), 'lock-release');
});

test('a deletion target outside authenticated fixed roots is refused before process or filesystem mutation', async () => {
  const f = fixture({ plan: [
    { path: 'D:\\foreign\\victim.txt', action: 'remove', reason: 'unchanged', category: 'managed-file' }
  ] });
  await assert.rejects(runUninstallCommand({}, f.context), (error) => error.code === 'SAFETY_REFUSAL');
  assert.equal(f.events.includes('inspect-gateway'), false);
  assert.equal(f.events.some((event) => event.startsWith('remove:')), false);
  assert.equal(f.events.at(-1), 'lock-release');
});

test('a removal action cannot relabel modified or unknown data as deletable', async () => {
  for (const item of [
    { path: `${ROOT}\\config.yaml`, action: 'remove', reason: 'modified', category: 'managed-file' },
    { path: `${ROOT}\\plugins\\owned\\foreign.json`, action: 'remove', reason: 'unknown-plugin', category: 'plugin' },
    { path: `${ROOT}\\ordinary-manager-file.json`, action: 'remove', reason: 'owned', category: 'plugin' }
  ]) {
    const f = fixture({ plan: [item] });
    await assert.rejects(runUninstallCommand({}, f.context), (error) => error.code === 'SAFETY_REFUSAL');
    assert.equal(f.events.includes('inspect-gateway'), false);
    assert.deepEqual(f.removed, []);
  }
});

test('changed, OAuth, unlisted, dirty-worktree, and unknown-plugin entries are never sent to deletion services', async () => {
  const f = fixture();
  const result = await runUninstallCommand({}, f.context);
  assert.equal(result.preserved.length, 5);
  for (const item of result.preserved) {
    assert.equal(f.events.includes(`remove:${item.path}`), false, item.reason);
  }
});

test('gateway identity change or denial at the immediate recheck refuses stop and every deletion', async () => {
  for (const recheck of [async () => false, async () => { throw new Error('private identity canary'); }]) {
    const f = fixture();
    f.context.recheckOwnedGateway = recheck;
    await assert.rejects(runUninstallCommand({}, f.context), (error) => ['SAFETY_REFUSAL', 'PROCESS_IDENTITY_MISMATCH'].includes(error.code)
      && !error.message.includes('canary'));
    assert.equal(f.events.includes('stop-gateway'), false);
    assert.deepEqual(f.removed, []);
    assert.equal(f.events.at(-1), 'lock-release');
  }
});

test('OAuth purge requires explicit confirmation, requires --yes noninteractively, and refuses unsafe roots', async () => {
  const declined = fixture();
  declined.context.confirmPurgeAuth = async () => false;
  await assert.rejects(runUninstallCommand({ purgeAuth: true }, declined.context),
    (error) => error.code === 'INTERACTION_REQUIRED');
  assert.equal(declined.events.includes('purge-auth'), false);

  const unattended = fixture();
  await assert.rejects(runUninstallCommand({ purgeAuth: true, nonInteractive: true }, unattended.context),
    (error) => error.code === 'INTERACTION_REQUIRED');
  assert.equal(unattended.events.includes('inspect-auth'), false);

  const confirmed = fixture();
  const result = await runUninstallCommand({ purgeAuth: true, nonInteractive: true, yes: true }, confirmed.context);
  assert.equal(result.auth.action, 'removed');
  assert.equal(confirmed.events.includes('confirm-auth'), false);
  assert.equal(confirmed.events.includes('purge-auth'), true);
  assert.ok(confirmed.events.indexOf('recheck-auth') < confirmed.events.indexOf('purge-auth'));

  const unsafe = fixture();
  unsafe.context.paths = { ...PATHS, authRoot: 'C:\\' };
  unsafe.context.inspectAuthRoot = async () => ({
    canonicalPath: 'C:\\', exists: true, type: 'directory', isLink: false, isJunction: false, isReparsePoint: false
  });
  await assert.rejects(runUninstallCommand({ purgeAuth: true, yes: true }, unsafe.context),
    (error) => error.code === 'SAFETY_REFUSAL');
  assert.equal(unsafe.events.includes('purge-auth'), false);
});

test('purge dry-run does not prompt, while a final auth-root identity change refuses deletion', async () => {
  const dry = fixture();
  dry.context.confirmPurgeAuth = async () => assert.fail('dry-run must not prompt');
  const preview = await runUninstallCommand({ dryRun: true, purgeAuth: true, nonInteractive: true }, dry.context);
  assert.deepEqual(preview.auth, { action: 'remove', reason: 'requested' });
  assert.equal(dry.events.includes('purge-auth'), false);

  const raced = fixture();
  raced.context.recheckAuthRoot = async () => false;
  await assert.rejects(runUninstallCommand({ purgeAuth: true, yes: true }, raced.context),
    (error) => error.code === 'SAFETY_REFUSAL');
  assert.equal(raced.events.includes('purge-auth'), false);

  const junction = fixture();
  junction.context.inspectAuthRoot = async () => ({
    canonicalPath: PATHS.authRoot, exists: true, type: 'directory', isLink: false, isJunction: true, isReparsePoint: false
  });
  await assert.rejects(runUninstallCommand({ purgeAuth: true, yes: true }, junction.context),
    (error) => error.code === 'SAFETY_REFUSAL');
  assert.equal(junction.events.includes('purge-auth'), false);
});

test('an interrupted mutation leaves journal recovery state, releases the lock, and sanitizes diagnostics', async () => {
  const f = fixture({ failAt: `remove:${ROOT}\\releases\\7.2.130\\CLIProxyAPI.exe` });
  await assert.rejects(runUninstallCommand({}, f.context), (error) => error.code === 'SAFETY_REFUSAL'
    && !error.message.includes('private'));
  assert.equal(f.events.includes('clear-journal'), false);
  assert.equal(f.events.at(-1), 'lock-release');
  assert.equal(f.events.includes('checkpoint:committed'), false);
});

test('a repeated uninstall with no manifest is an exit-zero no-op with no broadened scan or mutation', async () => {
  const f = fixture({ manifest: null });
  const result = await runUninstallCommand({}, f.context);
  assert.deepEqual(result, {
    operation: 'uninstall', changed: false, dryRun: false, alreadyUninstalled: true,
    targets: [], preserved: [], auth: { action: 'preserved', reason: 'not-requested' }
  });
  assert.equal(f.events.includes('plan'), false);
  assert.equal(f.events.includes('inspect-gateway'), false);
  assert.equal(f.events.at(-1), 'lock-release');
});

test('programmatic option types and hostile accessors are rejected before acquiring the lock', async () => {
  for (const options of [{ dryRun: 1 }, { purgeAuth: 'true' }, { yes: null }, { nonInteractive: 0 }]) {
    const f = fixture();
    await assert.rejects(runUninstallCommand(options, f.context), (error) => error.code === 'SAFETY_REFUSAL');
    assert.deepEqual(f.events, []);
  }
  const f = fixture();
  const hostile = new Proxy({}, { ownKeys: () => { throw new Error('private option canary'); } });
  await assert.rejects(runUninstallCommand(hostile, f.context), (error) => error.code === 'SAFETY_REFUSAL'
    && !error.message.includes('canary'));
  assert.deepEqual(f.events, []);
});
