import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { canonicalManifestBytes } from '../../src/core/manifest.js';
import { Secret } from '../../src/core/secrets.js';
import { parseManagementArgs } from '../../src/cli/parse.js';
import {
  createCursorMcpToolExecutor, runCursorCommand, runCursorMcpServe, runCursorModelsCommand
} from '../../src/cli/commands/cursor.js';

const UUID = '11111111-1111-4111-8111-111111111111';
const MANAGER = '/home/casey/.local/share/claudexctl';
const MARKETPLACE = `${MANAGER}/marketplace`;
const PROJECT = '/home/casey/project';

function fixture() {
  const events = [];
  const plugin = new Map();
  let writesEnabled = false;
  const call = (name, value) => { events.push([name, value]); return value; };
  const context = {
    installationId: UUID, managerRoot: MANAGER, marketplaceRoot: MARKETPLACE, platform: 'linux', currentProject: PROJECT,
    inspectPluginRegistration: async ({ scope }) => plugin.get(scope)
      ?? { marketplace: 'absent', plugin: 'absent', ownerInstallationId: null },
    runClaudePlugin: async (args) => call('claude-plugin', [...args]),
    writePluginOwnership: async ({ scope }) => {
      plugin.set(scope, { marketplace: 'owned', plugin: 'owned', ownerInstallationId: UUID });
      call('write-plugin-owner', scope);
    },
    removePluginOwnership: async ({ scope }) => { plugin.delete(scope); call('remove-plugin-owner', scope); },
    registry: {
      add: async (value) => { call('repo-add', { ...value }); return { action: 'added', root: value.path, scope: value.scope }; },
      list: async () => { call('repo-list'); return [{ root: PROJECT, scope: 'local' }]; },
      remove: async (value) => { call('repo-remove', { ...value }); return { action: 'removed', root: value.path }; }
    },
    writesStore: {
      read: async () => ({ schemaVersion: 1, installationId: UUID, enabled: writesEnabled }),
      write: async (record) => { writesEnabled = record.enabled; call('write-writes', structuredClone(record)); }
    },
    approvalService: {
      approve: async (id, options) => { call('approve', { id, isTTY: options.isTTY });
        const accepted = await options.confirm({ repository: PROJECT, model: 'cursor-a', baseCommit: 'a'.repeat(40),
          installationId: UUID, promptPreview: 'safe\\npreview', promptDigest: 'b'.repeat(64), expiresAt: 300_000 });
        if (!accepted) throw Object.assign(new Error('declined'), { code: 'APPROVAL_INVALID' });
        return { action: 'approved', approvalId: id }; },
      cleanup: async () => { call('approval-cleanup'); return { action: 'cleared' }; }
    },
    isTTY: true,
    confirmApproval: async (display) => call('confirm-approval', display) && true,
    cursorAvailable: async () => false,
    downloadCursorInstaller: async (request) => call('download-installer', request) && ({
      finalUrl: 'https://cursor.com/download/stable', sha256: 'c'.repeat(64), path: '/tmp/private/cursor-installer'
    }),
    confirmCursorInstaller: async (display) => call('confirm-installer', display) && true,
    executeCursorInstaller: async (descriptor) => call('execute-installer', descriptor),
    verifyCursorPrerequisite: async () => { call('verify-cursor'); return true; },
    runCursorLogin: async () => { call('cursor-login'); return { code: 0, signal: null }; },
    listCursorModels: async () => { call('cursor-models'); return { models: ['cursor-a', 'cursor-b'] }; },
    ensureGateway: async () => call('gateway-start')
  };
  return { context, events, plugin, get writesEnabled() { return writesEnabled; } };
}

test('enable uses only owned Claude marketplace/plugin commands, is scope-idempotent, and locally registers only the current project', async () => {
  const f = fixture();
  assert.deepEqual(await runCursorCommand(['cursor', 'enable'], { scope: 'local' }, f.context),
    { action: 'enabled', scope: 'local' });
  assert.deepEqual(f.events.slice(0, 4), [
    ['claude-plugin', ['plugin', 'marketplace', 'add', MARKETPLACE, '--scope', 'local']],
    ['claude-plugin', ['plugin', 'install', 'cursor-agent@claudey', '--scope', 'local']],
    ['write-plugin-owner', 'local'],
    ['repo-add', { path: PROJECT, scope: 'local', currentProject: PROJECT, confirmed: true }]
  ]);
  f.events.length = 0;
  assert.deepEqual(await runCursorCommand(['cursor', 'enable'], { scope: 'local' }, f.context),
    { action: 'preserved', reason: 'already-enabled', scope: 'local' });
  assert.deepEqual(f.events, [['repo-add', { path: PROJECT, scope: 'local', currentProject: PROJECT, confirmed: true }]]);

  f.plugin.set('user', { marketplace: 'foreign', plugin: 'foreign', ownerInstallationId: null });
  await assert.rejects(runCursorCommand(['cursor', 'enable'], { scope: 'user' }, f.context),
    (error) => error.code === 'MCP_OWNERSHIP_COLLISION');
  assert.equal(f.events.some(([name]) => name === 'settings-write'), false);
});

test('disable removes only exact owned scope through Claude commands, clears approvals/write opt-in, and repeats as a no-op', async () => {
  const f = fixture();
  await runCursorCommand(['cursor', 'enable'], { scope: 'user' }, f.context);
  f.events.length = 0;
  assert.deepEqual(await runCursorCommand(['cursor', 'disable'], { scope: 'user' }, f.context),
    { action: 'disabled', scope: 'user' });
  assert.deepEqual(f.events, [
    ['claude-plugin', ['plugin', 'uninstall', 'cursor-agent@claudey', '--scope', 'user', '--yes']],
    ['claude-plugin', ['plugin', 'marketplace', 'remove', 'claudey', '--scope', 'user']],
    ['remove-plugin-owner', 'user'], ['write-writes', { schemaVersion: 1, installationId: UUID, enabled: false }],
    ['approval-cleanup', undefined]
  ]);
  f.events.length = 0;
  assert.deepEqual(await runCursorCommand(['cursor', 'disable'], { scope: 'user' }, f.context),
    { action: 'preserved', reason: 'already-disabled', scope: 'user' });
  assert.deepEqual(f.events, [
    ['write-writes', { schemaVersion: 1, installationId: UUID, enabled: false }], ['approval-cleanup', undefined]
  ]);
});

test('explicit Cursor install displays fixed trust warning/final URL/hash before execution; login and models never start the gateway', async () => {
  const f = fixture();
  const installed = await runCursorCommand(['cursor', 'install'], { yes: true, nonInteractive: true }, f.context);
  assert.deepEqual(installed, { action: 'installed', sha256: 'c'.repeat(64), finalUrl: 'https://cursor.com/download/stable' });
  assert.deepEqual(f.events.map(([name]) => name),
    ['download-installer', 'confirm-installer', 'execute-installer', 'verify-cursor']);
  assert.match(f.events[1][1].warning, /no stable detached checksum/iu);
  assert.equal(f.events[1][1].yes, true);

  f.events.length = 0;
  assert.deepEqual(await runCursorCommand(['cursor', 'login'], {}, f.context), { action: 'authenticated' });
  assert.deepEqual(f.events.map(([name]) => name), ['verify-cursor', 'cursor-login']);
  f.events.length = 0;
  assert.deepEqual(await runCursorModelsCommand(f.context), { provider: 'cursor', models: ['cursor-a', 'cursor-b'] });
  assert.deepEqual(f.events.map(([name]) => name), ['verify-cursor', 'cursor-models']);
  assert.equal(f.events.some(([name]) => name === 'gateway-start'), false);

  const refused = fixture();
  await assert.rejects(runCursorCommand(['cursor', 'install'], { nonInteractive: true }, refused.context),
    (error) => error.code === 'INTERACTION_REQUIRED');
  assert.deepEqual(refused.events, []);
  await assert.rejects(runCursorCommand(['cursor', 'login'], { nonInteractive: true }, refused.context),
    (error) => error.code === 'INTERACTION_REQUIRED');
});

test('repo, write opt-in, and TTY approval commands delegate exact typed records and enforce confirmation boundaries', async () => {
  const f = fixture();
  assert.deepEqual(await runCursorCommand(['cursor', 'repo', 'add'], { path: '/home/casey/other', yes: true }, f.context),
    { action: 'added', root: '/home/casey/other', scope: 'user' });
  assert.deepEqual(await runCursorCommand(['cursor', 'repo', 'list'], {}, f.context),
    { repositories: [{ root: PROJECT, scope: 'local' }] });
  assert.deepEqual(await runCursorCommand(['cursor', 'repo', 'remove'], { path: '/home/casey/other', yes: true }, f.context),
    { action: 'removed', root: '/home/casey/other' });
  assert.deepEqual(await runCursorCommand(['cursor', 'writes', 'enable'], { yes: true }, f.context), { action: 'enabled' });
  assert.equal(f.writesEnabled, true);
  assert.deepEqual(await runCursorCommand(['cursor', 'writes', 'disable'], {}, f.context), { action: 'disabled' });
  assert.equal(f.writesEnabled, false);
  assert.deepEqual(await runCursorCommand(['cursor', 'approve'], { approvalId: 'a'.repeat(43) }, f.context),
    { action: 'approved', approvalId: 'a'.repeat(43) });
  assert.equal(f.events.find(([name]) => name === 'confirm-approval')[1].promptDigest, 'b'.repeat(64));

  f.events.length = 0;
  assert.deepEqual(await runCursorCommand(['cursor', 'repo', 'remove'], {}, f.context),
    { action: 'removed', root: PROJECT });
  assert.deepEqual(f.events, [
    ['repo-list', undefined], ['repo-remove', { path: PROJECT, confirmed: true }]
  ]);

  await assert.rejects(runCursorCommand(['cursor', 'writes', 'enable'], { yes: false }, f.context),
    (error) => error.code === 'INTERACTION_REQUIRED');
  await assert.rejects(runCursorCommand(['cursor', 'approve'], { approvalId: 'a'.repeat(43), yes: true }, f.context),
    (error) => error.code === 'USAGE_ERROR');
});

test('MCP executor keeps models repository-independent, anchors ask/plan to startup source, and resolves worktree inputs through registered services', async () => {
  const events = [];
  let sourceResolutions = 0;
  const executor = createCursorMcpToolExecutor({
    resolveSourceRepository: async () => { sourceResolutions += 1; return { root: PROJECT, scope: 'local' }; },
    listCursorModels: async () => ({ models: ['cursor-a', 'cursor-b'] }),
    resolveRepository: async (root) => root === PROJECT ? { root: PROJECT, scope: 'local' } : null,
    readonlyService: {
      ask: async (value) => { events.push(['ask', value]); return { answer: 'ok' }; },
      plan: async (value) => { events.push(['plan', value]); return { plan: 'ok' }; }
    },
    worktreeService: { run: async (value) => { events.push(['worktree', value]); return { state: 'retained' }; } },
    defaultBaseRef: 'refs/heads/main'
  });
  assert.deepEqual(await executor({ name: 'cursor_models', arguments: {}, signal: new AbortController().signal }),
    { models: ['cursor-a', 'cursor-b'] });
  assert.equal(sourceResolutions, 0);
  await executor({ name: 'cursor_ask', arguments: { prompt: 'ask' }, signal: new AbortController().signal });
  await executor({ name: 'cursor_plan', arguments: { prompt: 'plan', model: 'cursor-b', paths: ['src/a.js'] },
    signal: new AbortController().signal });
  await executor({ name: 'cursor_worktree_run', arguments: { repo: PROJECT, prompt: 'change' },
    signal: new AbortController().signal });
  assert.equal(events[0][1].repository.root, PROJECT);
  assert.equal(events[0][1].model, 'cursor-a');
  assert.equal(events[1][1].model, 'cursor-b');
  assert.deepEqual(events[1][1].paths, ['src/a.js']);
  assert.equal(events[2][1].baseRef, 'refs/heads/main');
  assert.equal(sourceResolutions, 2);
  assert.equal(Object.hasOwn(events[2][1], 'argv'), false);

  const noSource = createCursorMcpToolExecutor({
    resolveSourceRepository: async () => null, listCursorModels: async () => ({ models: ['cursor-a'] }),
    resolveRepository: async () => null, readonlyService: { ask: async () => {}, plan: async () => {} },
    worktreeService: { run: async () => {} }, defaultBaseRef: 'refs/heads/main'
  });
  assert.deepEqual(await noSource({ name: 'cursor_models', arguments: {}, signal: new AbortController().signal }),
    { models: ['cursor-a'] });
  await assert.rejects(noSource({ name: 'cursor_ask', arguments: { prompt: 'x' }, signal: new AbortController().signal }),
    (error) => error.code === 'SAFETY_REFUSAL');
});

test('management parser accepts bounded repo confirmation and the fixed hidden MCP wrapper contract', () => {
  assert.deepEqual(parseManagementArgs(['cursor', 'repo', 'add', '/home/casey/project', '--yes']), {
    command: ['cursor', 'repo', 'add'], options: { path: '/home/casey/project', yes: true }
  });
  assert.deepEqual(parseManagementArgs(['cursor', 'repo', 'remove', '--yes']), {
    command: ['cursor', 'repo', 'remove'], options: { yes: true }
  });
  assert.deepEqual(parseManagementArgs(['cursor', 'mcp-serve', '--source-root', PROJECT,
    '--installation-id', UUID, '--manager-root', MANAGER]), {
    command: ['cursor', 'mcp-serve'], options: { sourceRoot: PROJECT, installationId: UUID, managerRoot: MANAGER }
  });
});

function signedManifest() {
  const key = Secret.fromBytes(Buffer.alloc(32, 0x44));
  const unsigned = {
    schemaVersion: 1, installationId: UUID, platform: { family: 'linux', runtimeArch: 'x64' },
    managedRoots: { managerRoot: MANAGER, stateRoot: `${MANAGER}/state`, userBinRoot: `${MANAGER}/bin`,
      ownedPluginRoots: [`${MANAGER}/plugins`] }, files: [], hmac: ''
  };
  const hmac = key.withValue((bytes) => crypto.createHmac('sha256', bytes)
    .update(canonicalManifestBytes(unsigned)).digest('base64url'));
  return { key, manifest: { ...unsigned, hmac }, fixedPaths: unsigned.managedRoots };
}

test('hidden MCP serve authenticates installation UUID/root and revalidates non-link manager/plugin identities before use', async () => {
  const signed = signedManifest();
  const events = [];
  let startupRecheck;
  const result = await runCursorMcpServe({ installationId: UUID, managerRoot: MANAGER, sourceRoot: PROJECT }, {
    readManifest: async () => structuredClone(signed.manifest), manifestKey: signed.key, fixedPaths: signed.fixedPaths,
    revalidateMcpPaths: async (value) => { events.push(['revalidate-paths', value]); return true; },
    createServer: async (value) => { events.push(['create-server']); startupRecheck = value.revalidateStartup; return { id: 'server' }; },
    serveMcp: async (server) => { events.push(['serve', server]); return { action: 'closed' }; }
  });
  assert.deepEqual(result, { action: 'closed' });
  assert.equal(await startupRecheck(), true);
  assert.deepEqual(events.map(([name]) => name), ['revalidate-paths', 'create-server', 'serve', 'revalidate-paths']);

  await assert.rejects(runCursorMcpServe({ installationId: '22222222-2222-4222-8222-222222222222',
    managerRoot: MANAGER }, {
    readManifest: async () => structuredClone(signed.manifest), manifestKey: signed.key, fixedPaths: signed.fixedPaths,
    revalidateMcpPaths: async () => true, createServer: async () => { throw new Error('must not create'); },
    serveMcp: async () => {}
  }), (error) => error.code === 'SAFETY_REFUSAL');
});
