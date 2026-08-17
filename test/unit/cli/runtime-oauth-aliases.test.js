import assert from 'node:assert/strict';
import test from 'node:test';

import { Secret } from '../../../src/core/secrets.js';
import { visibleModelId } from '../../../src/providers/catalog.js';
import * as runtime from '../../../src/cli/runtime.js';

const TOKEN = Secret.fromBytes(Buffer.alloc(32, 23));

test('production launcher context wires oauth alias synchronization and readiness hooks', () => {
  const context = runtime.createProductionContainer({ HOME: '/tmp/claudey-runtime-home' }).contexts.claudey;

  assert.equal(typeof context.syncOAuthAliases, 'function');
  assert.equal(typeof context.waitForAliasReady, 'function');
});

test('syncManagedOAuthAliases atomically replaces managed config containing oauth-model-alias', async () => {
  assert.equal(typeof runtime.syncManagedOAuthAliases, 'function');
  const replacements = [];
  const paths = { configRoot: '/managed/config', authRoot: '/managed/auth' };
  const result = await runtime.syncManagedOAuthAliases({
    paths,
    port: 8317,
    token: TOKEN,
    models: [{ id: 'gpt-5.6-sol', object: 'model', created: 1, owned_by: 'codex' }],
    acquireLock: async () => ({
      assertHeld: async () => {},
      release: async () => {}
    }),
    atomicReplace: async (...args) => replacements.push(args)
  });

  assert.equal(replacements.length, 1);
  assert.deepEqual({
    root: replacements[0][0].root,
    child: replacements[0][0].child,
    mode: replacements[0][0].mode
  }, { root: paths.configRoot, child: 'config.yaml', mode: 0o600 });
  assert.match(replacements[0][0].bytes.toString('utf8'), /oauth-model-alias:/u);
  assert.match(replacements[0][0].bytes.toString('utf8'), new RegExp(visibleModelId('codex', 'gpt-5.6-sol'), 'u'));
  assert.equal(result.synced, true);
  assert.equal(result.oauthModelAlias.codex[0].alias, visibleModelId('codex', 'gpt-5.6-sol'));
});

test('syncManagedOAuthAliases preserves foreign aliases while replacing managed aliases under the installation lock', async () => {
  const events = [];
  const replacements = [];
  const paths = { configRoot: '/managed/config', authRoot: '/managed/auth', stateRoot: '/managed/state' };
  const prior = `host: "127.0.0.1"
oauth-model-alias:
  codex:
    - name: "user-model"
      alias: "my-custom-alias"
      display-name: "My custom alias"
      force-mapping: false
      fork: true
    - name: "stale-model"
      alias: "${visibleModelId('codex', 'stale-model')}"
      display-name: "Stale managed alias"
      force-mapping: true
  xai:
    - name: "user-grok"
      alias: "personal-grok"
      display-name: "Personal Grok"
      force-mapping: true
`;
  const result = await runtime.syncManagedOAuthAliases({
    paths,
    port: 8317,
    token: TOKEN,
    models: [{ id: 'gpt-5.6-sol', object: 'model', created: 1, owned_by: 'codex' }],
    fsApi: {
      readFile: async () => {
        events.push('read');
        return prior;
      }
    },
    acquireLock: async () => {
      events.push('acquire');
      return {
        assertHeld: async () => events.push('held'),
        release: async () => events.push('release')
      };
    },
    atomicReplace: async (...args) => {
      events.push('write');
      replacements.push(args);
    }
  });

  const written = replacements[0][0].bytes.toString('utf8');
  assert.deepEqual(events, ['acquire', 'held', 'read', 'held', 'write', 'release']);
  assert.match(written, /alias: "my-custom-alias"/u);
  assert.match(written, /force-mapping: false/u);
  assert.match(written, /fork: true/u);
  assert.match(written, /alias: "personal-grok"/u);
  assert.doesNotMatch(written, /stale-model/u);
  assert.match(written, new RegExp(visibleModelId('codex', 'gpt-5.6-sol'), 'u'));
  assert.equal(result.oauthModelAlias.codex.some((entry) => entry.alias === 'my-custom-alias'), false);
});

test('waitForManagedAliases waits until every expected alias appears in the gateway catalog', async () => {
  assert.equal(typeof runtime.waitForManagedAliases, 'function');
  const codexAlias = visibleModelId('codex', 'gpt-5.6-sol');
  const grokAlias = visibleModelId('grok', 'grok-4.5');
  const catalogs = [
    { data: [{ id: codexAlias }] },
    { data: [{ id: codexAlias }, { id: grokAlias }] }
  ];
  const calls = [];

  const ready = await runtime.waitForManagedAliases({
    host: '127.0.0.1',
    port: 8317,
    token: TOKEN,
    aliases: {
      codex: [{ alias: codexAlias }],
      xai: [{ alias: grokAlias }]
    },
    requestModels: async (options) => {
      calls.push(options);
      return catalogs.shift();
    },
    timeoutMs: 100,
    delayMs: 0
  });

  assert.equal(ready, true);
  assert.equal(calls.length, 2);
  assert.equal(calls.every((call) => call.allowPreAuthEmpty === true), true);
});
