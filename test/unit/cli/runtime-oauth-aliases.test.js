import assert from 'node:assert/strict';
import path from 'node:path';
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

test('syncManagedOAuthAliases writes managed config containing oauth-model-alias', async () => {
  assert.equal(typeof runtime.syncManagedOAuthAliases, 'function');
  const writes = [];
  const paths = { configRoot: '/managed/config', authRoot: '/managed/auth' };
  const result = await runtime.syncManagedOAuthAliases({
    paths,
    port: 8317,
    token: TOKEN,
    models: [{ id: 'gpt-5.6-sol', object: 'model', created: 1, owned_by: 'codex' }],
    fsApi: {
      writeFile: async (...args) => writes.push(args)
    }
  });

  assert.equal(writes.length, 1);
  assert.equal(writes[0][0], path.join(paths.configRoot, 'config.yaml'));
  assert.deepEqual(writes[0][2], { mode: 0o600 });
  assert.match(writes[0][1].toString('utf8'), /oauth-model-alias:/u);
  assert.match(writes[0][1].toString('utf8'), new RegExp(visibleModelId('codex', 'gpt-5.6-sol'), 'u'));
  assert.equal(result.synced, true);
  assert.equal(result.oauthModelAlias.codex[0].alias, visibleModelId('codex', 'gpt-5.6-sol'));
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
