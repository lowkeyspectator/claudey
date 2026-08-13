import assert from 'node:assert/strict';
import test from 'node:test';

import { runModelsCommand } from '../../src/cli/commands/models.js';
import { requestGatewayModels } from '../../src/core/gateway-client.js';
import { Secret } from '../../src/core/secrets.js';
import { requireProviderModel } from '../../src/providers/models.js';
import { startFakeGateway } from '../support/fake-gateway.js';

const TOKEN_BYTES = Buffer.alloc(32, 12);
const TOKEN_TEXT = TOKEN_BYTES.toString('base64url');

async function fixture(t, catalog) {
  const gateway = await startFakeGateway({ token: TOKEN_TEXT, catalog });
  t.after(() => gateway.close());
  return {
    host: gateway.host,
    port: gateway.port,
    token: Secret.fromBytes(TOKEN_BYTES),
    ensureHealthy: async () => ({ state: 'healthy' }),
    requestModels: requestGatewayModels
  };
}

test('models command uses the authenticated loopback endpoint and returns only exact provider ownership in sorted order', async (t) => {
  const context = await fixture(t, { object: 'list', data: [
    { id: 'z-codex', object: 'model', created: 3, owned_by: 'codex' },
    { id: 'agy', object: 'model', created: 2, owned_by: 'antigravity' },
    { id: 'a-codex', object: 'model', created: 1, owned_by: 'codex' }
  ] });
  const result = await runModelsCommand(['models', 'codex'], context);
  assert.deepEqual(result.models.map(({ id }) => id), ['a-codex', 'z-codex']);
  await assert.rejects(requireProviderModel('codex', 'agy', context), (error) => error.code === 'MODEL_NOT_FOUND');
});

test('models all preserves a successful provider while marking an unauthenticated provider unavailable', async (t) => {
  const context = await fixture(t, { object: 'list', data: [
    { id: 'codex-only', object: 'model', created: 1, owned_by: 'codex' }
  ] });
  const result = await runModelsCommand(['models', 'all'], context);
  assert.equal(result.status, 'partial');
  assert.deepEqual(result.providers.map(({ provider, status, code }) => ({ provider, status, code })), [
    { provider: 'codex', status: 'available', code: undefined },
    { provider: 'antigravity', status: 'unavailable', code: 'AUTH_REQUIRED' }
  ]);
});

test('malformed or ambiguously attributed live catalogs fail closed', async (t) => {
  const context = await fixture(t, { object: 'list', data: [
    { id: 'ambiguous', object: 'model', created: 1, owned_by: 'codex', provider: 'antigravity' }
  ] });
  await assert.rejects(runModelsCommand(['models', 'codex'], context), (error) => error.code === 'GATEWAY_UNHEALTHY');
});
