import assert from 'node:assert/strict';
import test from 'node:test';

import { ClaudeyError } from '../../../src/core/errors.js';
import { Secret } from '../../../src/core/secrets.js';
import { visibleModelId } from '../../../src/providers/catalog.js';
import {
  listAllGatewayModels,
  listProviderModels,
  requireProviderModel
} from '../../../src/providers/models.js';

const TOKEN = Secret.fromBytes(Buffer.alloc(32, 9));

function context(overrides = {}) {
  const calls = [];
  return {
    calls,
    value: {
      host: '127.0.0.1', port: 8317, token: TOKEN,
      ensureHealthy: async () => { calls.push('healthy'); return { state: 'healthy' }; },
      requestModels: async (request) => {
        calls.push({ request });
        return { object: 'list', data: [
          { id: 'zeta', object: 'model', created: 2, owned_by: 'codex' },
          { id: 'alpha', object: 'model', created: 1, owned_by: 'codex' },
          { id: 'agy-pro', object: 'model', created: 3, owned_by: 'antigravity' },
          { id: 'grok-4.5', object: 'model', created: 4, owned_by: 'xai' }
        ] };
      },
      ...overrides
    }
  };
}

test('ensures the owned gateway, fetches an authenticated strict catalog, filters exact owned_by, and sorts deterministically', async () => {
  const fixture = context();
  const result = await listProviderModels('codex', fixture.value);
  assert.deepEqual(result, {
    provider: 'codex',
    status: 'available',
    models: [
      { id: 'alpha', object: 'model', created: 1, owned_by: 'codex' },
      { id: 'zeta', object: 'model', created: 2, owned_by: 'codex' }
    ]
  });
  assert.equal(fixture.calls[0], 'healthy');
  assert.deepEqual(fixture.calls[1].request, { host: '127.0.0.1', port: 8317, token: TOKEN, allowPreAuthEmpty: true, signal: undefined });
});

test('retries an empty provider catalog until Antigravity finishes async registration', async () => {
  let calls = 0;
  const fixture = context({
    modelReadyWaitMs: 1_000,
    sleep: async () => {},
    requestModels: async () => {
      calls += 1;
      if (calls < 3) {
        return { object: 'list', data: [{ id: 'gpt', object: 'model', created: 1, owned_by: 'openai' }] };
      }
      return { object: 'list', data: [
        { id: 'gpt', object: 'model', created: 1, owned_by: 'openai' },
        { id: 'gemini-3-flash', object: 'model', created: 2, owned_by: 'antigravity' }
      ] };
    }
  });
  const result = await listProviderModels('antigravity', fixture.value);
  assert.equal(result.models[0].id, 'gemini-3-flash');
  assert.equal(calls, 3);
});

test('maps live Google ownership onto the antigravity provider', async () => {
  const fixture = context({
    requestModels: async () => ({ object: 'list', data: [
      { id: 'gemini-3-flash', object: 'model', created: 2, owned_by: 'google' }
    ] })
  });
  const result = await listProviderModels('antigravity', fixture.value);
  assert.deepEqual(result.models, [{ id: 'gemini-3-flash', object: 'model', created: 2, owned_by: 'antigravity' }]);
});

test('maps live xAI ownership onto the grok provider without guessing from the model name', async () => {
  const fixture = context();
  const result = await listProviderModels('grok', fixture.value);
  assert.deepEqual(result, {
    provider: 'grok',
    status: 'available',
    models: [{ id: 'grok-4.5', object: 'model', created: 4, owned_by: 'grok' }]
  });
});

test('normalizes managed visible aliases and their encoded provider from the live catalog', async () => {
  const fixture = context({
    requestModels: async () => ({ object: 'list', data: [
      { id: visibleModelId('codex', 'gpt-5.6-sol'), object: 'model', created: 1, owned_by: 'anthropic' }
    ] })
  });

  const result = await listProviderModels('codex', fixture.value);

  assert.deepEqual(result.models, [
    { id: 'gpt-5.6-sol', object: 'model', created: 1, owned_by: 'codex' }
  ]);
});

test('rejects malformed catalogs, ambiguous attribution, duplicates, and provider-name heuristics', async () => {
  const hostile = [
    { data: [] },
    { object: 'list', data: [{ id: 'codex-looking-name', object: 'model', created: 1, owned_by: 'antigravity' }] },
    { object: 'list', data: [{ id: 'x', object: 'model', created: 1, owned_by: 'codex' }, { id: 'x', object: 'model', created: 2, owned_by: 'codex' }] },
    { object: 'list', data: [{ id: 'x', object: 'model', created: 1, owned_by: 'codex', provider: 'antigravity' }] }
  ];
  for (const catalog of hostile) {
    const fixture = context({ requestModels: async () => catalog });
    if (catalog === hostile[1]) {
      await assert.rejects(listProviderModels('codex', fixture.value), (error) => error.code === 'AUTH_REQUIRED');
    } else {
      await assert.rejects(listProviderModels('codex', fixture.value), (error) => error.code === 'GATEWAY_UNHEALTHY');
    }
  }
});

test('distinguishes missing provider authentication and never falls back to another provider', async () => {
  const fixture = context({
    requestModels: async () => ({ object: 'list', data: [{ id: 'same-name', object: 'model', created: 1, owned_by: 'antigravity' }] })
  });
  await assert.rejects(listProviderModels('codex', fixture.value), (error) => error.code === 'AUTH_REQUIRED' && error.details.provider === 'codex');
});

test('requires requested models from the current exact provider list before downstream spawn', async () => {
  const fixture = context();
  assert.deepEqual(await requireProviderModel('codex', 'alpha', fixture.value), { id: 'alpha', object: 'model', created: 1, owned_by: 'codex' });
  let spawned = false;
  await assert.rejects(requireProviderModel('codex', 'agy-pro', fixture.value), (error) => error.code === 'MODEL_NOT_FOUND');
  assert.equal(spawned, false);
  for (const model of ['', ' alpha', 'alpha\0x', 42]) {
    await assert.rejects(requireProviderModel('codex', model, fixture.value), (error) => error.code === 'USAGE_ERROR');
  }
});

test('models all reports every provider and succeeds when at least one provider succeeds', async () => {
  const fixture = context();
  const result = await listAllGatewayModels({
    ...fixture.value,
    listOne: async (provider) => {
      if (provider === 'codex') return { provider, status: 'available', models: [{ id: 'gpt', object: 'model', created: 1, owned_by: provider }] };
      throw Object.assign(new Error('not logged in'), { code: 'AUTH_REQUIRED' });
    }
  });
  assert.deepEqual(result, {
    status: 'partial',
    providers: [
      { provider: 'codex', status: 'available', models: [{ id: 'gpt', object: 'model', created: 1, owned_by: 'codex' }] },
      { provider: 'antigravity', status: 'unavailable', code: 'AUTH_REQUIRED', models: [] },
      { provider: 'grok', status: 'unavailable', code: 'AUTH_REQUIRED', models: [] }
    ]
  });
});

test('models all returns the highest-priority public error when no gateway provider succeeds', async () => {
  const fixture = context();
  await assert.rejects(listAllGatewayModels({
    ...fixture.value,
    listOne: async (provider) => {
      if (provider === 'codex') throw Object.assign(new Error('logged out'), { code: 'AUTH_REQUIRED' });
      throw Object.assign(new Error('down'), { code: 'GATEWAY_UNHEALTHY' });
    }
  }), (error) => error.code === 'GATEWAY_UNHEALTHY' && !error.message.includes('down'));
});

test('sanitizes lifecycle and transport diagnostics before returning public model errors', async () => {
  for (const overrides of [
    { ensureHealthy: async () => { throw new ClaudeyError('GATEWAY_UNHEALTHY', 'lifecycle secret-canary'); } },
    { requestModels: async () => { throw new ClaudeyError('GATEWAY_UNHEALTHY', 'transport secret-canary'); } }
  ]) {
    const fixture = context(overrides);
    await assert.rejects(listProviderModels('codex', fixture.value), (error) => error.code === 'GATEWAY_UNHEALTHY'
      && !error.message.includes('secret-canary') && !JSON.stringify(error.details).includes('secret-canary'));
  }
});
