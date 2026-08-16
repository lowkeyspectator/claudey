import assert from 'node:assert/strict';
import test from 'node:test';

import { attachUsage, collectProviderUsage, usageForModel } from '../../../src/providers/usage.js';

test('maps Codex 7d remaining percent and named extra windows onto matching model ids', () => {
  const collected = {
    codex: {
      status: 'exhausted',
      remainingPercent: 0,
      resetAt: '2026-08-20T00:00:00.000Z',
      window: '7d',
      extras: [{ name: 'GPT-5.3-Codex-Spark', remainingPercent: 83, resetAt: '2026-08-21T00:00:00.000Z', window: '7d', allowed: true }]
    }
  };
  const spark = usageForModel({ id: 'gpt-5.3-codex-spark', owned_by: 'codex' }, collected);
  assert.equal(spark.remainingPercent, 83);
  assert.equal(spark.status, 'available');
  const general = usageForModel({ id: 'gpt-5.6-sol', owned_by: 'codex' }, collected);
  assert.equal(general.remainingPercent, 0);
  assert.equal(general.window, '7d');
});

test('attaches usage onto provider catalogs without inventing missing providers', () => {
  const result = attachUsage({
    provider: 'grok',
    status: 'available',
    models: [{ id: 'grok-4.5', object: 'model', created: 1, owned_by: 'grok' }]
  }, {
    grok: { status: 'available', remainingPercent: null, window: '1000000 ctx', extras: [{ name: 'grok-4.5', remainingPercent: null, window: '1000000 ctx', allowed: true }] }
  });
  assert.equal(result.models[0].usage.window, '1000000 ctx');
  assert.equal(result.models[0].id, 'grok-4.5');
});

test('collectProviderUsage gracefully handles network errors and timeouts', async () => {
  const failingFetch = async () => {
    throw new Error('Network timeout');
  };
  // We can pass a non-existent authDir to verify empty records or a fake dir
  const result = await collectProviderUsage({ authDir: 'non_existent_dir_123', fetchImpl: failingFetch });
  assert.deepEqual(result, {});
});
