import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { attachUsage, collectProviderUsage, formatUsageLine, providerTitle, usageForModel } from '../../../src/providers/usage.js';

test('labels models with provider titles and keeps usage after the provider', () => {
  assert.equal(providerTitle('codex'), 'Codex');
  assert.equal(providerTitle('antigravity'), 'Antigravity');
  assert.equal(providerTitle('grok'), 'Grok');
  assert.equal(providerTitle('cursor'), null);

  assert.equal(
    formatUsageLine({ id: 'gpt-5.6-sol', owned_by: 'codex', usage: { remainingPercent: 40, status: 'available' } }),
    'gpt-5.6-sol — Codex · 40% left'
  );
  assert.equal(
    formatUsageLine({ id: 'gpt-5.6-sol', owned_by: 'antigravity' }),
    'gpt-5.6-sol — Antigravity'
  );
  assert.equal(
    formatUsageLine({ id: 'grok-4.5', owned_by: 'grok', usage: { remainingPercent: 83, status: 'available' } }),
    'grok-4.5 — Grok · 83% left'
  );
});

test('attaches Grok, Antigravity, and Cursor remaining percent onto unmatched catalog ids', () => {
  const grok = usageForModel({ id: 'grok-4.6', owned_by: 'grok' }, {
    grok: { status: 'available', remainingPercent: 64, resetAt: '2026-08-21T20:27:10.549Z', window: '7d', extras: [] }
  });
  assert.equal(grok.remainingPercent, 64);
  assert.equal(grok.window, '7d');
  const flash = usageForModel({ id: 'gemini-3-flash-agent', owned_by: 'antigravity' }, {
    antigravity: {
      status: 'available', remainingPercent: 41, resetAt: '2026-08-17T16:00:00Z', extras: [
        { name: 'gemini-3.1-flash-lite', remainingPercent: 100, resetAt: '2026-08-17T16:00:00Z', allowed: true }
      ]
    }
  });
  assert.equal(flash.remainingPercent, 41);
  const lite = usageForModel({ id: 'gemini-3.1-flash-lite', owned_by: 'antigravity' }, {
    antigravity: {
      status: 'available', remainingPercent: 41, extras: [
        { name: 'gemini-3.1-flash-lite', remainingPercent: 100, allowed: true }
      ]
    }
  });
  assert.equal(lite.remainingPercent, 100);
  const composer = usageForModel({ id: 'composer-2.5', owned_by: 'cursor' }, {
    cursor: {
      status: 'exhausted', remainingPercent: 0, extras: [
        { name: 'composer-2.5', remainingPercent: 0, window: 'auto', allowed: false }
      ]
    }
  });
  assert.equal(composer.remainingPercent, 0);
  assert.equal(composer.status, 'exhausted');
});

test('collectProviderUsage reads Grok billing credits and Cursor period usage', async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(String(url));
    if (String(url).includes('cli-chat-proxy.grok.com/v1/user')) {
      return { status: 200, json: async () => ({ userId: 'user-1' }) };
    }
    if (String(url).includes('billing?format=credits')) {
      return { status: 200, json: async () => ({ config: { creditUsagePercent: 36, currentPeriod: { type: 'USAGE_PERIOD_TYPE_WEEKLY', end: '2026-08-21T20:00:00Z' }, productUsage: [{ product: 'GrokBuild', usagePercent: 36 }] } }) };
    }
    if (String(url).includes('api.x.ai/v1/models')) {
      return { status: 200, json: async () => ({ data: [{ id: 'grok-4.6', context_length: 500000 }] }) };
    }
    if (String(url).includes('GetCurrentPeriodUsage')) {
      return { status: 200, json: async () => ({ planUsage: { totalPercentUsed: 100, autoPercentUsed: 100, apiPercentUsed: 80 }, autoBucketModels: ['composer-2.5'], billingCycleEnd: '1789071806000' }) };
    }
    throw new Error(`unexpected ${url}`);
  };
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'usage-'));
  await fs.writeFile(path.join(root, 'xai.json'), JSON.stringify({
    type: 'xai', access_token: 'token', sub: 'user-1'
  }));
  const result = await collectProviderUsage({
    authDir: root,
    fetchImpl,
    readCursorToken: async () => 'cursor-token'
  });
  assert.equal(result.grok.remainingPercent, 64);
  assert.equal(result.grok.window, '7d');
  assert.equal(result.cursor.remainingPercent, 0);
  assert.equal(result.cursor.status, 'exhausted');
  await fs.rm(root, { recursive: true, force: true });
});

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
  const result = await collectProviderUsage({
    authDir: 'non_existent_dir_123',
    fetchImpl: failingFetch,
    readCursorToken: async () => null
  });
  assert.deepEqual(result, { cursor: { provider: 'cursor', status: 'unavailable' } });
});
