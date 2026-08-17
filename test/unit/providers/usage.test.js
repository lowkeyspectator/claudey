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
    'gpt-5.6-sol - Codex | 40% left'
  );
  assert.equal(
    formatUsageLine({ id: 'gpt-5.6-sol', owned_by: 'antigravity' }),
    'gpt-5.6-sol - Antigravity'
  );
  assert.equal(
    formatUsageLine({ id: 'grok-4.5', owned_by: 'grok', usage: { remainingPercent: 83, status: 'available' } }),
    'grok-4.5 - Grok | 83% left'
  );
  assert.equal(
    formatUsageLine({
      id: 'gemini-3-flash',
      owned_by: 'antigravity',
      usage: {
        status: 'available',
        remainingPercent: 60,
        window: '7d',
        windows: [
          { window: '7d', remainingPercent: 60 },
          { window: '5h', remainingPercent: 100 }
        ]
      }
    }),
    'gemini-3-flash - Antigravity | 60%/7d · 100%/5h'
  );
});

test('collectProviderUsage prefers Antigravity quota summary pools with antigravity User-Agent', async () => {
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push({ url: String(url), headers: options.headers ?? {}, body: options.body });
    if (String(url).includes('retrieveUserQuotaSummary')) {
      return {
        status: 200,
        json: async () => ({
          groups: [
            {
              displayName: 'Gemini Models',
              buckets: [
                { bucketId: 'gemini-weekly', window: 'weekly', remainingFraction: 0.606, resetTime: '2026-08-17T23:59:46Z' },
                { bucketId: 'gemini-5h', window: '5h', remainingFraction: 1, resetTime: '2026-08-18T02:05:25Z' }
              ]
            },
            {
              displayName: 'Claude and GPT models',
              buckets: [
                { bucketId: '3p-weekly', window: 'weekly', remainingFraction: 0.771, resetTime: '2026-08-23T02:42:13Z' },
                { bucketId: '3p-5h', window: '5h', remainingFraction: 1, resetTime: '2026-08-18T02:05:25Z' }
              ]
            }
          ]
        })
      };
    }
    if (String(url).includes('GetCurrentPeriodUsage')) {
      return { status: 200, json: async () => ({ planUsage: { totalPercentUsed: 10 } }) };
    }
    throw new Error(`unexpected ${url}`);
  };
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'usage-agy-'));
  await fs.writeFile(path.join(root, 'antigravity.json'), JSON.stringify({
    type: 'antigravity', access_token: 'token', project_id: 'proj-1'
  }));
  const result = await collectProviderUsage({
    authDir: root,
    fetchImpl,
    readCursorToken: async () => null
  });
  assert.equal(result.antigravity.status, 'available');
  const gemini = usageForModel({ id: 'gemini-3-flash', owned_by: 'antigravity' }, result);
  assert.equal(gemini.status, 'available');
  assert.equal(gemini.remainingPercent, 61);
  assert.deepEqual(gemini.windows, [
    { window: '7d', remainingPercent: 61, resetAt: '2026-08-17T23:59:46Z' },
    { window: '5h', remainingPercent: 100, resetAt: '2026-08-18T02:05:25Z' }
  ]);
  const claude = usageForModel({ id: 'claude-sonnet-4-6', owned_by: 'antigravity' }, result);
  assert.equal(claude.remainingPercent, 77);
  const gpt = usageForModel({ id: 'gpt-oss-120b-medium', owned_by: 'antigravity' }, result);
  assert.equal(gpt.remainingPercent, 77);
  assert.equal(calls.some((call) => /retrieveUserQuotaSummary/u.test(call.url)), true);
  assert.equal(
    calls.every((call) => !/retrieveUserQuotaSummary|retrieveUserQuota/u.test(call.url)
      || call.headers['user-agent'] === 'antigravity'
      || call.headers['User-Agent'] === 'antigravity'),
    true
  );
  await fs.rm(root, { recursive: true, force: true });
});

test('collectProviderUsage falls back to per-model Antigravity retrieveUserQuota with User-Agent', async () => {
  const fetchImpl = async (url, options = {}) => {
    if (String(url).includes('retrieveUserQuotaSummary')) {
      return { status: 403, json: async () => ({ error: { code: 403 } }) };
    }
    if (String(url).includes('retrieveUserQuota')) {
      assert.equal(options.headers?.['user-agent'] ?? options.headers?.['User-Agent'], 'antigravity');
      return {
        status: 200,
        json: async () => ({
          buckets: [
            { modelId: 'gemini-3-flash', remainingFraction: 0.4, resetTime: '2026-08-18T02:05:25Z' },
            { modelId: 'claude-sonnet-4-6', remainingFraction: 0.9, resetTime: '2026-08-18T02:05:25Z' }
          ]
        })
      };
    }
    if (String(url).includes('GetCurrentPeriodUsage')) {
      return { status: 200, json: async () => ({ planUsage: { totalPercentUsed: 10 } }) };
    }
    throw new Error(`unexpected ${url}`);
  };
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'usage-agy-fb-'));
  await fs.writeFile(path.join(root, 'antigravity.json'), JSON.stringify({
    type: 'antigravity', access_token: 'token', project_id: 'proj-1'
  }));
  const result = await collectProviderUsage({
    authDir: root,
    fetchImpl,
    readCursorToken: async () => null
  });
  assert.equal(result.antigravity.status, 'available');
  assert.equal(usageForModel({ id: 'gemini-3-flash', owned_by: 'antigravity' }, result).remainingPercent, 40);
  assert.equal(usageForModel({ id: 'claude-sonnet-4-6', owned_by: 'antigravity' }, result).remainingPercent, 90);
  await fs.rm(root, { recursive: true, force: true });
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

test('Grok treats a current period without creditUsagePercent as 100% remaining and never shows ctx as usage', async () => {
  const fetchImpl = async (url) => {
    if (String(url).includes('cli-chat-proxy.grok.com/v1/user')) {
      return { status: 200, json: async () => ({ userId: 'user-1' }) };
    }
    if (String(url).includes('billing?format=credits')) {
      return {
        status: 200,
        json: async () => ({
          config: {
            currentPeriod: {
              type: 'USAGE_PERIOD_TYPE_WEEKLY',
              start: '2026-08-14T20:27:10.549509+00:00',
              end: '2026-08-21T20:27:10.549509+00:00'
            },
            onDemandCap: { val: 0 },
            onDemandUsed: { val: 0 },
            isUnifiedBillingUser: true
          }
        })
      };
    }
    if (String(url).includes('api.x.ai/v1/models')) {
      return {
        status: 200,
        json: async () => ({
          data: [
            { id: 'grok-4.6', context_length: 500000 },
            { id: 'grok-4.5', context_length: 500000 }
          ]
        })
      };
    }
    if (String(url).includes('GetCurrentPeriodUsage')) {
      return { status: 200, json: async () => ({ planUsage: { totalPercentUsed: 10 } }) };
    }
    throw new Error(`unexpected ${url}`);
  };
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'usage-grok-omit-'));
  await fs.writeFile(path.join(root, 'xai.json'), JSON.stringify({
    type: 'xai', access_token: 'token', sub: 'user-1'
  }));
  const result = await collectProviderUsage({
    authDir: root,
    fetchImpl,
    readCursorToken: async () => null
  });
  assert.equal(result.grok.status, 'available');
  assert.equal(result.grok.remainingPercent, 100);
  assert.equal(result.grok.window, '7d');
  const labeled = usageForModel({ id: 'grok-4.6', owned_by: 'grok' }, result);
  assert.equal(labeled.remainingPercent, 100);
  assert.equal(labeled.window, '7d');
  assert.equal(
    formatUsageLine({ id: 'grok-4.6', owned_by: 'grok', usage: labeled }),
    'grok-4.6 - Grok | 100% left'
  );
  const unmatched = usageForModel({ id: 'grok-3-mini', owned_by: 'grok' }, result);
  assert.equal(unmatched.remainingPercent, 100);
  assert.equal(
    formatUsageLine({ id: 'grok-3-mini', owned_by: 'grok', usage: unmatched }),
    'grok-3-mini - Grok | 100% left'
  );
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
