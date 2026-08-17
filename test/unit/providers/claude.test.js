import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import test, { after } from 'node:test';

import { resolveVerifiedExecutable } from '../../../src/core/executable.js';
import { Secret } from '../../../src/core/secrets.js';
import { ClaudeyError } from '../../../src/core/errors.js';
import { visibleModelId } from '../../../src/providers/catalog.js';
import { buildManagedOAuthAliases } from '../../../src/providers/oauth-aliases.js';
import * as claudeProvider from '../../../src/providers/claude.js';

const { launchClaudeProvider, runClaudeProcess } = claudeProvider;

function executableAdapter() {
  const tagged = (stats) => { if (stats.reparseTag === undefined) Object.defineProperty(stats, 'reparseTag', { value: 0 }); return stats; };
  return {
    realpath: async (value) => { try { return await fs.realpath(value); } catch (error) { if (error?.code === 'EPERM') return value; throw error; } },
    lstat: async (value) => tagged(await fs.lstat(value)),
    stat: async (value) => tagged(await fs.stat(value)),
    openNoFollow: async (value) => {
      const before = tagged(await fs.lstat(value));
      if (before.isSymbolicLink()) throw Object.assign(new Error('link'), { code: 'ELOOP' });
      const handle = await fs.open(value, 'r');
      return { ...handle, noFollow: true, read: handle.read.bind(handle), close: handle.close.bind(handle), stat: async () => tagged(await handle.stat()) };
    }
  };
}

const fixtureRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'claudey-claude-unit-'));
after(() => fs.rm(fixtureRoot, { recursive: true, force: true }));
const CLAUDE = await resolveVerifiedExecutable({ command: 'claude', platform: process.platform, candidates: [{ path: process.execPath }], adapter: executableAdapter() });
const FIXTURE_CWD = process.platform === 'win32' ? fixtureRoot : 'C:\\claudey-claude-unit';
const TOKEN_BYTES = Buffer.alloc(32, 17);
const TOKEN_TEXT = TOKEN_BYTES.toString('base64url');

function fixture(overrides = {}) {
  const calls = [];
  const models = [
    { id: 'zeta-live', object: 'model', created: 3, owned_by: 'codex' },
    { id: 'gpt-5.6-sol', object: 'model', created: 1, owned_by: 'codex' }
  ];
  return {
    calls,
    value: {
      provider: 'codex',
      parsed: { model: 'gpt-5.6-sol', select: false, claudeArgs: [], nonInteractive: false },
      claude: CLAUDE,
      cwd: FIXTURE_CWD,
      isTTY: true,
      baseEnvironment: {
        PATH: 'safe-path', SystemRoot: 'C:\\Windows', HOME: 'C:\\Users\\person', TERM: 'xterm',
        ANTHROPIC_BASE_URL: 'http://hostile', ANTHROPIC_AUTH_TOKEN: 'hostile-token', ANTHROPIC_API_KEY: 'hostile-key',
        ANTHROPIC_MODEL: 'hostile-model', ANTHROPIC_DEFAULT_OPUS_MODEL: 'hostile-opus',
        OPENAI_API_KEY: 'secret-canary', AWS_SECRET_ACCESS_KEY: 'secret-canary', OTEL_EXPORTER_OTLP_HEADERS: 'secret-canary'
      },
      ensureGateway: async () => {
        calls.push('gateway');
        return { host: '127.0.0.1', port: 8317, token: Secret.fromBytes(TOKEN_BYTES) };
      },
      listModels: async (provider) => { calls.push(`models:${provider}`); return { provider, status: 'available', models }; },
      selectModel: async (request) => { calls.push({ select: request }); return request.models[0].id; },
      runChild: async (invocation) => { calls.push({ invocation }); return { code: 0, signal: null }; },
      syncOAuthAliases: async () => ({ synced: true, oauthModelAlias: {} }),
      waitForAliasReady: async () => true,
      ...overrides
    }
  };
}

test('verifies Claude, ensures the gateway, validates a current exact provider model, and spawns fixed discrete argv', async () => {
  let running = false;
  const f = fixture({
    parsed: { model: 'gpt-5.6-sol', select: false, claudeArgs: ['--print', 'hello world'], nonInteractive: true },
    selectModel: undefined,
    ensureGateway: async () => {
      if (!running) { f.calls.push('start-if-needed'); running = true; }
      f.calls.push('gateway');
      return { host: '127.0.0.1', port: 8317, token: Secret.fromBytes(TOKEN_BYTES) };
    }
  });
  const result = await launchClaudeProvider(f.value);
  assert.deepEqual(result, { provider: 'codex', model: 'gpt-5.6-sol', exitCode: 0, signal: null });
  assert.deepEqual(f.calls.slice(0, 3), ['start-if-needed', 'gateway', 'models:codex']);
  const invocation = f.calls[3].invocation;
  assert.deepEqual(invocation.args.slice(-6), ['--model', 'gpt-5.6-sol', '--fallback-model', 'gpt-5.6-sol', '--print', 'hello world']);
  assert.equal(invocation.shell, false);
  assert.equal(invocation.stdio, 'inherit');
  assert.equal(invocation.cwd, FIXTURE_CWD);
});

test('uses a live interactive selector, offers the preferred source model first only when present, and revalidates its exact result', async () => {
  const f = fixture({ parsed: { model: undefined, select: true, claudeArgs: [], nonInteractive: false } });
  const result = await launchClaudeProvider(f.value);
  assert.equal(result.model, 'gpt-5.6-sol');
  assert.deepEqual(f.calls[2].select.models.map(({ id }) => id), ['gpt-5.6-sol', 'zeta-live']);

  const hostile = fixture({
    parsed: { model: undefined, select: true, claudeArgs: [], nonInteractive: false },
    selectModel: async () => 'not-in-live-list'
  });
  await assert.rejects(launchClaudeProvider(hostile.value), (error) => error.code === 'MODEL_NOT_FOUND');
  assert.equal(hostile.calls.some((call) => call?.invocation), false);
});

test('single-provider launch normalizes a managed visible catalog alias to its raw upstream model', async () => {
  const f = fixture({
    listModels: async (provider) => ({
      provider,
      status: 'available',
      models: [{
        id: visibleModelId('codex', 'gpt-5.6-sol'),
        object: 'model',
        created: 1,
        owned_by: 'codex'
      }]
    })
  });

  const result = await launchClaudeProvider(f.value);

  assert.equal(result.model, 'gpt-5.6-sol');
  assert.deepEqual(
    f.calls.at(-1).invocation.args.slice(-4),
    ['--model', 'gpt-5.6-sol', '--fallback-model', 'gpt-5.6-sol']
  );
});

test('requires an explicit model in noninteractive mode and refuses noninteractive selection before any side effect', async () => {
  for (const parsed of [
    { model: undefined, select: false, claudeArgs: [], nonInteractive: true },
    { model: undefined, select: true, claudeArgs: [], nonInteractive: true }
  ]) {
    const f = fixture({ parsed });
    await assert.rejects(launchClaudeProvider(f.value), (error) => error.code === (parsed.select ? 'INTERACTION_REQUIRED' : 'MODEL_REQUIRED'));
    assert.deepEqual(f.calls, []);
  }
});

test('rejects unknown models and every forwarded model override before Claude spawn without provider fallback', async () => {
  const forwarded = [
    ['--model', 'other'], ['--model=other'], ['-m', 'other'], ['-m=other'], ['--MODEL', 'other'],
    ['--fallback-model', 'other'], ['--fallback-model=other'], ['--FALLBACK-MODEL', 'other']
  ];
  for (const claudeArgs of forwarded) {
    const f = fixture({ parsed: { model: 'gpt-5.6-sol', select: false, claudeArgs, nonInteractive: false } });
    await assert.rejects(launchClaudeProvider(f.value), (error) => error.code === 'USAGE_ERROR');
    assert.deepEqual(f.calls, []);
  }
  const missing = fixture({ parsed: { model: 'agy-only', select: false, claudeArgs: [], nonInteractive: false } });
  await assert.rejects(launchClaudeProvider(missing.value), (error) => error.code === 'MODEL_NOT_FOUND' && error.details.provider === 'codex');
  assert.equal(missing.calls.some((call) => call?.invocation), false);
});

test('preserves hostile Claude arguments byte-for-byte as discrete values after the authoritative model', async () => {
  const hostile = ['', 'space value', 'üñïçødé', '"quoted"', 'slash\\', '-leading', ';', '&', '|', '`echo`', '$(echo)', '%VAR%', 'line\rreturn', 'line\nfeed'];
  const f = fixture({ parsed: { model: 'gpt-5.6-sol', select: false, claudeArgs: hostile, nonInteractive: false } });
  await launchClaudeProvider(f.value);
  assert.deepEqual(f.calls.at(-1).invocation.args.slice(-hostile.length), hostile);
});

test('constructs only an internal child-scoped routing environment and leaves the parent object byte-for-byte unchanged', async () => {
  const f = fixture();
  const source = f.value.baseEnvironment;
  const before = JSON.stringify(source);
  let env;
  const result = await launchClaudeProvider({
    ...f.value,
    runChild: async (invocation) => { env = { ...invocation.env }; return { code: 0, signal: null }; }
  });
  assert.deepEqual(env, {
    PATH: 'safe-path', SystemRoot: 'C:\\Windows', HOME: 'C:\\Users\\person', TERM: 'xterm',
    ANTHROPIC_BASE_URL: 'http://127.0.0.1:8317',
    ANTHROPIC_AUTH_TOKEN: TOKEN_TEXT,
    ANTHROPIC_MODEL: 'gpt-5.6-sol',
    ANTHROPIC_DEFAULT_HAIKU_MODEL: 'gpt-5.6-sol',
    ANTHROPIC_DEFAULT_SONNET_MODEL: 'gpt-5.6-sol',
    ANTHROPIC_DEFAULT_OPUS_MODEL: 'gpt-5.6-sol',
    ANTHROPIC_DEFAULT_FABLE_MODEL: 'gpt-5.6-sol',
    ANTHROPIC_DEFAULT_HAIKU_MODEL_NAME: 'gpt-5.6-sol',
    ANTHROPIC_DEFAULT_SONNET_MODEL_NAME: 'gpt-5.6-sol',
    ANTHROPIC_DEFAULT_OPUS_MODEL_NAME: 'gpt-5.6-sol',
    ANTHROPIC_DEFAULT_FABLE_MODEL_NAME: 'gpt-5.6-sol',
    ANTHROPIC_CUSTOM_MODEL_OPTION: 'gpt-5.6-sol',
    ANTHROPIC_CUSTOM_MODEL_OPTION_NAME: 'gpt-5.6-sol',
    CLAUDE_CODE_SUBAGENT_MODEL: 'gpt-5.6-sol',
    CLAUDE_CODE_ALWAYS_ENABLE_EFFORT: '1',
    CLAUDE_CODE_MAX_TOOL_USE_CONCURRENCY: '3',
    CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: '1',
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1',
    ENABLE_TOOL_SEARCH: 'false'
  });
  assert.equal(JSON.stringify(source), before);
  assert.equal(JSON.stringify(env).includes('secret-canary'), false);
  assert.equal(Object.hasOwn(env, 'ANTHROPIC_API_KEY'), false);
  assert.equal(env.ANTHROPIC_MODEL, 'gpt-5.6-sol');
  assert.equal(env.ANTHROPIC_DEFAULT_OPUS_MODEL, 'gpt-5.6-sol');
  assert.deepEqual(result, { provider: 'codex', model: 'gpt-5.6-sol', exitCode: 0, signal: null });
  assert.deepEqual(Object.keys(claudeProvider).sort(), ['launchClaudeProvider', 'runClaudeProcess']);
});

test('mixed --all session accepts a live model from any authenticated provider and maps picker aliases', async () => {
  const announcements = [];
  const sessionSettingsDir = path.join(fixtureRoot, 'claude-session');
  const f = fixture({
    parsed: { model: 'grok-4.5', select: false, all: true, claudeArgs: [], nonInteractive: true },
    sessionSettingsDir,
    listModels: async (name) => {
      if (name === 'codex') {
        return { provider: name, status: 'available', models: [
          { id: 'gpt-5.6-sol', object: 'model', created: 1, owned_by: 'codex' }
        ] };
      }
      if (name === 'antigravity') {
        return { provider: name, status: 'available', models: [
          { id: 'gemini-3-flash', object: 'model', created: 2, owned_by: 'antigravity' }
        ] };
      }
      return { provider: name, status: 'available', models: [
        { id: 'grok-4.5', object: 'model', created: 3, owned_by: 'grok' }
      ] };
    }
  });
  let env;
  let invocation;
  const result = await launchClaudeProvider({
    ...f.value,
    announce: (text) => announcements.push(text),
    runChild: async (request) => { invocation = request; env = { ...request.env }; return { code: 0, signal: null }; }
  });
  assert.deepEqual(result, { provider: 'grok', model: 'grok-4.5', exitCode: 0, signal: null });
  assert.equal(Object.hasOwn(env, 'ANTHROPIC_DEFAULT_HAIKU_MODEL'), false);
  assert.equal(Object.hasOwn(env, 'ANTHROPIC_CUSTOM_MODEL_OPTION'), false);
  assert.equal(Object.hasOwn(env, 'CLAUDE_CODE_SUBAGENT_MODEL'), false);
  assert.equal(env.CLAUDE_CONFIG_DIR, sessionSettingsDir);
  const visible = visibleModelId('grok', 'grok-4.5');
  assert.equal(env.ANTHROPIC_MODEL, visible);
  assert.match(env.ANTHROPIC_BASE_URL, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.notEqual(env.ANTHROPIC_BASE_URL, 'http://127.0.0.1:8317');
  assert.equal(env.CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY, '1');
  assert.equal(Object.hasOwn(env, 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC'), false);
  assert.deepEqual(invocation.args.slice(-4), ['--model', visible, '--fallback-model', visible]);
  const settings = JSON.parse(await fs.readFile(path.join(sessionSettingsDir, 'settings.json'), 'utf8'));
  assert.equal(settings.model, visible);
  assert.equal(Object.hasOwn(settings, 'availableModels'), false);
  assert.equal(settings.env.CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY, '1');
  assert.match(announcements.join('\n'), /\/model/);
  assert.match(announcements.join('\n'), /grok-4.5/);
});

test('mixed session keeps duplicate raw model IDs from different providers', async () => {
  const announced = [];
  const startPicker = async ({ models }) => {
    assert.equal(models.filter((model) => model.id === 'gpt-5.6-sol').length, 2);
    assert.deepEqual(
      models.filter((model) => model.id === 'gpt-5.6-sol').map((model) => model.owned_by).sort(),
      ['antigravity', 'codex']
    );
    return {
      host: '127.0.0.1',
      port: 19_001,
      close: async () => {}
    };
  };
  const f = fixture({
    parsed: {
      model: visibleModelId('antigravity', 'gpt-5.6-sol'),
      select: false,
      all: true,
      claudeArgs: [],
      nonInteractive: true
    },
    listModels: async (name) => {
      if (name === 'codex') {
        return { provider: name, status: 'available', models: [
          { id: 'gpt-5.6-sol', object: 'model', created: 1, owned_by: 'codex' }
        ] };
      }
      if (name === 'antigravity') {
        return { provider: name, status: 'available', models: [
          { id: 'gpt-5.6-sol', object: 'model', created: 2, owned_by: 'antigravity' }
        ] };
      }
      return { provider: name, status: 'available', models: [
        { id: 'grok-4.5', object: 'model', created: 3, owned_by: 'grok' }
      ] };
    },
    startPicker,
    announce: (text) => announced.push(text),
    syncOAuthAliases: async () => ({ synced: true, oauthModelAlias: {} }),
    waitForAliasReady: async () => true
  });

  const result = await launchClaudeProvider(f.value);

  assert.equal(result.provider, 'antigravity');
  assert.deepEqual(
    f.calls.at(-1).invocation.args.slice(-4),
    ['--model', visibleModelId('antigravity', 'gpt-5.6-sol'), '--fallback-model', visibleModelId('antigravity', 'gpt-5.6-sol')]
  );
  assert.match(announced.join('\n'), /gpt-5\.6-sol — Codex/u);
  assert.match(announced.join('\n'), /gpt-5\.6-sol — Antigravity/u);
});

test('mixed launch normalizes managed visible aliases before labels, alias sync, and picker consumption', async () => {
  const codexVisible = visibleModelId('codex', 'gpt-5.6-sol');
  let pickerModelsSeen;
  let aliasesSeen;
  const f = fixture({
    parsed: { model: codexVisible, select: false, all: true, claudeArgs: [], nonInteractive: true },
    listModels: async (name) => ({
      provider: name,
      status: 'available',
      models: name === 'codex' ? [{
        id: codexVisible,
        object: 'model',
        created: 1,
        owned_by: 'codex'
      }] : []
    }),
    syncOAuthAliases: async ({ models }) => {
      aliasesSeen = buildManagedOAuthAliases(models);
      return { synced: true, oauthModelAlias: aliasesSeen };
    },
    waitForAliasReady: async () => true,
    startPicker: async ({ models }) => {
      pickerModelsSeen = models;
      return { host: '127.0.0.1', port: 19_005, close: async () => {} };
    }
  });

  const result = await launchClaudeProvider(f.value);

  assert.deepEqual(pickerModelsSeen.map(({ id, owned_by }) => ({ id, owned_by })), [
    { id: 'gpt-5.6-sol', owned_by: 'codex' }
  ]);
  assert.deepEqual(aliasesSeen.codex[0], {
    name: 'gpt-5.6-sol',
    alias: codexVisible,
    displayName: 'gpt-5.6-sol — Codex',
    forceMapping: true
  });
  assert.deepEqual(result, { provider: 'codex', model: 'gpt-5.6-sol', exitCode: 0, signal: null });
});

test('mixed interactive selector qualifies duplicate IDs so either provider can be selected', async () => {
  const listModels = async (name) => ({
    provider: name,
    status: 'available',
    models: name === 'grok' ? [] : [
      { id: 'shared-model', object: 'model', created: name === 'codex' ? 1 : 2, owned_by: name }
    ]
  });

  for (const expectedProvider of ['codex', 'antigravity']) {
    const selectedId = visibleModelId(expectedProvider, 'shared-model');
    const f = fixture({
      parsed: { model: undefined, select: true, all: true, claudeArgs: [], nonInteractive: false },
      listModels,
      selectModel: async ({ models }) => {
        assert.deepEqual(
          models.map(({ id }) => id).sort(),
          [
            visibleModelId('antigravity', 'shared-model'),
            visibleModelId('codex', 'shared-model')
          ].sort()
        );
        return selectedId;
      },
      syncOAuthAliases: async () => ({ synced: true, oauthModelAlias: {} }),
      waitForAliasReady: async () => true,
      startPicker: async () => ({ host: '127.0.0.1', port: 19_004, close: async () => {} })
    });

    const result = await launchClaudeProvider(f.value);
    assert.equal(result.provider, expectedProvider);
    assert.deepEqual(
      f.calls.at(-1).invocation.args.slice(-4),
      ['--model', selectedId, '--fallback-model', selectedId]
    );
  }
});

test('mixed launch syncs oauth aliases before starting the picker', async () => {
  const events = [];
  const f = fixture({
    parsed: {
      model: visibleModelId('codex', 'gpt-5.6-sol'),
      select: false,
      all: true,
      claudeArgs: [],
      nonInteractive: true
    },
    listModels: async (name) => ({
      provider: name,
      status: 'available',
      models: name === 'codex'
        ? [{ id: 'gpt-5.6-sol', object: 'model', created: 1, owned_by: 'codex' }]
        : []
    }),
    syncOAuthAliases: async ({ models }) => {
      events.push(['sync', models.map((model) => `${model.owned_by}:${model.id}`)]);
      return { synced: true, oauthModelAlias: { codex: [{ alias: visibleModelId('codex', 'gpt-5.6-sol') }] } };
    },
    waitForAliasReady: async ({ aliases }) => {
      events.push(['wait', aliases]);
      return true;
    },
    startPicker: async () => {
      events.push(['picker']);
      return { host: '127.0.0.1', port: 19_002, close: async () => {} };
    }
  });

  await launchClaudeProvider(f.value);

  assert.deepEqual(events, [
    ['sync', ['codex:gpt-5.6-sol']],
    ['wait', { codex: [{ alias: visibleModelId('codex', 'gpt-5.6-sol') }] }],
    ['picker']
  ]);
});

test('mixed --model rejects ambiguous raw IDs and accepts unique raw IDs', async () => {
  const listModels = async (name) => {
    if (name === 'codex') {
      return { provider: name, status: 'available', models: [
        { id: 'shared-model', object: 'model', created: 1, owned_by: 'codex' },
        { id: 'only-codex', object: 'model', created: 2, owned_by: 'codex' }
      ] };
    }
    if (name === 'antigravity') {
      return { provider: name, status: 'available', models: [
        { id: 'shared-model', object: 'model', created: 3, owned_by: 'antigravity' }
      ] };
    }
    return { provider: name, status: 'available', models: [] };
  };

  await assert.rejects(
    () => launchClaudeProvider(fixture({
      parsed: { model: 'shared-model', select: false, all: true, claudeArgs: [], nonInteractive: true },
      listModels,
      syncOAuthAliases: async () => ({ synced: true, oauthModelAlias: {} }),
      waitForAliasReady: async () => true
    }).value),
    (error) => error.code === 'MODEL_AMBIGUOUS'
  );

  const unique = fixture({
    parsed: { model: 'only-codex', select: false, all: true, claudeArgs: [], nonInteractive: true },
    listModels,
    syncOAuthAliases: async () => ({ synced: true, oauthModelAlias: {} }),
    waitForAliasReady: async () => true,
    startPicker: async () => ({ host: '127.0.0.1', port: 19_003, close: async () => {} })
  });
  const result = await launchClaudeProvider(unique.value);
  assert.equal(result.provider, 'codex');
  assert.equal(result.model, 'only-codex');
});

test('mixed launch fails closed when alias readiness never arrives', async () => {
  const f = fixture({
    parsed: {
      model: visibleModelId('codex', 'gpt-5.6-sol'),
      select: false,
      all: true,
      claudeArgs: [],
      nonInteractive: true
    },
    listModels: async (name) => ({
      provider: name,
      status: 'available',
      models: name === 'codex'
        ? [{ id: 'gpt-5.6-sol', object: 'model', created: 1, owned_by: 'codex' }]
        : []
    }),
    syncOAuthAliases: async () => ({ synced: true, oauthModelAlias: {} }),
    waitForAliasReady: async () => false,
    startPicker: async () => {
      throw new Error('picker must not start');
    }
  });

  await assert.rejects(
    launchClaudeProvider(f.value),
    (error) => error.code === 'GATEWAY_UNHEALTHY'
  );
});

test('mixed --all session accepts a cloaked Anthropic id and keeps Claude-written session theme', async () => {
  const sessionSettingsDir = path.join(fixtureRoot, 'claude-session-theme');
  await fs.mkdir(sessionSettingsDir, { recursive: true });
  await fs.writeFile(path.join(sessionSettingsDir, 'settings.json'), `${JSON.stringify({
    model: 'gpt-5.3-codex-spark',
    availableModels: ['grok-4.5', 'gpt-5.3-codex-spark'],
    enforceAvailableModels: true,
    theme: 'light'
  }, null, 2)}\n`);
  const f = fixture({
    parsed: { model: visibleModelId('grok', 'grok-4.5'), select: false, all: true, claudeArgs: [], nonInteractive: true },
    sessionSettingsDir,
    listModels: async (name) => {
      if (name === 'codex') {
        return { provider: name, status: 'available', models: [
          { id: 'gpt-5.6-sol', object: 'model', created: 1, owned_by: 'codex' }
        ] };
      }
      if (name === 'antigravity') {
        return { provider: name, status: 'available', models: [
          { id: 'gemini-3-flash', object: 'model', created: 2, owned_by: 'antigravity' }
        ] };
      }
      return { provider: name, status: 'available', models: [
        { id: 'grok-4.5', object: 'model', created: 3, owned_by: 'grok' }
      ] };
    }
  });
  const result = await launchClaudeProvider({
    ...f.value,
    runChild: async () => ({ code: 0, signal: null })
  });
  assert.deepEqual(result, { provider: 'grok', model: 'grok-4.5', exitCode: 0, signal: null });
  const settings = JSON.parse(await fs.readFile(path.join(sessionSettingsDir, 'settings.json'), 'utf8'));
  assert.equal(settings.theme, 'light');
  assert.equal(settings.model, visibleModelId('grok', 'grok-4.5'));
  assert.equal(Object.hasOwn(settings, 'availableModels'), false);
});

test('sanitizes lifecycle and model-service diagnostics while preserving only stable public error classes', async () => {
  for (const overrides of [
    { ensureGateway: async () => { throw new ClaudeyError('GATEWAY_UNHEALTHY', 'lifecycle secret-canary'); } },
    { ensureGateway: async () => { throw new ClaudeyError('PORT_IN_USE', 'listener secret-canary', { details: { private: 'secret-canary' } }); } },
    { listModels: async () => { throw new ClaudeyError('AUTH_REQUIRED', 'catalog secret-canary'); } },
    { listModels: async () => { throw new ClaudeyError('PROCESS_IDENTITY_MISMATCH', 'identity secret-canary'); } }
  ]) {
    const f = fixture(overrides);
    await assert.rejects(launchClaudeProvider(f.value), (error) => ['GATEWAY_UNHEALTHY', 'PORT_IN_USE', 'AUTH_REQUIRED', 'PROCESS_IDENTITY_MISMATCH'].includes(error.code)
      && !error.message.includes('secret-canary') && !JSON.stringify(error.details).includes('secret-canary'));
  }
});

test('preserves the stable not-installed remediation and fails closed on hostile diagnostic accessors', async () => {
  const missing = fixture({
    ensureGateway: async () => { throw new ClaudeyError('NOT_INSTALLED', 'install path secret-canary'); }
  });
  await assert.rejects(launchClaudeProvider(missing.value), (error) => error.code === 'NOT_INSTALLED'
    && error.hint === 'Run claudey setup.' && !error.message.includes('secret-canary'));

  const hostile = fixture({
    ensureGateway: async () => { throw new Proxy({}, { get: () => { throw new Error('diagnostic secret-canary'); } }); }
  });
  await assert.rejects(launchClaudeProvider(hostile.value), (error) => error.code === 'GATEWAY_UNHEALTHY'
    && !error.message.includes('secret-canary'));
});

test('rejects option-shaped live model identifiers before Claude spawn', async () => {
  const f = fixture({
    parsed: { model: '--danger', select: false, claudeArgs: [], nonInteractive: false },
    listModels: async () => ({
      provider: 'codex', status: 'available',
      models: [{ id: '--danger', object: 'model', created: 1, owned_by: 'codex' }]
    })
  });
  await assert.rejects(launchClaudeProvider(f.value), (error) => error.code === 'USAGE_ERROR');
  assert.deepEqual(f.calls, []);
});

test('fails closed for forged/stale Claude identity, malformed gateway, token, model, cwd, or child result without leaking diagnostics', async () => {
  const forged = Object.freeze({ ...CLAUDE });
  const cases = [
    { claude: forged },
    { ensureGateway: async () => ({ host: 'localhost', port: 8317, token: Secret.fromBytes(TOKEN_BYTES) }) },
    { ensureGateway: async () => ({ host: '127.0.0.1', port: 80, token: Secret.fromBytes(TOKEN_BYTES) }) },
    { ensureGateway: async () => ({ host: '127.0.0.1', port: 8317, token: 'plain' }) },
    { cwd: 'relative' },
    { baseEnvironment: new Proxy({}, { ownKeys: () => { throw new Error('environment secret-canary'); } }) },
    { runChild: async () => ({ code: 0 }) },
    { runChild: async () => new Proxy({}, { get: () => { throw new Error('result secret-canary'); } }) },
    { runChild: async () => { throw new Error('private secret-canary'); } }
  ];
  for (const overrides of cases) {
    const f = fixture(overrides);
    await assert.rejects(launchClaudeProvider(f.value), (error) => ['PREREQUISITE_MISSING', 'GATEWAY_UNHEALTHY', 'SAFETY_REFUSAL'].includes(error.code)
      && !error.message.includes('secret-canary'));
  }
});

test('process runner inherits stdio, relays signals, scrubs its mutable token environment, and returns exact termination', async () => {
  const parent = new EventEmitter();
  const child = new EventEmitter();
  child.kill = (signal) => { child.signal = signal; return true; };
  const env = { ANTHROPIC_AUTH_TOKEN: TOKEN_TEXT, PATH: 'safe' };
  const spawns = [];
  let rawSpawnEnvironment;
  const operation = runClaudeProcess({ executablePath: process.execPath, args: ['x'], cwd: fixtureRoot, env, shell: false, stdio: 'inherit' }, {
    parent,
    spawnProcess: (file, args, options) => {
      rawSpawnEnvironment = options.env;
      spawns.push({ file, args, options: { ...options, env: { ...options.env } } });
      queueMicrotask(() => parent.emit('SIGINT'));
      queueMicrotask(() => child.emit('exit', null, 'SIGINT'));
      return child;
    }
  });
  const result = await operation;
  assert.deepEqual(result, { code: null, signal: 'SIGINT' });
  assert.equal(child.signal, 'SIGINT');
  assert.equal(Object.hasOwn(env, 'ANTHROPIC_AUTH_TOKEN'), false);
  assert.equal(spawns[0].options.env.ANTHROPIC_AUTH_TOKEN, TOKEN_TEXT);
  assert.equal(Object.hasOwn(rawSpawnEnvironment, 'ANTHROPIC_AUTH_TOKEN'), false);
  assert.equal(parent.listenerCount('SIGINT'), 0);
  assert.equal(parent.listenerCount('SIGTERM'), 0);
});
