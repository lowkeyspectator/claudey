import assert from 'node:assert/strict';
import test from 'node:test';

import { main } from '../../src/cli/main.js';

test('wired router sends every public Cursor command and hidden MCP serve to the owned Cursor boundaries', async () => {
  const calls = [];
  const handler = (name) => async (request) => { calls.push([name, request]); return { operation: name }; };
  const container = { handlers: { cursor: handler('cursor'), cursorMcpServe: handler('mcp') },
    contexts: { cursor: { owner: 'cursor' }, cursorMcpServe: { owner: 'mcp' } } };
  const cases = [
    ['cursor', 'enable', '--scope', 'local'], ['cursor', 'disable', '--scope', 'user'],
    ['cursor', 'install', '--yes'], ['cursor', 'login'], ['cursor', 'repo', 'add'],
    ['cursor', 'repo', 'list'], ['cursor', 'repo', 'remove', '--yes'],
    ['cursor', 'writes', 'enable', '--yes'], ['cursor', 'writes', 'disable'],
    ['cursor', 'approve', 'a'.repeat(43)]
  ];
  for (const argv of cases) assert.deepEqual(await main(argv, {}, container), { operation: 'cursor' });
  assert.deepEqual(await main(['cursor', 'mcp-serve', '--installation-id',
    '11111111-1111-4111-8111-111111111111', '--manager-root', '/home/casey/.local/share/claudexctl'], {}, container),
  { operation: 'mcp' });
  assert.equal(calls.filter(([name]) => name === 'cursor').length, cases.length);
  assert.equal(calls.at(-1)[1].context.owner, 'mcp');
});

test('models cursor stays gateway-independent and models all reports every provider with partial success', async () => {
  const events = [];
  const container = { handlers: {
    models: async ({ command }) => {
      events.push(command.join(' '));
      if (command[1] === 'cursor') return { schemaVersion: 1, provider: 'cursor', status: 'available', models: ['cursor-a'] };
      if (command[1] === 'all') return { schemaVersion: 1, status: 'partial', providers: [
        { provider: 'codex', status: 'available', models: [{ id: 'codex-a' }] },
        { provider: 'antigravity', status: 'unavailable', code: 'AUTH_REQUIRED', models: [] },
        { provider: 'cursor', status: 'available', models: ['cursor-a'] }
      ] };
      throw new Error('unexpected');
    }
  }, contexts: { models: {} } };
  assert.equal((await main(['models', 'cursor'], {}, container)).provider, 'cursor');
  const all = await main(['models', 'all'], {}, container);
  assert.deepEqual(all.providers.map(({ provider }) => provider), ['codex', 'antigravity', 'cursor']);
  assert.deepEqual(events, ['models cursor', 'models all']);
});

test('default model router keeps Cursor-only gateway-free and joins all three live provider outcomes', async () => {
  const calls = [];
  const container = { contexts: { models: {
    gateway: { listOne: async (provider) => {
      calls.push(`gateway:${provider}`);
      if (provider === 'codex') return { provider, status: 'available', models: [{ id: 'codex-a' }] };
      const error = new Error('not authenticated'); error.code = 'AUTH_REQUIRED'; throw error;
    } },
    cursor: {
      verifyCursorPrerequisite: async () => { calls.push('cursor:verify'); return true; },
      listCursorModels: async () => { calls.push('cursor:models'); return { models: ['cursor-a'] }; }
    }
  } } };
  const cursor = await main(['models', 'cursor'], {}, container);
  assert.deepEqual(cursor, { schemaVersion: 1, provider: 'cursor', models: ['cursor-a'] });
  assert.deepEqual(calls, ['cursor:verify', 'cursor:models']);
  calls.length = 0;
  const all = await main(['models', 'all'], {}, container);
  assert.equal(all.schemaVersion, 1);
  assert.equal(all.status, 'partial');
  assert.deepEqual(all.providers.map(({ provider, status }) => ({ provider, status })), [
    { provider: 'codex', status: 'available' },
    { provider: 'antigravity', status: 'unavailable' },
    { provider: 'cursor', status: 'available' }
  ]);
  assert.deepEqual(calls, ['gateway:codex', 'gateway:antigravity', 'cursor:verify', 'cursor:models']);
});
