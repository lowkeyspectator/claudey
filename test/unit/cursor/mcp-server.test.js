import assert from 'node:assert/strict';
import { PassThrough, Writable } from 'node:stream';
import test from 'node:test';

import { ClaudexError } from '../../../src/core/errors.js';
import { probeCursorCapabilities } from '../../../src/cursor/capabilities.js';
import { resolveCursorAgentExecutable } from '../../../src/cursor/executable.js';
import {
  assertCursorMcpEnvironment, createCursorMcpServer, serveCursorMcpStdio
} from '../../../src/cursor/mcp-server.js';

const TARGET = Object.freeze({ name: 'verified-cursor' });
const BINDING = await resolveCursorAgentExecutable({
  candidates: [{ command: 'cursor-agent', source: 'path', target: TARGET }],
  verifyTarget: async ({ target }) => target,
  verifyVersion: async () => true
});
const ENVIRONMENT = Object.freeze({ CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: '1', PATH: '/usr/bin' });

async function capabilities() {
  return probeCursorCapabilities(BINDING, {
    nonceFactory: () => 'mcp-server-nonce',
    invoke: async (request) => {
      const values = {
        '--version': 'Cursor Agent 1.0.0\n',
        'status --json': '{"authenticated":true}\n',
        'models --json': '{"models":[{"id":"cursor-a"}]}\n',
        'probe json --json': '{"type":"probe","capability":"json","framing":"json-lines"}\n',
        'probe stdin --json': `${JSON.stringify({ type: 'probe', capability: 'stdin', echo: request.stdin })}\n`,
        'probe mode ask --json': '{"type":"probe","capability":"ask","supported":true}\n',
        'probe mode plan --json': '{"type":"probe","capability":"plan","supported":true}\n',
        'probe mode worktree --json': '{"type":"probe","capability":"worktree","supported":true}\n',
        'probe sandbox read-only --json': '{"type":"probe","capability":"sandbox","supported":true}\n'
      };
      const value = values[request.args.join(' ')];
      return { code: value === undefined ? 2 : 0, stdout: value ?? '', stderr: '' };
    }
  });
}

async function fixture({ executeTool, revalidateStartup = async () => true } = {}) {
  const calls = [];
  const server = createCursorMcpServer({
    environment: ENVIRONMENT, capabilities: await capabilities(), writesEnabled: true, worktreeSafetyReady: true,
    revalidateStartup: async () => { calls.push(['revalidate']); return revalidateStartup(); },
    executeTool: executeTool ?? (async ({ name, arguments: args, signal }) => {
      calls.push(['tool', name, args, signal]);
      return { name, received: args };
    })
  });
  return { server, calls };
}

const initialize = (id = 1) => ({ jsonrpc: '2.0', id, method: 'initialize', params: {
  protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'fixture', version: '1.0.0' }
} });
const initialized = { jsonrpc: '2.0', method: 'notifications/initialized' };

test('startup requires the scrub contract and explicit absence of provider, gateway, Cursor, and Claude session secrets', () => {
  assert.deepEqual(assertCursorMcpEnvironment(ENVIRONMENT), { scrubbed: true });
  const names = [
    'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GOOGLE_API_KEY',
    'GOOGLE_APPLICATION_CREDENTIALS', 'GITHUB_TOKEN', 'GH_TOKEN', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
    'AZURE_CLIENT_SECRET', 'CURSOR_API_KEY', 'CLAUDE_SESSION_ID', 'CLAUDE_CODE_OAUTH_TOKEN',
    'CLIPROXY_API_TOKEN', 'CLIPROXY_AUTH_DIR', 'CLIPROXYAPI_TOKEN', 'CLI_PROXY_API_TOKEN'
  ];
  for (const name of names) {
    assert.throws(() => assertCursorMcpEnvironment({ ...ENVIRONMENT, [name]: 'private-canary' }),
      (error) => error.code === 'SAFETY_REFUSAL', name);
  }
  assert.throws(() => assertCursorMcpEnvironment({ PATH: '/usr/bin' }),
    (error) => error.code === 'SAFETY_REFUSAL');
  assert.throws(() => assertCursorMcpEnvironment({ ...ENVIRONMENT, CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: 'true' }),
    (error) => error.code === 'SAFETY_REFUSAL');
});

test('implements initialized JSON-RPC lifecycle and revalidates startup identity before dynamic tools/list', async () => {
  const f = await fixture();
  assert.deepEqual(await f.server.handle(initialize()), {
    jsonrpc: '2.0', id: 1, result: {
      protocolVersion: '2025-11-25', capabilities: { tools: { listChanged: false } },
      serverInfo: { name: 'claudey-cursor', version: '1.0.0' }
    }
  });
  assert.equal(await f.server.handle(initialized), null);
  const listed = await f.server.handle({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  assert.deepEqual(listed.result.tools.map(({ name }) => name),
    ['cursor_models', 'cursor_ask', 'cursor_plan', 'cursor_worktree_run']);
  assert.deepEqual(f.calls, [['revalidate']]);
  assert.deepEqual(await f.server.handle({ jsonrpc: '2.0', id: 9, method: 'ping', extra: true }), {
    jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' }
  });

  const denied = await fixture({ revalidateStartup: async () => false });
  await denied.server.handle(initialize());
  await denied.server.handle(initialized);
  assert.deepEqual(await denied.server.handle({ jsonrpc: '2.0', id: 3, method: 'tools/list' }), {
    jsonrpc: '2.0', id: 3, error: { code: -32603, message: 'Cursor MCP startup identity is unsafe.' }
  });
});

test('validates exact advertised tool calls and returns content plus structuredContent with stable sanitized project errors', async () => {
  const f = await fixture({ executeTool: async ({ name, arguments: args, signal }) => {
    f.calls.push(['tool', name, args, signal]);
    if (args.prompt === 'fail') throw new ClaudexError('MODEL_NOT_FOUND', 'private diagnostic canary');
    return { tool: name, value: args.prompt ?? 'models' };
  } });
  await f.server.handle(initialize());
  await f.server.handle(initialized);
  const called = await f.server.handle({ jsonrpc: '2.0', id: 'call-1', method: 'tools/call', params: {
    name: 'cursor_ask', arguments: { prompt: 'private prompt', model: 'cursor-a' }
  } });
  assert.deepEqual(called, { jsonrpc: '2.0', id: 'call-1', result: {
    content: [{ type: 'text', text: '{"ok":true,"value":{"tool":"cursor_ask","value":"private prompt"}}' }],
    structuredContent: { ok: true, value: { tool: 'cursor_ask', value: 'private prompt' } }
  } });
  assert.equal(Object.hasOwn(f.calls.find(([kind]) => kind === 'tool')[2], 'argv'), false);

  const failed = await f.server.handle({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: {
    name: 'cursor_plan', arguments: { prompt: 'fail' }
  } });
  assert.equal(failed.result.isError, true);
  assert.equal(failed.result.structuredContent.error.code, 'MODEL_NOT_FOUND');
  assert.equal(JSON.stringify(failed).includes('private diagnostic canary'), false);

  for (const [id, params] of [
    [5, { name: 'unknown', arguments: {} }],
    [6, { name: 'cursor_ask', arguments: { prompt: 'x', executable: 'evil' } }],
    [7, { name: 'cursor_models', arguments: {}, extra: true }]
  ]) {
    const response = await f.server.handle({ jsonrpc: '2.0', id, method: 'tools/call', params });
    assert.equal(response.error.code, -32602);
  }
});

test('newline stdio framing emits one bounded response per request, handles parse/method errors, and cancels active calls', async () => {
  let started;
  const startedPromise = new Promise((resolve) => { started = resolve; });
  const f = await fixture({ executeTool: async ({ signal }) => new Promise((resolve, reject) => {
    started();
    signal.addEventListener('abort', () => reject(new Error('private abort canary')), { once: true });
  }) });
  const input = new PassThrough();
  let outputText = '';
  const output = new Writable({ write(chunk, encoding, callback) { outputText += chunk.toString('utf8'); callback(); } });
  const serving = serveCursorMcpStdio({ server: f.server, input, output, maxRequestBytes: 512, maxOutputBytes: 1_048_576 });
  input.write(`${JSON.stringify(initialize())}\n${JSON.stringify(initialized)}\n`);
  input.write('{bad json}\n');
  input.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'unknown' })}\n`);
  input.write(`${JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: {
    name: 'cursor_ask', arguments: { prompt: 'wait' }
  } })}\n`);
  await startedPromise;
  input.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 3 } })}\n`);
  input.write(`${JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'tools/list', params: { padding: 'x'.repeat(600) } })}\n`);
  input.end();
  await serving;

  const responses = outputText.trimEnd().split('\n').map((line) => JSON.parse(line));
  assert.equal(responses.filter(({ id }) => id === 1).length, 1);
  assert.equal(responses.filter(({ id }) => id === 2).length, 1);
  assert.equal(responses.filter(({ id }) => id === 3).length, 1);
  assert.equal(responses.filter(({ id }) => id === null).length, 2);
  assert.equal(responses.find(({ id }) => id === 2).error.code, -32601);
  assert.equal(responses.find(({ id }) => id === 3).error.code, -32800);
  assert.deepEqual(responses.filter(({ id }) => id === null).map(({ error }) => error.code), [-32700, -32700]);
  assert.equal(outputText.includes('private abort canary'), false);
});

test('output overflow and deterministic shutdown fail closed without duplicate responses', async () => {
  const f = await fixture({ executeTool: async () => ({ text: 'x'.repeat(10_000) }) });
  const input = new PassThrough();
  let outputText = '';
  const output = new Writable({ write(chunk, encoding, callback) { outputText += chunk.toString(); callback(); } });
  const serving = serveCursorMcpStdio({ server: f.server, input, output, maxOutputBytes: 512 });
  input.write(`${JSON.stringify(initialize())}\n${JSON.stringify(initialized)}\n`);
  input.write(`${JSON.stringify({ jsonrpc: '2.0', id: 8, method: 'tools/call', params: {
    name: 'cursor_models', arguments: {}
  } })}\n`);
  input.end();
  await serving;
  const responses = outputText.trimEnd().split('\n').map((line) => JSON.parse(line));
  assert.equal(responses.filter(({ id }) => id === 8).length, 1);
  assert.deepEqual(responses.find(({ id }) => id === 8).error,
    { code: -32603, message: 'Cursor MCP response exceeded its output limit.' });
  assert.deepEqual(await f.server.close(), { action: 'closed' });
  assert.deepEqual(await f.server.close(), { action: 'closed' });
});
