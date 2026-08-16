import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { runClaudeAgy } from '../../src/cli/launchers/claude-agy.js';
import { runClaudeGrok } from '../../src/cli/launchers/claude-grok.js';
import { runClaudeCodex, stageLaunchers } from '../../src/cli/launchers/claude-codex.js';
import { resolveVerifiedExecutable } from '../../src/core/executable.js';
import { requestGatewayModels } from '../../src/core/gateway-client.js';
import { Secret } from '../../src/core/secrets.js';
import { runClaudeProcess } from '../../src/providers/claude.js';
import { listProviderModels } from '../../src/providers/models.js';
import { startFakeGateway } from '../support/fake-gateway.js';

const TOKEN_BYTES = Buffer.alloc(32, 22);
const TOKEN_TEXT = TOKEN_BYTES.toString('base64url');

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

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudey-launcher-integration-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const entryDirectory = path.join(root, 'node_modules', '@anthropic-ai', 'claude-code');
  await fs.mkdir(entryDirectory, { recursive: true });
  await fs.copyFile(process.execPath, path.join(root, 'node.exe'));
  await fs.copyFile(fileURLToPath(new URL('../fixtures/bin/fake-claude.js', import.meta.url)), path.join(entryDirectory, 'cli.js'));
  const shim = path.join(root, 'claude.cmd');
  await fs.writeFile(shim, '@ECHO off\r\n"%~dp0\\node.exe" "%~dp0\\node_modules\\@anthropic-ai\\claude-code\\cli.js" %*\r\n');
  const claude = await resolveVerifiedExecutable({ command: 'claude', platform: 'win32', candidates: [{ path: shim }], adapter: executableAdapter() });
  const gateway = await startFakeGateway({ token: TOKEN_TEXT, catalog: { object: 'list', data: [
    { id: 'gpt-live', object: 'model', created: 2, owned_by: 'codex' },
    { id: 'agy-live', object: 'model', created: 3, owned_by: 'antigravity' },
    { id: 'grok-live', object: 'model', created: 4, owned_by: 'xai' }
  ] } });
  t.after(() => gateway.close());
  const context = {
    claude,
    cwd: root,
    isTTY: true,
    baseEnvironment: {
      PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, HOME: root, TERM: 'xterm',
      ANTHROPIC_BASE_URL: 'http://hostile', ANTHROPIC_AUTH_TOKEN: 'hostile', ANTHROPIC_API_KEY: 'launcher-secret-canary',
      OPENAI_API_KEY: 'launcher-secret-canary', OTEL_EXPORTER_OTLP_HEADERS: 'launcher-secret-canary'
    },
    ensureGateway: async () => ({ host: gateway.host, port: gateway.port, token: Secret.fromBytes(TOKEN_BYTES) }),
    listModels: async (provider, owned) => listProviderModels(provider, {
      ...owned,
      ensureHealthy: async () => ({ state: 'healthy' }),
      requestModels: requestGatewayModels
    }),
    selectModel: async ({ models }) => models[0].id
  };
  return { root, capturePath: path.join(entryDirectory, 'capture.jsonl'), gatewayPort: gateway.port, context };
}

async function captures(pathname) {
  return (await fs.readFile(pathname, 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);
}

test('real launcher routes exact args/stdin through a verified Claude child and leaves parent and normal Claude environments unchanged', async (t) => {
  const f = await fixture(t);
  const parentBefore = JSON.stringify(process.env);
  const input = 'stdin line one\nstdin ünicode\n';
  const runChild = (invocation) => runClaudeProcess(invocation, {
    spawnProcess: (file, args, options) => {
      const child = spawn(file, args, { ...options, stdio: ['pipe', 'inherit', 'inherit'] });
      child.stdin.end(input);
      return child;
    }
  });
  const result = await runClaudeCodex(['--model', 'gpt-live', '--', '--print', 'hello world', ';', '%VAR%'], {}, { ...f.context, runChild });
  assert.deepEqual(result, { provider: 'codex', model: 'gpt-live', exitCode: 0, signal: null });
  assert.equal(JSON.stringify(process.env), parentBefore);
  let captured = await captures(f.capturePath);
  assert.deepEqual(captured[0].args, ['--model', 'gpt-live', '--fallback-model', 'gpt-live', '--print', 'hello world', ';', '%VAR%']);
  assert.equal(captured[0].stdin, input);
  assert.equal(captured[0].env.ANTHROPIC_BASE_URL, `http://127.0.0.1:${f.gatewayPort}`);
  assert.equal(captured[0].env.ANTHROPIC_AUTH_TOKEN, TOKEN_TEXT);
  assert.equal(captured[0].env.CLAUDE_CODE_SUBAGENT_MODEL, 'gpt-live');
  assert.equal(JSON.stringify(captured[0]).includes('launcher-secret-canary'), false);

  const normal = spawnSync(process.execPath, [path.join(f.root, 'node_modules', '@anthropic-ai', 'claude-code', 'cli.js'), '--version'], {
    cwd: f.root, env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot }, encoding: 'utf8'
  });
  assert.equal(normal.status, 0);
  captured = await captures(f.capturePath);
  assert.equal(Object.hasOwn(captured.at(-1).env, 'ANTHROPIC_BASE_URL'), false);
  assert.equal(Object.hasOwn(captured.at(-1).env, 'ANTHROPIC_AUTH_TOKEN'), false);
});

test('real Antigravity launcher relays the exact nonzero Claude exit without fallback or simulated success', async (t) => {
  const f = await fixture(t);
  const result = await runClaudeAgy(['--model', 'agy-live', '--', '--fixture-exit=23'], {}, f.context);
  assert.deepEqual(result, { provider: 'antigravity', model: 'agy-live', exitCode: 23, signal: null });
  const captured = await captures(f.capturePath);
  assert.deepEqual(captured[0].args, ['--model', 'agy-live', '--fallback-model', 'agy-live', '--fixture-exit=23']);
});

test('real Grok launcher pins the selected model for Claude Code subagents', async (t) => {
  const f = await fixture(t);
  const result = await runClaudeGrok(['--model', 'grok-live', '--', '--fixture-exit=0'], {}, f.context);
  assert.deepEqual(result, { provider: 'grok', model: 'grok-live', exitCode: 0, signal: null });
  const captured = await captures(f.capturePath);
  assert.deepEqual(captured[0].args, ['--model', 'grok-live', '--fallback-model', 'grok-live', '--fixture-exit=0']);
  assert.equal(captured[0].env.CLAUDE_CODE_SUBAGENT_MODEL, 'grok-live');
  assert.equal(captured[0].env.ANTHROPIC_DEFAULT_HAIKU_MODEL, 'grok-live');
  assert.equal(captured[0].env.ANTHROPIC_DEFAULT_SONNET_MODEL, 'grok-live');
  assert.equal(captured[0].env.ANTHROPIC_DEFAULT_OPUS_MODEL, 'grok-live');
});

test('real Claude child receives a relayed terminal signal and the launcher reports exact signal termination', async (t) => {
  const f = await fixture(t);
  const parent = new EventEmitter();
  const runChild = (invocation) => {
    const operation = runClaudeProcess(invocation, { parent });
    const deadline = Date.now() + 5_000;
    const signalAfterCapture = async () => {
      while (Date.now() < deadline) {
        try {
          if ((await captures(f.capturePath)).length > 0) { parent.emit('SIGTERM'); return; }
        } catch { /* capture is not published yet */ }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      parent.emit('SIGTERM');
    };
    void signalAfterCapture();
    return operation;
  };
  const result = await runClaudeCodex(['--model', 'gpt-live', '--', '--fixture-wait'], {}, { ...f.context, runChild });
  assert.deepEqual(result, { provider: 'codex', model: 'gpt-live', exitCode: null, signal: 'SIGTERM' });
  assert.equal(parent.listenerCount('SIGINT'), 0);
  assert.equal(parent.listenerCount('SIGTERM'), 0);
});

test('staged launcher artifacts are deterministic, port/token-free, and preserve the fixed hidden profile contract', async (t) => {
  const f = await fixture(t);
  const staged = [];
  const files = await stageLaunchers({
    platform: 'linux', nodePath: '/opt/claudey/node', managerPath: '/opt/claudey/bin/claudeyctl.js',
    stageFile: async (file) => staged.push({ ...file, bytes: Buffer.from(file.bytes) })
  });
  assert.equal(files.length, 5);
  assert.deepEqual(staged.map(({ child, mode }) => ({ child, mode })), [
    { child: 'claudeyctl', mode: 0o755 }, { child: 'claudey', mode: 0o755 },
    { child: 'claude-codex', mode: 0o755 }, { child: 'claude-agy', mode: 0o755 },
    { child: 'claude-grok', mode: 0o755 }
  ]);
  const joined = staged.map(({ bytes }) => bytes.toString('utf8')).join('\n');
  assert.equal(joined.includes(String((await f.context.ensureGateway()).port)), false);
  assert.equal(joined.includes(TOKEN_TEXT), false);
  assert.match(joined, /'launcher' 'claudey' "\$@"/);
  assert.match(joined, /'launcher' 'claude-codex' "\$@"/);
  assert.match(joined, /'launcher' 'claude-agy' "\$@"/);
  assert.match(joined, /'launcher' 'claude-grok' "\$@"/);
});
