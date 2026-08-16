import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import test, { after } from 'node:test';
import { fileURLToPath } from 'node:url';

import { resolveVerifiedExecutable } from '../../../src/core/executable.js';

import {
  probeRequiredCapabilities,
  resolveCursorExecutable,
  runFixedCommand,
  validateAuthenticatedModelCatalog
} from '../../../src/providers/capabilities.js';

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

const fixtureRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'claudex-capabilities-'));
after(() => fs.rm(fixtureRoot, { recursive: true, force: true }));

async function makeTarget(command, fixtureName, suffix = '') {
  const root = path.join(fixtureRoot, `${command}${suffix}`);
  const entries = {
    claude: ['@anthropic-ai', 'claude-code', 'cli.js'],
    cliproxyapi: ['cliproxyapi', 'cli.js'],
    'cursor-agent': ['@cursor', 'agent', 'cli.js'],
    agent: ['@cursor', 'agent', 'cli.js']
  };
  const entry = entries[command];
  await fs.mkdir(path.join(root, 'node_modules', ...entry.slice(0, -1)), { recursive: true });
  await fs.copyFile(process.execPath, path.join(root, 'node.exe'));
  await fs.copyFile(fileURLToPath(new URL(`../../fixtures/bin/${fixtureName}`, import.meta.url)), path.join(root, 'node_modules', ...entry));
  const script = `@ECHO off\r\n"%~dp0\\node.exe" "%~dp0\\node_modules\\${entry.join('\\')}" %*\r\n`;
  const shim = path.join(root, `${command}.cmd`);
  await fs.writeFile(shim, script);
  return resolveVerifiedExecutable({ command, platform: 'win32', candidates: [{ path: shim }], adapter: executableAdapter() });
}

const CLI = await makeTarget('cliproxyapi', 'fake-cliproxy.js');
const CLAUDE = await makeTarget('claude', 'fake-claude.js');
const CURSOR = await makeTarget('cursor-agent', 'fake-cursor-agent.js');

function forgeTarget(executablePath, argsPrefix = []) {
  const identity = Object.freeze({
    schemaVersion: 1, command: 'forged', platform: process.platform, kind: 'native', candidatePaths: Object.freeze([executablePath]),
    components: Object.freeze([Object.freeze({ path: executablePath, type: 'file', dev: '1', ino: '1', birthtimeMs: '1', mode: '1', size: '1', mtimeMs: '1', ctimeMs: '1' })])
  });
  return Object.freeze({ kind: 'native', executablePath, argsPrefix: Object.freeze([...argsPrefix]), identity, revalidate: async () => true });
}
function successfulRunner(calls = [], { versions = {}, override = {} } = {}) {
  return async (invocation) => {
    const commandArgs = invocation.args[0]?.toLowerCase().endsWith('.js') ? invocation.args.slice(1) : invocation.args;
    const observed = { ...invocation, args: commandArgs };
    calls.push(observed);
    const key = `${invocation.tool}:${commandArgs.join(' ')}`;
    if (Object.hasOwn(override, key)) return typeof override[key] === 'function' ? override[key](observed) : override[key];
    const responses = {
      'cliProxy:--version': `CLIProxyAPI ${versions.cliProxy ?? '7.2.130'}\n`,
      'cliProxy:--help --json': '{"commands":["login","config"],"loginModes":["codex","antigravity"]}\n',
      'cliProxy:config probe --json': '{"explicitConfigSelection":true,"requiredKeys":["host","port","tls","remote-management","auth-dir","api-keys","debug","commercial-mode","logging-to-file","usage-statistics-enabled","pprof","plugins","ws-auth"],"commercialMode":{"requiredValue":true,"requestLoggingDisabled":true}}\n',
      'claude:--version': `Claude Code ${versions.claude ?? '2.1.229'}\n`,
      'claude:model --help --json': '{"modelSelection":true}\n',
      'claude:plugin --help --json': '{"plugins":true}\n',
      'claude:mcp --help --json': '{"mcp":true}\n',
      'claude:environment --json': '{"gatewayVariables":["ANTHROPIC_BASE_URL","ANTHROPIC_AUTH_TOKEN"]}\n',
      'cursor:--version': 'Cursor Agent 1.0.0\n',
      'cursor:status --json': '{"authenticated":true}\n',
      'cursor:models --json': '{"models":[{"id":"cursor-model"}]}\n',
      'cursor:probe json --json': '{"type":"probe","capability":"json","framing":"json-lines"}\n',
      'cursor:probe stdin --json': `${JSON.stringify({ type: 'probe', capability: 'stdin', echo: invocation.stdin })}\n`,
      'cursor:probe mode ask --json': '{"type":"probe","capability":"ask","supported":true}\n',
      'cursor:probe mode plan --json': '{"type":"probe","capability":"plan","supported":true}\n',
      'cursor:probe sandbox read-only --json': '{"type":"probe","capability":"sandbox","supported":true}\n'
    };
    return { code: Object.hasOwn(responses, key) ? 0 : 2, stdout: responses[key] ?? '', stderr: '' };
  };
}

test('rejects a deeply frozen forged process identity before provider or Cursor execution', async () => {
  let executed = 0;
  const forged = forgeTarget(process.execPath, ['-e', 'process.exit(99)']);
  const provider = await probeRequiredCapabilities({
    cliProxy: forged,
    claude: forged,
    run: async () => { executed += 1; return { code: 0, stdout: 'CLIProxyAPI 7.2.130\n', stderr: '' }; }
  });
  assert.equal(provider.ready, false);
  await assert.rejects(resolveCursorExecutable({ candidates: [{ command: 'cursor-agent', target: forged }], run: async () => { executed += 1; return { code: 0, stdout: 'Cursor Agent 1.0.0\n', stderr: '' }; } }), (error) => error.code === 'CAPABILITY_UNSUPPORTED');
  assert.equal(executed, 0);
});
test('probes baseline CLIProxyAPI and Claude with exact side-effect-free argv and revalidates before every spawn', async () => {
  const calls = [];
  let cliChecks = 0;
  let claudeChecks = 0;
  const cli = CLI;
  const claude = CLAUDE;
  const result = await probeRequiredCapabilities({ cliProxy: cli, claude, run: successfulRunner(calls) });

  assert.equal(result.ready, true);
  assert.deepEqual(calls.map(({ tool, args, shell, stdin, env }) => ({ tool, args, shell, stdin, env })), [
    { tool: 'cliProxy', args: ['--version'], shell: false, stdin: null, env: {} },
    { tool: 'cliProxy', args: ['--help', '--json'], shell: false, stdin: null, env: {} },
    { tool: 'cliProxy', args: ['config', 'probe', '--json'], shell: false, stdin: null, env: {} },
    { tool: 'claude', args: ['--version'], shell: false, stdin: null, env: {} },
    { tool: 'claude', args: ['model', '--help', '--json'], shell: false, stdin: null, env: {} },
    { tool: 'claude', args: ['plugin', '--help', '--json'], shell: false, stdin: null, env: {} },
    { tool: 'claude', args: ['mcp', '--help', '--json'], shell: false, stdin: null, env: {} },
    { tool: 'claude', args: ['environment', '--json'], shell: false, stdin: null, env: {} }
  ]);
  assert.equal(cliChecks, 0);
  assert.equal(claudeChecks, 0);
});

test('refuses old/spoofed versions before later probes and accepts newer versions only with all required capabilities', async () => {
  for (const versions of [{ cliProxy: '7.2.129' }, { claude: '2.1.228' }]) {
    const calls = [];
    const result = await probeRequiredCapabilities({ cliProxy: CLI, claude: CLAUDE, run: successfulRunner(calls, { versions }) });
    assert.equal(result.ready, false);
    if (versions.cliProxy) assert.deepEqual(calls.map((call) => call.args), [['--version']]);
  }
  const calls = [];
  const newer = await probeRequiredCapabilities({
    cliProxy: CLI, claude: CLAUDE, run: successfulRunner(calls, { versions: { cliProxy: '7.2.131', claude: '2.2.0' } })
  });
  assert.equal(newer.ready, true);
  const current = await probeRequiredCapabilities({
    cliProxy: CLI, claude: CLAUDE, run: async (invocation) => {
      if (invocation.tool === 'claude' && invocation.args[0] === '--version') {
        return { code: 0, stdout: 'Claude Code 2.1.233.0\n', stderr: 'update available\n' };
      }
      return successfulRunner([], { versions: { claude: '2.1.233' } })(invocation);
    }
  });
  assert.equal(current.ready, true);
  assert.equal(current.capabilities.claude.version.version, '2.1.233');
  assert.equal(calls.length, 8);

  for (const firstResult of [
    { code: 0, stdout: 'CLIProxyAPI 7.2.130\nextra\n', stderr: '' },
    { code: 0, stdout: `CLIProxyAPI ${'9'.repeat(16_385)}\n`, stderr: '' },
    { code: 0, stdout: 'CLIProxyAPI 7.2.130\n', stderr: 'warning\n' },
    { code: 2, stdout: 'CLIProxyAPI 7.2.130\n', stderr: '' }
  ]) {
    const result = await probeRequiredCapabilities({
      cliProxy: CLI,
      claude: CLAUDE,
      run: successfulRunner([], { override: { 'cliProxy:--version': firstResult } })
    });
    assert.equal(result.ready, false);
  }
});

test('validates authenticated model catalogs independently without network access', () => {
  assert.equal(validateAuthenticatedModelCatalog({ object: 'list', data: [] }), false);
  assert.equal(validateAuthenticatedModelCatalog({ object: 'list', data: [] }, { allowPreAuthEmpty: true }), true);
  assert.equal(validateAuthenticatedModelCatalog({ object: 'list', data: [{ id: 'gpt', object: 'model', created: 1, owned_by: 'codex' }], extra: true }), false);
  assert.equal(validateAuthenticatedModelCatalog({ object: 'list', data: [{ id: 'gpt', object: 'model', created: 1, owned_by: 'codex' }, { id: 'gpt', object: 'model', created: 2, owned_by: 'codex' }] }), false);
  assert.equal(validateAuthenticatedModelCatalog({ object: 'list', data: [{ id: 'gpt', object: 'model', created: 1, owned_by: '' }] }), false);
  assert.equal(validateAuthenticatedModelCatalog({ object: 'list', data: [{ id: 'gpt', object: 'model', created: 1, owned_by: 'codex' }] }), true);
  assert.equal(validateAuthenticatedModelCatalog({ object: 'list', data: [{ id: 'grok-4.5', object: 'model', created: 1, owned_by: 'xai' }] }), true);
  assert.equal(validateAuthenticatedModelCatalog({ object: 'list', data: [{ id: 'gemini-3-flash', object: 'model', owned_by: 'antigravity' }] }), true);
});

test('resolves verified cursor-agent first and verifies agent identity plus Cursor version before fallback', async () => {
  const calls = [];
  const cursorAgent = CURSOR;
  const agent = await makeTarget('agent', 'fake-cursor-agent.js', '-fallback');
  const selected = await resolveCursorExecutable({
    candidates: [{ command: 'agent', target: agent }, { command: 'cursor-agent', target: cursorAgent }],
    run: successfulRunner(calls)
  });
  assert.equal(selected, cursorAgent);
  assert.deepEqual(calls.map((call) => call.args), [['--version']]);

  const fallbackCalls = [];
  const fallback = await resolveCursorExecutable({
    candidates: [{ command: 'cursor-agent', target: cursorAgent }, { command: 'agent', target: agent }],
    run: successfulRunner(fallbackCalls, { override: { 'cursor:--version': (() => {
      let invocation = 0;
      return () => ({ code: 0, stdout: ++invocation === 1 ? 'Unrelated Agent 1.0.0\n' : 'Cursor Agent 1.0.0\n', stderr: '' });
    })() } })
  });
  assert.equal(fallback, agent);
  assert.equal(fallbackCalls.length, 2);

  await assert.rejects(
    resolveCursorExecutable({ candidates: [{ command: 'agent', target: agent }], run: successfulRunner([], { override: { 'cursor:--version': { code: 0, stdout: 'Other Agent 1.0.0\n', stderr: '' } } }) }),
    (error) => error.code === 'CAPABILITY_UNSUPPORTED'
  );
});

test('probes every Cursor capability separately and returns an explicit advertisement matrix', async () => {
  const calls = [];
  const result = await probeRequiredCapabilities({
    cliProxy: CLI, claude: CLAUDE, cursor: CURSOR, nonceFactory: () => 'nonce-7', run: successfulRunner(calls)
  });
  assert.equal(result.ready, true);
  assert.deepEqual(Object.keys(result.capabilities.cursor), [
    'identity', 'version', 'status', 'models', 'jsonPrint', 'stdin', 'askMode', 'planMode', 'sandbox', 'tools'
  ]);
  assert.deepEqual(result.capabilities.cursor.tools, {
    models: { available: true, code: 'AVAILABLE' },
    ask: { available: true, code: 'AVAILABLE' },
    plan: { available: true, code: 'AVAILABLE' }
  });
  const cursorCalls = calls.filter((call) => call.tool === 'cursor');
  assert.deepEqual(cursorCalls.map((call) => call.args), [
    ['--version'], ['status', '--json'], ['models', '--json'], ['probe', 'json', '--json'], ['probe', 'stdin', '--json'],
    ['probe', 'mode', 'ask', '--json'], ['probe', 'mode', 'plan', '--json'], ['probe', 'sandbox', 'read-only', '--json']
  ]);
  const stdinProbe = cursorCalls.find((call) => call.args[1] === 'stdin');
  assert.equal(stdinProbe.stdin, 'nonce:nonce-7');
  assert.equal(JSON.stringify(stdinProbe.args).includes('nonce-7') || JSON.stringify(stdinProbe.env).includes('nonce-7'), false);
});

test('uses the strict --list-models compatibility fallback only after the primary Cursor list command fails', async () => {
  const calls = [];
  const result = await probeRequiredCapabilities({
    cliProxy: CLI, claude: CLAUDE, cursor: CURSOR,
    run: successfulRunner(calls, { override: {
      'cursor:models --json': { code: 2, stdout: '', stderr: '' },
      'cursor:--list-models --json': { code: 0, stdout: '{"models":[{"id":"fallback-model"}]}\n', stderr: '' }
    } })
  });
  assert.equal(result.capabilities.cursor.models.available, true);
  assert.deepEqual(calls.filter((call) => call.tool === 'cursor' && (call.args[0] === 'models' || call.args[0] === '--list-models')).map((call) => call.args), [
    ['models', '--json'], ['--list-models', '--json']
  ]);
});
test('Cursor capability failures disable only tools that actually depend on them', async () => {
  const cases = [
    ['cursor:models --json', '{"models":"bad"}\n', { models: false, ask: false, plan: false }],
    ['cursor:probe json --json', '{"type":"probe","capability":"json","framing":"text"}\n', { models: true, ask: false, plan: false }],
    ['cursor:probe stdin --json', '{"type":"probe","capability":"stdin","echo":"wrong"}\n', { models: true, ask: false, plan: false }],
    ['cursor:probe mode ask --json', '{"type":"probe","capability":"ask","supported":false}\n', { models: true, ask: false, plan: true }],
    ['cursor:probe mode plan --json', '{"type":"probe","capability":"plan","supported":false}\n', { models: true, ask: true, plan: false }],
    ['cursor:probe sandbox read-only --json', '{"type":"probe","capability":"sandbox","supported":false}\n', { models: true, ask: false, plan: false }]
  ];
  for (const [probe, stdout, expected] of cases) {
    const result = await probeRequiredCapabilities({
      cliProxy: CLI,
      claude: CLAUDE,
      cursor: CURSOR,
      nonceFactory: () => 'matrix',
      run: successfulRunner([], { override: { [probe]: { code: 0, stdout, stderr: '' } } })
    });
    assert.deepEqual(Object.fromEntries(Object.entries(result.capabilities.cursor.tools).map(([name, value]) => [name, value.available])), expected, probe);
  }
});

test('distinguishes a valid logged-out Cursor status from a hostile status schema', async () => {
  const loggedOut = await probeRequiredCapabilities({
    cliProxy: CLI,
    claude: CLAUDE,
    cursor: CURSOR,
    run: successfulRunner([], { override: { 'cursor:status --json': { code: 0, stdout: '{"authenticated":false}\n', stderr: '' } } })
  });
  assert.equal(loggedOut.capabilities.cursor.status.code, 'AUTH_REQUIRED');
  assert.deepEqual(Object.values(loggedOut.capabilities.cursor.tools).map((tool) => tool.code), ['AUTH_REQUIRED', 'AUTH_REQUIRED', 'AUTH_REQUIRED']);

  const hostile = await probeRequiredCapabilities({
    cliProxy: CLI,
    claude: CLAUDE,
    cursor: CURSOR,
    run: successfulRunner([], { override: { 'cursor:status --json': { code: 0, stdout: '{"authenticated":"yes"}\n', stderr: '' } } })
  });
  assert.equal(hostile.capabilities.cursor.status.code, 'CAPABILITY_UNSUPPORTED');
  assert.deepEqual(Object.values(hostile.capabilities.cursor.tools).map((tool) => tool.code), ['CAPABILITY_UNSUPPORTED', 'CAPABILITY_UNSUPPORTED', 'CAPABILITY_UNSUPPORTED']);
});
test('Cursor identity or version failure disables every Cursor probe/tool and a failed revalidation causes zero spawn', async () => {
  let called = false;
  const swapped = forgeTarget(process.execPath);
  const identityFailure = await probeRequiredCapabilities({
    cliProxy: CLI, claude: CLAUDE, cursor: swapped,
    run: async (invocation) => { if (invocation.tool === 'cursor') called = true; return successfulRunner([])(invocation); }
  });
  assert.equal(called, false);
  assert.equal(identityFailure.capabilities.cursor.tools.models.available, false);
  assert.equal(identityFailure.capabilities.cursor.tools.ask.available, false);
  assert.equal(identityFailure.capabilities.cursor.tools.plan.available, false);

  const calls = [];
  const versionFailure = await probeRequiredCapabilities({
    cliProxy: CLI,
    claude: CLAUDE,
    cursor: CURSOR,
    run: successfulRunner(calls, { override: { 'cursor:--version': { code: 0, stdout: 'not Cursor\n', stderr: '' } } })
  });
  assert.equal(calls.filter((call) => call.tool === 'cursor').length, 1);
  assert.deepEqual(Object.values(versionFailure.capabilities.cursor.tools).map((tool) => tool.available), [false, false, false]);
});

test('executes the owned Cursor capture fixture with exact argv/env/stdin boundaries', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudex-cursor-capture-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const previousCanary = process.env.ANTHROPIC_API_KEY;
  process.env.ANTHROPIC_API_KEY = 'TASK7_ENV_CANARY';
  t.after(() => { if (previousCanary === undefined) delete process.env.ANTHROPIC_API_KEY; else process.env.ANTHROPIC_API_KEY = previousCanary; });
  const cursor = await makeTarget('cursor-agent', 'fake-cursor-agent.js', '-t310');
  const capturePath = path.join(path.dirname(cursor.argsPrefix[0]), 'capture.jsonl');
  await fs.rm(capturePath, { force: true });
  const synthetic = successfulRunner([]);
  const result = await probeRequiredCapabilities({
    cliProxy: CLI,
    claude: CLAUDE,
    cursor,
    nonceFactory: () => 'owned-fixture-nonce',
    run: (invocation) => invocation.tool === 'cursor' ? runFixedCommand(invocation) : synthetic(invocation)
  });
  assert.equal(result.capabilities.cursor.tools.plan.available, true);
  const captures = (await fs.readFile(capturePath, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.deepEqual(captures.map((capture) => capture.args), [
    ['--version'], ['status', '--json'], ['models', '--json'], ['probe', 'json', '--json'], ['probe', 'stdin', '--json'],
    ['probe', 'mode', 'ask', '--json'], ['probe', 'mode', 'plan', '--json'], ['probe', 'sandbox', 'read-only', '--json']
  ]);
  assert.ok(captures.every((capture) => capture.env.ANTHROPIC_API_KEY === undefined && !JSON.stringify(capture.env).includes('TASK7_ENV_CANARY')));
  assert.ok(captures.every((capture) => JSON.stringify(capture.env) === JSON.stringify(captures[0].env)));
  assert.deepEqual(captures.map((capture) => capture.stdin), ['', '', '', '', 'nonce:owned-fixture-nonce', '', '', '']);
  assert.equal(captures.filter((capture) => JSON.stringify(capture.args).includes('owned-fixture-nonce') || JSON.stringify(capture.env).includes('owned-fixture-nonce')).length, 0);
});

test('executes owned CLIProxyAPI and Claude fixtures through branded resolution and the real runner', async (t) => {
  const previousCanary = process.env.ANTHROPIC_API_KEY;
  process.env.ANTHROPIC_API_KEY = 'TASK7_ENV_CANARY';
  t.after(() => {
    if (previousCanary === undefined) delete process.env.ANTHROPIC_API_KEY; else process.env.ANTHROPIC_API_KEY = previousCanary;
  });
  const cli = await makeTarget('cliproxyapi', 'fake-cliproxy.js', '-t339');
  const claude = await makeTarget('claude', 'fake-claude.js', '-t339');
  for (const target of [cli, claude]) await fs.rm(path.join(path.dirname(target.argsPrefix[0]), 'capture.jsonl'), { force: true });
  const result = await probeRequiredCapabilities({ cliProxy: cli, claude, run: runFixedCommand });
  assert.equal(result.ready, true);
  const cliCaptures = (await fs.readFile(path.join(path.dirname(cli.argsPrefix[0]), 'capture.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  const claudeCaptures = (await fs.readFile(path.join(path.dirname(claude.argsPrefix[0]), 'capture.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.deepEqual(cliCaptures.map((capture) => capture.args), [['--version'], ['--help', '--json'], ['config', 'probe', '--json']]);
  assert.deepEqual(claudeCaptures.map((capture) => capture.args), [['--version'], ['model', '--help', '--json'], ['plugin', '--help', '--json'], ['mcp', '--help', '--json'], ['environment', '--json']]);
  assert.ok([...cliCaptures, ...claudeCaptures].every((capture) => capture.stdin === '' && !JSON.stringify(capture.env).includes('TASK7_ENV_CANARY')));
});
test('bounds real child output at the exact cap', async () => {
  const output = await runFixedCommand({
    executablePath: process.execPath,
    args: ['-e', 'process.stdout.write("x".repeat(64))'],
    shell: false,
    stdin: null,
    env: {},
    timeoutMs: 1_000,
    maxStdoutBytes: 16,
    maxStderrBytes: 16
  });
  assert.ok(Buffer.byteLength(output.stdout) <= 16);
  assert.equal(output.code, -1);
});

test('never expands an incomplete UTF-8 sequence beyond the byte output cap', async () => {
  const output = await runFixedCommand({
    executablePath: process.execPath,
    args: ['-e', 'process.stdout.write("€€")'],
    shell: false, stdin: null, env: {}, timeoutMs: 1_000, maxStdoutBytes: 4, maxStderrBytes: 4
  });
  assert.ok(Buffer.byteLength(output.stdout, 'utf8') <= 4);
  assert.equal(output.stdout, '€');
});
test('propagates a real nonzero exit without cleanup and handles abort plus stdin failure through bounded cleanup', async () => {
  const nonzero = await runFixedCommand({ executablePath: process.execPath, args: ['-e', 'process.exit(7)'], shell: false, stdin: null, env: {}, timeoutMs: 1_000, maxStdoutBytes: 64, maxStderrBytes: 64 });
  assert.equal(nonzero.code, 7);
  assert.equal(Object.hasOwn(nonzero, 'cleanupConfirmed'), false);

  const fixture = fileURLToPath(new URL('../../fixtures/bin/fake-process-tree.js', import.meta.url));
  const terminate = async ({ pid, force }) => { if (force) { try { process.kill(pid, 'SIGKILL'); } catch { /* closed */ } } return { acknowledged: true }; };
  const checker = async ({ pid }) => { try { process.kill(pid, 0); return false; } catch { return true; } };
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 30);
  const aborted = await runFixedCommand({ executablePath: process.execPath, args: [fixture, 'hang'], shell: false, stdin: null, env: {}, timeoutMs: 1_000, maxStdoutBytes: 64, maxStderrBytes: 64, signal: controller.signal, treeTerminator: terminate, treeChecker: checker });
  assert.equal(aborted.code, -1);
  assert.equal(aborted.cleanupConfirmed, true);

  class FailingStdin extends EventEmitter {
    end() { queueMicrotask(() => this.emit('error', Object.assign(new Error('EPIPE'), { code: 'EPIPE' }))); }
    destroy() {}
  }
  const fakeChild = new EventEmitter();
  fakeChild.pid = 4242;
  fakeChild.stdin = new FailingStdin();
  fakeChild.stdout = new PassThrough();
  fakeChild.stderr = new PassThrough();
  fakeChild.unref = () => {};
  const stdinFailure = await runFixedCommand({
    executablePath: process.execPath, args: ['unused'], shell: false, stdin: 'prompt', env: {}, timeoutMs: 1_000,
    maxStdoutBytes: 64, maxStderrBytes: 64, spawnProcess: () => fakeChild,
    treeTerminator: async () => { queueMicrotask(() => fakeChild.emit('close', null)); return { acknowledged: true }; },
    treeChecker: async () => true
  });
  assert.equal(stdinFailure.code, -1);
  assert.equal(stdinFailure.cleanupConfirmed, true);
});
test('injected process-tree termination is ordered soft then hard and never resolves before cleanup closes the child', async () => {
  const fixture = fileURLToPath(new URL('../../fixtures/bin/fake-process-tree.js', import.meta.url));
  const actions = [];
  const startedAt = Date.now();
  const result = await runFixedCommand({
    executablePath: process.execPath,
    args: [fixture, 'hang'],
    shell: false,
    stdin: null,
    env: {},
    timeoutMs: 20,
    maxStdoutBytes: 64,
    maxStderrBytes: 64,
    treeTerminator: async ({ pid, force }) => {
      actions.push({ force, at: Date.now() - startedAt });
      if (force) process.kill(pid, 'SIGKILL');
      return { acknowledged: true };
    },
    treeChecker: async ({ pid }) => { try { process.kill(pid, 0); return false; } catch (error) { return error?.code === 'ESRCH'; } }
  });
  assert.deepEqual(actions.map((action) => action.force), [false, true]);
  assert.ok(actions[1].at - actions[0].at >= 90);
  assert.equal(result.code, -1);
  assert.equal(result.cleanupConfirmed, true);
  assert.ok(Date.now() - startedAt >= 110);
});

test('injected cleanup denial reaches an independent terminal deadline and reports cleanup-unconfirmed, never success', async () => {
  const fixture = fileURLToPath(new URL('../../fixtures/bin/fake-process-tree.js', import.meta.url));
  const startedAt = Date.now();
  const result = await runFixedCommand({
    executablePath: process.execPath,
    args: [fixture, 'hang'],
    shell: false,
    stdin: null,
    env: {},
    timeoutMs: 20,
    maxStdoutBytes: 64,
    maxStderrBytes: 64,
    treeTerminator: async () => ({ acknowledged: false, error: 'ACCESS_DENIED' })
  });
  const pid = Number(result.stdout.trim());
  try {
    assert.equal(result.code, -1);
    assert.equal(result.cleanupConfirmed, false);
    assert.equal(result.cleanupError, 'CLEANUP_UNCONFIRMED');
    assert.ok(Date.now() - startedAt >= 240);
  } finally {
    if (Number.isSafeInteger(pid)) { try { process.kill(pid, 'SIGKILL'); } catch { /* already exited */ } }
  }
});

test('parent exit does not skip hard cleanup of a SIGTERM-resistant descendant', async (t) => {
  const fixture = fileURLToPath(new URL('../../fixtures/bin/fake-process-tree.js', import.meta.url));
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudex-tree-check-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const pidFile = path.join(root, 'descendant.pid');
  const actions = [];
  let descendantPid;
  const readDescendant = async () => {
    if (descendantPid) return descendantPid;
    try { descendantPid = Number(await fs.readFile(pidFile, 'utf8')); } catch { return null; }
    return descendantPid;
  };
  const isAlive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
  const result = await runFixedCommand({
    executablePath: process.execPath,
    args: [fixture, 'term-exits', pidFile],
    shell: false,
    stdin: null,
    env: {},
    timeoutMs: 200,
    maxStdoutBytes: 64,
    maxStderrBytes: 64,
    treeTerminator: async ({ pid, force }) => {
      if (!force) { actions.push({ force, descendant: await readDescendant() }); try { process.kill(pid, 'SIGTERM'); } catch { /* parent already closed */ } }
      else { const descendant = await readDescendant(); actions.push({ force, descendant }); if (descendant) { try { process.kill(descendant, 'SIGKILL'); } catch { /* already closed */ } } }
      return { acknowledged: true };
    },
    treeChecker: async ({ pid }) => {
      const descendant = await readDescendant();
      return Boolean(descendant) && !isAlive(pid) && !isAlive(descendant);
    }
  });
  assert.deepEqual(actions.map((action) => action.force), [false, true]);
  assert.ok(Number.isSafeInteger(actions[1].descendant));
  assert.equal(result.code, -1);
  assert.equal(result.cleanupConfirmed, true);
});test('native Windows taskkill tree cleanup proof is explicitly unavailable in this sandbox', {
  skip: 'Native taskkill /PID <pid> /T /F proof is skipped because this Windows sandbox returns Access is denied; injected denial behavior is covered above.'
}, () => {});
