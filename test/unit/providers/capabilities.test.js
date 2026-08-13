import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  probeRequiredCapabilities,
  resolveCursorExecutable,
  runFixedCommand,
  validateAuthenticatedModelCatalog
} from '../../../src/providers/capabilities.js';

function freeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function target(executablePath, argsPrefix = [], overrides = {}) {
  return freeze({
    kind: argsPrefix.length ? 'node-entry' : 'native',
    executablePath,
    argsPrefix: [...argsPrefix],
    identity: {
      schemaVersion: 1,
      command: 'fixture',
      platform: process.platform,
      kind: argsPrefix.length ? 'node-entry' : 'native',
      candidatePaths: [executablePath],
      components: [{ path: executablePath, type: 'file', dev: '1', ino: '1', birthtimeMs: '1', mode: '1', size: '1', mtimeMs: '1', ctimeMs: '1' }]
    },
    revalidate: async () => true,
    ...overrides
  });
}

const CLI = target('/fixtures/fake-cliproxy');
const CLAUDE = target('/fixtures/fake-claude');
const CURSOR = target('/fixtures/fake-cursor-agent');

function successfulRunner(calls = [], { versions = {}, override = {} } = {}) {
  return async (invocation) => {
    calls.push(invocation);
    const key = `${invocation.tool}:${invocation.args.join(' ')}`;
    if (Object.hasOwn(override, key)) return typeof override[key] === 'function' ? override[key](invocation) : override[key];
    const responses = {
      'cliProxy:--version': `CLIProxyAPI ${versions.cliProxy ?? '7.2.130'}\n`,
      'cliProxy:--help --json': '{"commands":["login","config"],"loginModes":["codex","antigravity"],"configSelection":true}\n',
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

test('probes baseline CLIProxyAPI and Claude with exact side-effect-free argv and revalidates before every spawn', async () => {
  const calls = [];
  let cliChecks = 0;
  let claudeChecks = 0;
  const cli = target(CLI.executablePath, [], { revalidate: async () => { cliChecks += 1; return true; } });
  const claude = target(CLAUDE.executablePath, [], { revalidate: async () => { claudeChecks += 1; return true; } });
  const result = await probeRequiredCapabilities({ cliProxy: cli, claude, run: successfulRunner(calls) });

  assert.equal(result.ready, true);
  assert.deepEqual(calls.map(({ tool, args, shell, stdin, env }) => ({ tool, args, shell, stdin, env })), [
    { tool: 'cliProxy', args: ['--version'], shell: false, stdin: null, env: {} },
    { tool: 'cliProxy', args: ['--help', '--json'], shell: false, stdin: null, env: {} },
    { tool: 'claude', args: ['--version'], shell: false, stdin: null, env: {} },
    { tool: 'claude', args: ['model', '--help', '--json'], shell: false, stdin: null, env: {} },
    { tool: 'claude', args: ['plugin', '--help', '--json'], shell: false, stdin: null, env: {} },
    { tool: 'claude', args: ['mcp', '--help', '--json'], shell: false, stdin: null, env: {} },
    { tool: 'claude', args: ['environment', '--json'], shell: false, stdin: null, env: {} }
  ]);
  assert.equal(cliChecks, 2);
  assert.equal(claudeChecks, 5);
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
  assert.equal(calls.length, 7);

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
  assert.equal(validateAuthenticatedModelCatalog({ data: [] }), true);
  assert.equal(validateAuthenticatedModelCatalog({ data: [{ id: 'gpt', object: 'model', owned_by: 'codex' }, { id: 'gpt', object: 'model', owned_by: 'codex' }] }), false);
  assert.equal(validateAuthenticatedModelCatalog({ data: [{ id: 'gpt', object: 'model', owned_by: 'unknown', extra: true }] }), false);
});

test('resolves verified cursor-agent first and verifies agent identity plus Cursor version before fallback', async () => {
  const calls = [];
  const cursorAgent = target('/bin/cursor-agent');
  const agent = target('/bin/agent');
  const selected = await resolveCursorExecutable({
    candidates: [{ command: 'agent', target: agent }, { command: 'cursor-agent', target: cursorAgent }],
    run: successfulRunner(calls)
  });
  assert.equal(selected.executablePath, '/bin/cursor-agent');
  assert.deepEqual(calls.map((call) => call.args), [['--version']]);

  const fallbackCalls = [];
  const fallback = await resolveCursorExecutable({
    candidates: [{ command: 'cursor-agent', target: cursorAgent }, { command: 'agent', target: agent }],
    run: successfulRunner(fallbackCalls, { override: { 'cursor:--version': (() => {
      let invocation = 0;
      return () => ({ code: 0, stdout: ++invocation === 1 ? 'Unrelated Agent 1.0.0\n' : 'Cursor Agent 1.0.0\n', stderr: '' });
    })() } })
  });
  assert.equal(fallback.executablePath, '/bin/agent');
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
  const swapped = target('/fixtures/swapped', [], { revalidate: async () => false });
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
  const capturePath = path.join(root, 'capture.jsonl');
  const previousCanary = process.env.ANTHROPIC_API_KEY;
  process.env.ANTHROPIC_API_KEY = 'TASK7_ENV_CANARY';
  t.after(() => { if (previousCanary === undefined) delete process.env.ANTHROPIC_API_KEY; else process.env.ANTHROPIC_API_KEY = previousCanary; });
  const fixture = fileURLToPath(new URL('../../fixtures/bin/fake-cursor-agent.js', import.meta.url));
  const cursor = target(process.execPath, [fixture, capturePath]);
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
      return { confirmed: true };
    }
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
    treeTerminator: async () => ({ confirmed: false, error: 'ACCESS_DENIED' })
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

test('parent exit after a denied tree action never authenticates descendant cleanup', async () => {
  const fixture = fileURLToPath(new URL('../../fixtures/bin/fake-process-tree.js', import.meta.url));
  const actions = [];
  const result = await runFixedCommand({
    executablePath: process.execPath,
    args: [fixture, 'term-exits'],
    shell: false,
    stdin: null,
    env: {},
    timeoutMs: 20,
    maxStdoutBytes: 64,
    maxStderrBytes: 64,
    treeTerminator: async ({ pid, force }) => {
      actions.push(force);
      if (!force) { try { process.kill(pid, 'SIGTERM'); } catch { /* process already closed */ } }
      return { confirmed: false, error: 'ACCESS_DENIED' };
    }
  });
  assert.deepEqual(actions, [false, true]);
  assert.equal(result.code, -1);
  assert.equal(result.cleanupConfirmed, false);
  assert.equal(result.cleanupError, 'CLEANUP_UNCONFIRMED');
});
test('native Windows taskkill tree cleanup proof is explicitly unavailable in this sandbox', {
  skip: 'Native taskkill /PID <pid> /T /F proof is skipped because this Windows sandbox returns Access is denied; injected denial behavior is covered above.'
}, () => {});
