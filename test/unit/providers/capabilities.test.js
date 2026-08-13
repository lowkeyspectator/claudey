import assert from 'node:assert/strict';
import test from 'node:test';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { probeRequiredCapabilities, runFixedCommand, validateAuthenticatedModelCatalog, resolveCursorExecutable } from '../../../src/providers/capabilities.js';

const CLI = { executablePath: '/fixtures/fake-cliproxy', argsPrefix: [], identity: '/fixtures/fake-cliproxy', revalidate: async () => true };
const CLAUDE = { executablePath: '/fixtures/fake-claude', argsPrefix: [], identity: '/fixtures/fake-claude', revalidate: async () => true };
const CURSOR = { executablePath: '/fixtures/fake-cursor-agent', argsPrefix: [], identity: '/fixtures/fake-cursor-agent', revalidate: async () => true };

function successfulRunner(calls, versions = {}) {
  return async (invocation) => {
    calls.push(invocation);
    const key = invocation.args.join(' ');
    const responses = {
      cliProxy: {
        '--version': `CLIProxyAPI ${versions.cliProxy ?? '7.2.130'}\n`,
        'login codex --json': '{"modes":["codex"]}\n',
        'login antigravity --json': '{"modes":["antigravity"]}\n',
        'config check --config /private/manager/config.yaml --json': '{"configPath":"/private/manager/config.yaml","requiredKeys":["host","port","api-keys"]}\n',
        '--help --json': '{"commands":["login","config"],"loginModes":["codex","antigravity"],"configSelection":true}\n'
      },
      claude: {
        '--version': `Claude Code ${versions.claude ?? '2.1.229'}\n`,
        'model --help --json': '{"modelSelection":true}\n',
        'plugin --help --json': '{"plugins":true}\n',
        'mcp --help --json': '{"mcp":true}\n',
        'environment --json': '{"gatewayVariables":["ANTHROPIC_BASE_URL","ANTHROPIC_AUTH_TOKEN"]}\n'
      },
      cursor: {
        '--version': 'Cursor Agent 1.0.0\n',
        'status --json': '{"authenticated":true}\n',
        'models --json': '{"models":[{"id":"cursor-model"}]}\n',
        'print --json --mode ask --sandbox read-only': '{"type":"result","echo":"Reply with exactly OK."}\n'
      }
    };
    if (invocation.tool === 'cursor' && invocation.args[0] === 'print') return { code: 0, stdout: JSON.stringify({ type: 'result', echo: invocation.stdin }) + '\n', stderr: '' };
    return { code: 0, stdout: responses[invocation.tool][key], stderr: '' };
  };
}

test('probes required baseline CLIProxyAPI and Claude capabilities with fixed executable identities and argv', async () => {
  const calls = [];
  const result = await probeRequiredCapabilities({ cliProxy: CLI, claude: CLAUDE, configPath: '/private/manager/config.yaml', run: successfulRunner(calls) });

  assert.equal(result.ready, true);
  assert.equal(result.capabilities.cliProxy.help.code, 'AVAILABLE');
  assert.equal(result.capabilities.claude.environment.code, 'AVAILABLE');
  assert.deepEqual(calls.map(({ args, shell, stdin, env }) => ({ args, shell, stdin, env })), [
    { args: ['--version'], shell: false, stdin: null, env: {} },
    { args: ['--help', '--json'], shell: false, stdin: null, env: {} },
    { args: ['--version'], shell: false, stdin: null, env: {} },
    { args: ['model', '--help', '--json'], shell: false, stdin: null, env: {} },
    { args: ['plugin', '--help', '--json'], shell: false, stdin: null, env: {} },
    { args: ['mcp', '--help', '--json'], shell: false, stdin: null, env: {} },
    { args: ['environment', '--json'], shell: false, stdin: null, env: {} }
  ]);
  assert.equal(calls.some(({ args }) => args[0] === 'login' && !args.includes('--help')), false);
});

test('refuses older versions and accepts newer versions only after every required capability succeeds', async () => {
  for (const versions of [{ cliProxy: '7.2.129' }, { claude: '2.1.228' }]) {
    const result = await probeRequiredCapabilities({ cliProxy: CLI, claude: CLAUDE, configPath: '/private/manager/config.yaml', run: successfulRunner([], versions) });
    assert.equal(result.ready, false);
  }

  const calls = [];
  const newer = await probeRequiredCapabilities({ cliProxy: CLI, claude: CLAUDE, configPath: '/private/manager/config.yaml', run: successfulRunner(calls, { cliProxy: '7.2.131', claude: '2.2.0' }) });
  assert.equal(newer.ready, true);
  assert.equal(calls.length, 7);
});

test('fails closed for spoofed, multiline, oversized, timeout, stderr, nonzero, and confused model output', async () => {
  const unsafeResponses = [
    { code: 0, stdout: 'CLIProxyAPI 7.2.130\nextra\n', stderr: '' },
    { code: 0, stdout: `CLIProxyAPI ${'9'.repeat(16_385)}\n`, stderr: '' },
    { code: 0, stdout: 'CLIProxyAPI 7.2.130\n', stderr: 'warning\n' },
    { code: 2, stdout: 'CLIProxyAPI 7.2.130\n', stderr: '' },
    { code: 0, stdout: '{"models":[{"id":"gpt","provider":"unknown"}]}\n', stderr: '' }
  ];
  for (const firstResult of unsafeResponses) {
    let first = true;
    const result = await probeRequiredCapabilities({
      cliProxy: CLI,
      claude: CLAUDE,
      configPath: '/private/manager/config.yaml',
      run: async (invocation) => first ? (first = false, firstResult) : successfulRunner([])(invocation)
    });
    assert.equal(result.ready, false);
    assert.equal(result.capabilities.cliProxy.version.code, 'CAPABILITY_UNSUPPORTED');
  }
});

test('keeps Cursor optional and disables only the malformed capability while using a bounded explicit stdin probe', async () => {
  const calls = [];
  const run = successfulRunner(calls);
  const result = await probeRequiredCapabilities({ cliProxy: CLI, claude: CLAUDE, cursor: CURSOR, configPath: '/private/manager/config.yaml', run });
  assert.equal(result.ready, true);
  assert.equal(result.capabilities.cursor.print.code, 'AVAILABLE');
  assert.deepEqual(calls.at(-1).args, ['print', '--json', '--mode', 'ask', '--sandbox', 'read-only']);
  assert.match(calls.at(-1).stdin, /^nonce:/);

  const malformed = await probeRequiredCapabilities({
    cliProxy: CLI,
    claude: CLAUDE,
    cursor: CURSOR,
    configPath: '/private/manager/config.yaml',
    run: async (invocation) => invocation.tool === 'cursor' && invocation.args[0] === 'models'
      ? { code: 0, stdout: '{"models":"not-an-array"}\n', stderr: '' }
      : successfulRunner([])(invocation)
  });
  assert.equal(malformed.ready, true);
  assert.equal(malformed.capabilities.cursor.models.code, 'CAPABILITY_UNSUPPORTED');
  assert.equal(malformed.capabilities.cursor.status.code, 'AVAILABLE');
});

test('does not run side-effecting commands and short-circuits every later probe after an unsupported version', async () => {
  const calls = [];
  const result = await probeRequiredCapabilities({
    cliProxy: CLI,
    claude: CLAUDE,
    configPath: '/private/manager/config.yaml',
    run: async (invocation) => {
      calls.push(invocation.args);
      return { code: 0, stdout: 'CLIProxyAPI 7.2.129\n', stderr: '' };
    }
  });
  assert.equal(result.ready, false);
  assert.deepEqual(calls, [['--version']]);
});

test('bounds real child output at the exact cap and validates authenticated catalogs without probing a network', async () => {
  const output = await runFixedCommand({ executablePath: process.execPath, args: ['-e', 'process.stdout.write("x".repeat(64))'], shell: false, stdin: null, env: {}, timeoutMs: 1_000, maxStdoutBytes: 16, maxStderrBytes: 16 });
  assert.ok(Buffer.byteLength(output.stdout) <= 16);
  assert.equal(validateAuthenticatedModelCatalog({ data: [] }), true);
  assert.equal(validateAuthenticatedModelCatalog({ data: [{ id: 'gpt', object: 'model', owned_by: 'codex' }, { id: 'gpt', object: 'model', owned_by: 'codex' }] }), false);
  assert.equal(validateAuthenticatedModelCatalog({ data: [{ id: 'gpt', object: 'model', owned_by: 'unknown', extra: true }] }), false);
});
test('does not spawn when identity revalidation fails', async () => {
  let called = false;
  const result = await probeRequiredCapabilities({ cliProxy: { ...CLI, revalidate: async () => false }, claude: CLAUDE, run: async () => { called = true; return { code: 0, stdout: '', stderr: '' }; } });
  assert.equal(result.ready, false);
  assert.equal(called, false);
});
test('prefers verified cursor-agent and only accepts agent after Cursor identity verification', () => {
  const candidates = [
    { command: 'agent', target: { executablePath: '/bin/agent', argsPrefix: [], identity: 'agent', verified: true, revalidate: async () => true } },
    { command: 'cursor-agent', target: { executablePath: '/bin/cursor-agent', argsPrefix: [], identity: 'cursor-agent', verified: true, revalidate: async () => true } }
  ];
  assert.equal(resolveCursorExecutable({ candidates }).identity, 'cursor-agent');
  assert.throws(() => resolveCursorExecutable({ candidates: [{ command: 'agent', target: { executablePath: '/bin/agent', argsPrefix: [], identity: 'agent', verified: false, revalidate: async () => false } }] }), (error) => error.code === 'CAPABILITY_UNSUPPORTED');
});
test('timeout reaches a terminal result and removes an ignore-TERM descendant', { skip: process.platform === 'win32' }, async () => {
  const fixture = fileURLToPath(new URL('../../fixtures/bin/fake-process-tree.js', import.meta.url));
  const result = await runFixedCommand({ executablePath: process.execPath, args: [fixture, 'ignore-tree'], shell: false, stdin: null, env: {}, timeoutMs: 30, maxStdoutBytes: 64, maxStderrBytes: 64 });
  const pid = Number(result.stdout.trim());
  assert.equal(result.code, -1);
  assert.ok(Number.isSafeInteger(pid));
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.throws(() => process.kill(pid, 0));
});
test('sends an injected Cursor nonce only on stdin and requires its exact echo', async () => {
  const calls = [];
  const result = await probeRequiredCapabilities({ cliProxy: CLI, claude: CLAUDE, cursor: CURSOR, configPath: '/private/manager/config.yaml', nonceFactory: () => 'nonce-7', run: async (invocation) => {
    calls.push(invocation);
    if (invocation.tool === 'cursor' && invocation.args[0] === 'print') return { code: 0, stdout: '{"type":"result","echo":"nonce:nonce-7"}\n', stderr: '' };
    return successfulRunner([])(invocation);
  } });
  const print = calls.find((call) => call.tool === 'cursor' && call.args[0] === 'print');
  assert.equal(result.capabilities.cursor.print.code, 'AVAILABLE');
  assert.equal(print.stdin, 'nonce:nonce-7');
  assert.equal(print.args.join(' ').includes('nonce-7') || Object.values(print.env).join(' ').includes('nonce-7'), false);
});