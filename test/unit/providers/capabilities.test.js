import assert from 'node:assert/strict';
import test from 'node:test';

import { probeRequiredCapabilities } from '../../../src/providers/capabilities.js';

const CLI = { executablePath: '/fixtures/fake-cliproxy', argsPrefix: [], identity: '/fixtures/fake-cliproxy' };
const CLAUDE = { executablePath: '/fixtures/fake-claude', argsPrefix: [], identity: '/fixtures/fake-claude' };
const CURSOR = { executablePath: '/fixtures/fake-cursor-agent', argsPrefix: [], identity: '/fixtures/fake-cursor-agent' };

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
        'models --json': '{"models":[{"id":"gpt","provider":"codex"},{"id":"gemini","provider":"antigravity"}]}\n'
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
        'print --json --mode ask --sandbox read-only': '{"type":"result"}\n'
      }
    };
    return { code: 0, stdout: responses[invocation.tool][key], stderr: '' };
  };
}

test('probes required baseline CLIProxyAPI and Claude capabilities with fixed executable identities and argv', async () => {
  const calls = [];
  const result = await probeRequiredCapabilities({ cliProxy: CLI, claude: CLAUDE, configPath: '/private/manager/config.yaml', run: successfulRunner(calls) });

  assert.equal(result.ready, true);
  assert.equal(result.capabilities.cliProxy.models.code, 'AVAILABLE');
  assert.equal(result.capabilities.claude.environment.code, 'AVAILABLE');
  assert.deepEqual(calls.map(({ tool, executablePath, args, shell, stdin, env, timeoutMs, maxStdoutBytes, maxStderrBytes }) => ({ tool, executablePath, args, shell, stdin, env, timeoutMs, maxStdoutBytes, maxStderrBytes })), [
    { tool: 'cliProxy', executablePath: CLI.executablePath, args: ['--version'], shell: false, stdin: null, env: {}, timeoutMs: 3_000, maxStdoutBytes: 16_384, maxStderrBytes: 16_384 },
    { tool: 'cliProxy', executablePath: CLI.executablePath, args: ['login', 'codex', '--json'], shell: false, stdin: null, env: {}, timeoutMs: 3_000, maxStdoutBytes: 16_384, maxStderrBytes: 16_384 },
    { tool: 'cliProxy', executablePath: CLI.executablePath, args: ['login', 'antigravity', '--json'], shell: false, stdin: null, env: {}, timeoutMs: 3_000, maxStdoutBytes: 16_384, maxStderrBytes: 16_384 },
    { tool: 'cliProxy', executablePath: CLI.executablePath, args: ['config', 'check', '--config', '/private/manager/config.yaml', '--json'], shell: false, stdin: null, env: {}, timeoutMs: 3_000, maxStdoutBytes: 16_384, maxStderrBytes: 16_384 },
    { tool: 'cliProxy', executablePath: CLI.executablePath, args: ['models', '--json'], shell: false, stdin: null, env: {}, timeoutMs: 3_000, maxStdoutBytes: 16_384, maxStderrBytes: 16_384 },
    { tool: 'claude', executablePath: CLAUDE.executablePath, args: ['--version'], shell: false, stdin: null, env: {}, timeoutMs: 3_000, maxStdoutBytes: 16_384, maxStderrBytes: 16_384 },
    { tool: 'claude', executablePath: CLAUDE.executablePath, args: ['model', '--help', '--json'], shell: false, stdin: null, env: {}, timeoutMs: 3_000, maxStdoutBytes: 16_384, maxStderrBytes: 16_384 },
    { tool: 'claude', executablePath: CLAUDE.executablePath, args: ['plugin', '--help', '--json'], shell: false, stdin: null, env: {}, timeoutMs: 3_000, maxStdoutBytes: 16_384, maxStderrBytes: 16_384 },
    { tool: 'claude', executablePath: CLAUDE.executablePath, args: ['mcp', '--help', '--json'], shell: false, stdin: null, env: {}, timeoutMs: 3_000, maxStdoutBytes: 16_384, maxStderrBytes: 16_384 },
    { tool: 'claude', executablePath: CLAUDE.executablePath, args: ['environment', '--json'], shell: false, stdin: null, env: {}, timeoutMs: 3_000, maxStdoutBytes: 16_384, maxStderrBytes: 16_384 }
  ]);
});

test('refuses older versions and accepts newer versions only after every required capability succeeds', async () => {
  for (const versions of [{ cliProxy: '7.2.129' }, { claude: '2.1.228' }]) {
    const result = await probeRequiredCapabilities({ cliProxy: CLI, claude: CLAUDE, configPath: '/private/manager/config.yaml', run: successfulRunner([], versions) });
    assert.equal(result.ready, false);
  }

  const calls = [];
  const newer = await probeRequiredCapabilities({ cliProxy: CLI, claude: CLAUDE, configPath: '/private/manager/config.yaml', run: successfulRunner(calls, { cliProxy: '7.2.131', claude: '2.2.0' }) });
  assert.equal(newer.ready, true);
  assert.equal(calls.length, 10);
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
  assert.equal(calls.at(-1).stdin, 'Reply with exactly OK.');

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
