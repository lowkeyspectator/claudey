import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import test, { after } from 'node:test';

import { resolveVerifiedExecutable } from '../../../src/core/executable.js';
import {
  AUTH_WARNING,
  authenticateProvider,
  probeAuthCapabilities,
  runInteractiveAuthProcess
} from '../../../src/providers/auth.js';

function executableAdapter() {
  const tagged = (stats) => { if (stats.reparseTag === undefined) Object.defineProperty(stats, 'reparseTag', { value: 0 }); return stats; };
  return {
    realpath: fs.realpath,
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

const fixtureRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'claudex-auth-unit-'));
after(() => fs.rm(fixtureRoot, { recursive: true, force: true }));
const CLI = await resolveVerifiedExecutable({
  command: 'cliproxyapi', platform: 'win32', candidates: [{ path: process.execPath }], adapter: executableAdapter()
});
const HELP = `Usage of CLIProxyAPI\n  -antigravity-login\n  -codex-device-login\n  -codex-login\n  -config string\n  -no-browser\n  -oauth-callback-port int\n`;

async function capabilities(calls = [], version = '7.2.130') {
  return probeAuthCapabilities({
    cliProxy: CLI,
    run: async (invocation) => {
      calls.push(invocation);
      return { code: 0, stdout: invocation.args.at(-1) === '--version' ? `CLIProxyAPI ${version}\n` : HELP, stderr: '', cleanupConfirmed: true };
    }
  });
}

function authOptions(descriptor, overrides = {}) {
  return {
    provider: 'codex',
    mode: 'browser',
    callbackPort: undefined,
    nonInteractive: false,
    ci: false,
    isTTY: true,
    configPath: 'C:\\Users\\person\\claudex\\config.yaml',
    cwd: 'C:\\Users\\person\\claudex',
    environment: { PATH: 'safe-path', SystemRoot: 'C:\\Windows', OPENAI_API_KEY: 'secret-canary', ANTHROPIC_BASE_URL: 'http://hostile' },
    capabilities: descriptor,
    inspectCallbackPort: async ({ port }) => ({ state: 'free', port }),
    warn: () => {},
    runInteractive: async (invocation) => ({ code: 0, signal: null, invocation }),
    ...overrides
  };
}

test('probes exact installed version and help and returns a frozen, nonforgeable descriptor', async () => {
  const calls = [];
  const descriptor = await capabilities(calls);
  assert.equal(Object.isFrozen(descriptor), true);
  assert.deepEqual(descriptor.providers, {
    codex: { browser: true, deviceCode: true, noBrowser: true, callbackPort: true, defaultCallbackPort: 1455 },
    antigravity: { browser: true, noBrowser: true, callbackPort: true, defaultCallbackPort: 51121 }
  });
  assert.deepEqual(calls.map(({ args, shell, stdin, env, timeoutMs, maxStdoutBytes, maxStderrBytes }) => ({ args, shell, stdin, env, timeoutMs, maxStdoutBytes, maxStderrBytes })), [
    { args: ['--version'], shell: false, stdin: null, env: {}, timeoutMs: 3_000, maxStdoutBytes: 16_384, maxStderrBytes: 16_384 },
    { args: ['--help'], shell: false, stdin: null, env: {}, timeoutMs: 3_000, maxStdoutBytes: 16_384, maxStderrBytes: 16_384 }
  ]);

  await assert.rejects(
    authenticateProvider(authOptions(Object.freeze({ providers: descriptor.providers }))),
    (error) => error.code === 'CAPABILITY_UNSUPPORTED'
  );
});

test('rejects malformed, partial, oversized, warning, nonzero, and stale help without authenticating', async () => {
  for (const result of [
    { code: 0, stdout: HELP.replace('  -codex-login\n', ''), stderr: '' },
    { code: 0, stdout: `${HELP}  -unknown-login\n`, stderr: '' },
    { code: 0, stdout: HELP, stderr: 'warning\n' },
    { code: 2, stdout: HELP, stderr: '' },
    { code: 0, stdout: 'x'.repeat(16_385), stderr: '' }
  ]) {
    await assert.rejects(
      probeAuthCapabilities({ cliProxy: CLI, run: async (invocation) => invocation.args.at(-1) === '--version'
        ? { code: 0, stdout: 'CLIProxyAPI 7.2.130\n', stderr: '' }
        : result }),
      (error) => error.code === 'CAPABILITY_UNSUPPORTED'
    );
  }
});

test('rejects old, malformed, noisy, and nonzero version probes before reading auth help', async () => {
  for (const result of [
    { code: 0, stdout: 'CLIProxyAPI 7.2.129\n', stderr: '' },
    { code: 0, stdout: 'CLIProxyAPI v7.2.130\n', stderr: '' },
    { code: 0, stdout: 'CLIProxyAPI 7.2.130\nextra\n', stderr: '' },
    { code: 0, stdout: 'CLIProxyAPI 7.2.130\n', stderr: 'warning\n' },
    { code: 2, stdout: 'CLIProxyAPI 7.2.130\n', stderr: '' }
  ]) {
    let calls = 0;
    await assert.rejects(probeAuthCapabilities({ cliProxy: CLI, run: async () => { calls += 1; return result; } }), (error) => error.code === 'CAPABILITY_UNSUPPORTED');
    assert.equal(calls, 1);
  }
});

test('newer reviewed-help versions require an explicit callback port instead of assuming baseline defaults', async () => {
  const descriptor = await capabilities([], '7.2.131');
  assert.equal(descriptor.providers.codex.defaultCallbackPort, null);
  let touched = false;
  await assert.rejects(authenticateProvider(authOptions(descriptor, {
    inspectCallbackPort: async () => { touched = true; return { state: 'free' }; },
    runInteractive: async () => { touched = true; return { code: 0, signal: null }; }
  })), (error) => error.code === 'CAPABILITY_UNSUPPORTED');
  assert.equal(touched, false);
  const explicit = await authenticateProvider(authOptions(descriptor, { callbackPort: 24567 }));
  assert.equal(explicit.authenticated, true);
});

test('constructs only fixed supported provider argv and checks effective callback ports before spawn', async () => {
  const descriptor = await capabilities();
  const cases = [
    { provider: 'codex', mode: 'browser', callbackPort: undefined, port: 1455, suffix: ['--codex-login'] },
    { provider: 'codex', mode: 'device-code', callbackPort: undefined, port: null, suffix: ['--codex-device-login'] },
    { provider: 'codex', mode: 'no-browser', callbackPort: 23456, port: 23456, suffix: ['--codex-login', '--no-browser', '--oauth-callback-port', '23456'] },
    { provider: 'antigravity', mode: 'browser', callbackPort: undefined, port: 51121, suffix: ['--antigravity-login'] },
    { provider: 'antigravity', mode: 'no-browser', callbackPort: 34567, port: 34567, suffix: ['--antigravity-login', '--no-browser', '--oauth-callback-port', '34567'] }
  ];
  for (const item of cases) {
    const inspected = [];
    let invocation;
    const result = await authenticateProvider(authOptions(descriptor, {
      ...item,
      inspectCallbackPort: async (request) => { inspected.push(request); return { state: 'free', port: request.port }; },
      runInteractive: async (value) => { invocation = value; return { code: 0, signal: null }; }
    }));
    assert.equal(result.authenticated, true);
    assert.deepEqual(Object.keys(result), ['authenticated', 'provider', 'mode']);
    assert.deepEqual(invocation.args.slice(-item.suffix.length), item.suffix);
    assert.deepEqual(invocation.args.slice(0, 2), ['--config', 'C:\\Users\\person\\claudex\\config.yaml']);
    assert.deepEqual(inspected, item.port === null ? [] : [{ host: '127.0.0.1', port: item.port, provider: item.provider }]);
  }
});

test('refuses unsupported modes, callback collisions, invalid callbacks, and identity changes before interactive spawn', async () => {
  const descriptor = await capabilities();
  let spawned = 0;
  const runInteractive = async () => { spawned += 1; return { code: 0, signal: null }; };
  for (const options of [
    { provider: 'antigravity', mode: 'device-code' },
    { provider: 'codex', mode: 'unknown' },
    { provider: 'codex', mode: 'browser', callbackPort: 80 },
    { provider: 'codex', mode: 'browser', callbackPort: 65536 }
  ]) {
    await assert.rejects(authenticateProvider(authOptions(descriptor, { ...options, runInteractive })), (error) => ['USAGE_ERROR', 'CAPABILITY_UNSUPPORTED'].includes(error.code));
  }
  await assert.rejects(authenticateProvider(authOptions(descriptor, {
    runInteractive,
    inspectCallbackPort: async ({ port }) => ({ state: 'owned', port, pid: 991 })
  })), (error) => error.code === 'PORT_IN_USE' && error.details.pid === 991);
  assert.equal(spawned, 0);
});

test('refuses relative, UNC, alternate-stream, ambiguous, and out-of-working-directory config paths before side effects', async () => {
  const descriptor = await capabilities();
  const cases = [
    { configPath: 'config.yaml' },
    { configPath: '\\\\server\\share\\config.yaml', cwd: '\\\\server\\share' },
    { configPath: 'C:\\Users\\person\\claudex\\config.yaml:secret' },
    { configPath: 'C:\\Users\\person\\claudex\\sub\\..\\config.yaml' },
    { configPath: 'C:\\Users\\person\\elsewhere\\config.yaml' },
    { configPath: 'C:\\Users\\person\\claudex\\other.yaml' }
  ];
  for (const item of cases) {
    let touched = false;
    await assert.rejects(authenticateProvider(authOptions(descriptor, {
      ...item,
      inspectCallbackPort: async () => { touched = true; return { state: 'free' }; },
      warn: () => { touched = true; },
      runInteractive: async () => { touched = true; return { code: 0, signal: null }; }
    })), (error) => error.code === 'USAGE_ERROR');
    assert.equal(touched, false);
  }
});

test('refuses CI, noninteractive, and non-TTY use immediately without probing ports, warnings, or spawning', async () => {
  const descriptor = await capabilities();
  for (const refusal of [{ ci: true }, { nonInteractive: true }, { isTTY: false }]) {
    const touched = [];
    await assert.rejects(authenticateProvider(authOptions(descriptor, {
      ...refusal,
      inspectCallbackPort: async () => { touched.push('port'); return { state: 'free' }; },
      warn: () => touched.push('warn'),
      runInteractive: async () => { touched.push('spawn'); return { code: 0, signal: null }; }
    })), (error) => error.code === 'INTERACTION_REQUIRED');
    assert.deepEqual(touched, []);
  }
});

test('uses a minimal environment, emits the third-party warning, and never puts ambient secrets in argv or env', async () => {
  const descriptor = await capabilities();
  const warnings = [];
  let invocation;
  const result = await authenticateProvider(authOptions(descriptor, {
    warn: (message) => warnings.push(message),
    runInteractive: async (value) => { invocation = value; return { code: 0, signal: null }; }
  }));
  assert.deepEqual(warnings, [AUTH_WARNING]);
  assert.deepEqual(invocation.env, { PATH: 'safe-path', SystemRoot: 'C:\\Windows' });
  const serialized = JSON.stringify(invocation);
  assert.equal(serialized.includes('secret-canary'), false);
  assert.equal(serialized.includes('http://hostile'), false);
  assert.equal(invocation.shell, false);
  assert.equal(invocation.stdio, 'inherit');
  assert.equal(invocation.fileModeMask, 0o077);
  assert.deepEqual(Object.keys(result), ['authenticated', 'provider', 'mode']);
});

test('relays exact nonzero and signal termination without simulating authentication success', async () => {
  const descriptor = await capabilities();
  for (const expected of [
    { code: 9, signal: null },
    { code: null, signal: 'SIGTERM' }
  ]) {
    const result = await authenticateProvider(authOptions(descriptor, { runInteractive: async () => expected }));
    assert.deepEqual(Object.keys(result), ['authenticated', 'provider', 'mode', 'exitCode', 'signal']);
    assert.deepEqual({ authenticated: result.authenticated, exitCode: result.exitCode, signal: result.signal }, {
      authenticated: false, exitCode: expected.code, signal: expected.signal
    });
  }
});

test('malformed or throwing runners fail closed without leaking private diagnostics', async () => {
  const descriptor = await capabilities();
  for (const runInteractive of [
    async () => ({ code: 0 }),
    async () => { throw new Error('private diagnostic secret-canary'); }
  ]) {
    await assert.rejects(authenticateProvider(authOptions(descriptor, { runInteractive })), (error) => error.code === 'AUTH_REQUIRED' && !error.message.includes('secret-canary'));
  }
});

test('warning output failure is sanitized and prevents authentication spawn', async () => {
  const descriptor = await capabilities();
  let spawned = false;
  await assert.rejects(authenticateProvider(authOptions(descriptor, {
    warn: () => { throw new Error('warning sink secret-canary'); },
    runInteractive: async () => { spawned = true; return { code: 0, signal: null }; }
  })), (error) => error.code === 'AUTH_REQUIRED' && !error.message.includes('secret-canary'));
  assert.equal(spawned, false);
});

test('interactive runner inherits stdio, relays parent signals, restores umask, and returns exact child termination', async () => {
  const parent = new EventEmitter();
  const child = new EventEmitter();
  child.kill = (signal) => { child.killedWith = signal; return true; };
  const spawns = [];
  let mask = 0o022;
  const operation = runInteractiveAuthProcess({
    executablePath: process.execPath,
    args: ['fixture.js'],
    cwd: fixtureRoot,
    env: { PATH: 'safe' },
    shell: false,
    stdio: 'inherit',
    fileModeMask: 0o077,
    signal: undefined
  }, {
    parent,
    umask: (value) => { const prior = mask; if (value !== undefined) mask = value; return prior; },
    spawnProcess: (file, args, options) => { spawns.push({ file, args, options, mask }); queueMicrotask(() => parent.emit('SIGTERM')); queueMicrotask(() => child.emit('exit', null, 'SIGTERM')); return child; }
  });
  const result = await operation;
  assert.deepEqual(result, { code: null, signal: 'SIGTERM' });
  assert.equal(child.killedWith, 'SIGTERM');
  assert.equal(mask, 0o022);
  assert.deepEqual(spawns[0], {
    file: process.execPath,
    args: ['fixture.js'],
    options: { cwd: fixtureRoot, env: { PATH: 'safe' }, shell: false, stdio: 'inherit', windowsHide: false },
    mask: 0o077
  });
  assert.equal(parent.listenerCount('SIGINT'), 0);
  assert.equal(parent.listenerCount('SIGTERM'), 0);
});
