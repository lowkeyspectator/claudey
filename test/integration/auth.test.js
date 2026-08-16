import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import test from 'node:test';

import { runAuthCommand } from '../../src/cli/commands/auth.js';
import { resolveVerifiedExecutable } from '../../src/core/executable.js';
import { probeAuthCapabilities } from '../../src/providers/auth.js';

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

async function fixture(t, exitCode = 0) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudey-auth-integration-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const capturePath = path.join(root, 'capture.json');
  const entryDirectory = path.join(root, 'node_modules', 'cliproxyapi');
  await fs.mkdir(entryDirectory, { recursive: true });
  await fs.writeFile(path.join(entryDirectory, 'package.json'), '{"type":"module"}');
  await fs.copyFile(process.execPath, path.join(root, 'node.exe'));
  const help = 'Usage of CLIProxyAPI\n  -antigravity-login\n  -codex-device-login\n  -codex-login\n  -config string\n  -no-browser\n  -oauth-callback-port int\n';
  await fs.writeFile(path.join(entryDirectory, 'cli.js'), `
import fs from 'node:fs/promises';
const args = process.argv.slice(2);
if (args.length === 1 && args[0] === '--version') process.stdout.write('CLIProxyAPI 7.2.130\\n');
else if (args.length === 1 && args[0] === '--help') process.stdout.write(${JSON.stringify(help)});
else await fs.writeFile(${JSON.stringify(capturePath)}, JSON.stringify({ args, env: process.env, cwd: process.cwd() }));
process.exitCode = args.length === 1 ? 0 : ${exitCode};
`);
  const shim = path.join(root, 'cliproxyapi.cmd');
  await fs.writeFile(shim, '@ECHO off\r\n"%~dp0\\node.exe" "%~dp0\\node_modules\\cliproxyapi\\cli.js" %*\r\n');
  const cliProxy = await resolveVerifiedExecutable({ command: 'cliproxyapi', platform: 'win32', candidates: [{ path: shim }], adapter: executableAdapter() });
  return { root, capturePath, cliProxy };
}

test('probes and runs a verified fake CLIProxyAPI with exact discrete OAuth arguments and a scrubbed environment', async (t) => {
  const fake = await fixture(t);
  const descriptor = await probeAuthCapabilities({ cliProxy: fake.cliProxy });
  const result = await runAuthCommand(['auth', 'codex'], { noBrowser: true, callbackPort: 23456 }, {
    capabilities: descriptor,
    isTTY: true,
    configPath: path.join(fake.root, 'config.yaml'),
    cwd: fake.root,
    environment: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, OPENAI_API_KEY: 'integration-secret-canary', ANTHROPIC_AUTH_TOKEN: 'hostile' },
    inspectCallbackPort: async ({ port }) => ({ state: 'free', port }),
    warn: () => {}
  });
  assert.equal(result.authenticated, true);
  assert.deepEqual(Object.keys(result), ['authenticated', 'provider', 'mode']);
  const captured = JSON.parse(await fs.readFile(fake.capturePath, 'utf8'));
  assert.deepEqual(captured.args, ['--config', path.join(fake.root, 'config.yaml'), '--codex-login', '--no-browser', '--oauth-callback-port', '23456']);
  assert.equal(captured.cwd, fake.root);
  assert.equal(JSON.stringify(captured).includes('integration-secret-canary'), false);
  assert.equal(Object.hasOwn(captured.env, 'OPENAI_API_KEY'), false);
  assert.equal(Object.hasOwn(captured.env, 'ANTHROPIC_AUTH_TOKEN'), false);
});

test('a real nonzero authentication child is never reported as authenticated', async (t) => {
  const fake = await fixture(t, 9);
  const descriptor = await probeAuthCapabilities({ cliProxy: fake.cliProxy });
  const result = await runAuthCommand(['auth', 'antigravity'], {}, {
    capabilities: descriptor,
    isTTY: true,
    configPath: path.join(fake.root, 'config.yaml'),
    cwd: fake.root,
    environment: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot },
    inspectCallbackPort: async ({ port }) => ({ state: 'free', port }),
    warn: () => {}
  });
  assert.deepEqual({ authenticated: result.authenticated, exitCode: result.exitCode, signal: result.signal }, {
    authenticated: false, exitCode: 9, signal: null
  });
});
