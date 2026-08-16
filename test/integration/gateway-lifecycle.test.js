import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { buildGatewayConfig } from '../../src/core/config.js';
import { createRuntimeStore, startOwnedGateway, stopOwnedGateway } from '../../src/core/lifecycle.js';
import { Secret } from '../../src/core/secrets.js';

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

function rawStatus({ port, authorization }) {
  return new Promise((resolve) => {
    const request = http.request({ host: '127.0.0.1', port, path: '/v1/models', method: 'GET', headers: authorization ? { authorization } : {} }, (response) => {
      response.resume();
      response.once('end', () => resolve(response.statusCode));
    });
    request.once('error', () => resolve(0));
    request.end();
  });
}

test('real fake gateway starts twice and stops twice only through authenticated owned lifecycle', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudey-lifecycle-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const runtimeRoot = path.join(root, 'runtime');
  await fs.mkdir(runtimeRoot, { mode: 0o700 });
  const configPath = path.join(root, 'config.yaml');
  const port = await freePort();
  const token = Secret.fromBytes(Buffer.alloc(32, 7));
  await fs.writeFile(configPath, buildGatewayConfig({ port, authDir: path.join(root, 'auth'), token }), { mode: 0o600 });
  const canonicalConfig = await fs.realpath(configPath);
  const fakeGateway = fileURLToPath(new URL('../support/fake-gateway.js', import.meta.url));
  const runtimeStore = createRuntimeStore({ root: runtimeRoot, child: 'gateway.json', platform: process.platform }, {
    assertProtected: async () => true,
    canonicalize: (value) => fs.realpath(value)
  });
  let child;
  let current;
  let randomCount = 0;
  const isAlive = () => child && child.exitCode === null && child.signalCode === null;
  const waitClosed = (timeoutMs) => new Promise((resolve) => {
    if (!isAlive()) { resolve(true); return; }
    const timer = setTimeout(() => resolve(false), timeoutMs);
    child.once('close', () => { clearTimeout(timer); resolve(true); });
  });
  t.after(async () => { if (isAlive()) { child.kill('SIGKILL'); await waitClosed(1_000); } });
  const processAdapter = {
    captureProcessTree: async () => {
      if (!isAlive() || !current) throw Object.assign(new Error('not found'), { code: 'ESRCH' });
      return {
        complete: true,
        root: {
          pid: current.pid, parentPid: process.pid, processGroupId: current.processGroupId,
          processStartTime: current.processStartTime, executableCanonicalPath: current.executableCanonicalPath,
          configCanonicalPath: current.configCanonicalPath, installationId: current.installationId,
          instanceId: current.instanceId, nonce: current.nonce
        },
        descendants: []
      };
    },
    signalTree: async ({ pids, force }) => {
      assert.deepEqual(pids, [child.pid]);
      assert.equal(child.kill(force ? 'SIGKILL' : 'SIGTERM'), true);
      return { acknowledged: true };
    },
    waitForTreeExit: async ({ timeoutMs }) => waitClosed(timeoutMs)
  };
  const originalLoad = runtimeStore.load.bind(runtimeStore);
  runtimeStore.load = async () => { current = await originalLoad(); return current; };
  const originalWrite = runtimeStore.write.bind(runtimeStore);
  runtimeStore.write = async (value) => { await originalWrite(value); current = value; return true; };
  const originalRemove = runtimeStore.remove.bind(runtimeStore);
  runtimeStore.remove = async () => { const result = await originalRemove(); current = null; return result; };

  const ctx = {
    platform: process.platform, host: '127.0.0.1', port, token,
    installationId: '11111111-1111-4111-8111-111111111111', version: '7.2.130',
    executable: Object.freeze({ fixture: true }), configCanonicalPath: canonicalConfig,
    runtimeStore, processAdapter,
    inspectListeners: async () => isAlive() && current
      ? { state: 'listening', bindings: [{ host: '127.0.0.1', port, pid: current.pid, processStartTime: current.processStartTime }] }
      : { state: 'free' },
    revalidateExecutable: async () => true,
    getInvocation: () => ({ executablePath: process.execPath, argsPrefix: [fakeGateway] }),
    spawnGateway: async (invocation) => {
      assert.equal(invocation.shell, false);
      assert.equal(JSON.stringify(invocation).includes(Buffer.alloc(32, 7).toString('base64url')), false);
      child = spawn(invocation.executablePath, invocation.args, {
        shell: false, detached: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], env: invocation.env
      });
      await new Promise((resolve, reject) => { child.once('spawn', resolve); child.once('error', reject); });
      return { pid: child.pid, processGroupId: child.pid, processStartTime: new Date().toISOString() };
    },
    cleanupSpawnedChild: async () => {
      if (!child || !isAlive()) return true;
      child.kill();
      return waitClosed(1_000);
    },
    isChildExited: async () => !isAlive(),
    randomUUID: () => '22222222-2222-4222-8222-222222222222',
    randomBytes: (size) => Buffer.alloc(size, 3 + randomCount++),
    now: () => new Date().toISOString(),
    startupTimeoutMs: 10_000, pollIntervalMs: 25, gracefulTimeoutMs: 1_000, forceTimeoutMs: 1_000,
    baseEnvironment: { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR, TEMP: process.env.TEMP, TMP: process.env.TMP, ANTHROPIC_AUTH_TOKEN: 'INTEGRATION_SECRET_CANARY' }
  };

  const first = await startOwnedGateway(ctx);
  assert.equal(first.state, 'started');
  const pid = child.pid;
  assert.equal((await startOwnedGateway(ctx)).state, 'already-running');
  assert.equal(child.pid, pid);
  assert.equal(await rawStatus({ port }), 401);
  assert.equal(await rawStatus({ port, authorization: 'Bearer wrong' }), 401);
  assert.equal((await stopOwnedGateway(ctx)).state, 'stopped');
  assert.equal(await waitClosed(1_000), true);
  assert.equal((await stopOwnedGateway(ctx)).state, 'already-stopped');
  assert.equal(await rawStatus({ port }), 0);
});
