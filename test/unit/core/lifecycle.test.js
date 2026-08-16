import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { ClaudeyError, ClaudexError } from '../../../src/core/errors.js';
import { Secret } from '../../../src/core/secrets.js';
import {
  createRuntimeStore,
  ensureGatewayHealthy,
  restartOwnedGateway,
  startOwnedGateway,
  stopOwnedGateway,
  verifyOwnedProcess
} from '../../../src/core/lifecycle.js';

const INSTALLATION_ID = '11111111-1111-4111-8111-111111111111';
const EXECUTABLE = Object.freeze({ kind: 'verified-fixture' });
const EXECUTABLE_PATH = 'C:\\Program Files\\Claudex\\CLIProxyAPI.exe';
const CONFIG_PATH = 'C:\\Users\\fixture\\Claudex\\config.yaml';
const TOKEN = () => Secret.fromBytes(Buffer.alloc(32, 7));
const READINESS_DOMAIN = 'claudeyctl-gateway-readiness-v1\0';

function authenticatedReadinessIdentity(record) {
  const binding = {};
  for (const key of [
    'schemaVersion', 'installationId', 'instanceId', 'pid', 'processGroupId', 'processStartTime',
    'executableCanonicalPath', 'configCanonicalPath', 'version', 'host', 'port', 'nonce'
  ]) binding[key] = record[key];
  return crypto.createHmac('sha256', Buffer.alloc(32, 7))
    .update(READINESS_DOMAIN, 'utf8').update(JSON.stringify(binding), 'utf8').digest('base64url');
}

function makeContext({ installed = false, graceful = true, requestFailures = 0, writeFails = false } = {}) {
  let current = installed ? null : null;
  let alive = false;
  let exited = false;
  let nowMs = Date.parse('2026-08-13T10:11:12.000Z');
  let requestCount = 0;
  let randomCount = 0;
  let spawnCount = 0;
  let captureCount = 0;
  let unboundCleanupCount = 0;
  const signals = [];
  const writes = [];
  const removals = [];
  const invocations = [];
  const exitAnswers = [];
  let treeMutation;
  const runtimeStore = {
    load: async () => current,
    write: async (record) => {
      writes.push(record);
      if (writeFails) throw Object.assign(new Error('disk full'), { code: 'ENOSPC' });
      current = record;
      return true;
    },
    remove: async () => { removals.push(current?.pid ?? null); current = null; return true; }
  };
  const processAdapter = {
    captureProcessTree: async () => {
      captureCount += 1;
      const identity = current ?? writes.at(-1);
      if (!alive || !identity) throw Object.assign(new Error('not found'), { code: 'ESRCH' });
      const tree = {
        complete: true,
        root: {
          pid: identity.pid, parentPid: 100, processGroupId: identity.processGroupId,
          processStartTime: identity.processStartTime, executableCanonicalPath: identity.executableCanonicalPath,
          configCanonicalPath: identity.configCanonicalPath, installationId: identity.installationId,
          instanceId: identity.instanceId, nonce: identity.nonce
        },
        descendants: [{
          pid: identity.pid + 1, parentPid: identity.pid, processGroupId: identity.processGroupId,
          processStartTime: '2026-08-13T10:11:12.500Z', executableCanonicalPath: 'C:\\Program Files\\Claudex\\worker.exe'
        }]
      };
      return treeMutation ? treeMutation(structuredClone(tree), captureCount) : tree;
    },
    signalTree: async (request) => {
      signals.push(structuredClone(request));
      if (!request.force && graceful) alive = false;
      if (request.force) alive = false;
      return { acknowledged: true };
    },
    waitForTreeExit: async () => exitAnswers.length ? exitAnswers.shift() : !alive
  };
  const ctx = {
    platform: 'win32', host: '127.0.0.1', port: 8317, token: TOKEN(), installationId: INSTALLATION_ID,
    version: '7.2.130', executable: EXECUTABLE, configCanonicalPath: CONFIG_PATH,
    runtimeStore, processAdapter,
    inspectListeners: async () => alive && current
      ? { state: 'listening', bindings: [{ host: '127.0.0.1', port: 8317, pid: current.pid, processStartTime: current.processStartTime }] }
      : { state: 'free' },
    revalidateExecutable: async (value) => value === EXECUTABLE,
    getInvocation: () => ({ executablePath: EXECUTABLE_PATH, argsPrefix: [] }),
    spawnGateway: async (invocation) => {
      spawnCount += 1;
      invocations.push(structuredClone(invocation));
      alive = true;
      return { pid: 3210, processGroupId: 3210, processStartTime: '2026-08-13T10:11:12.000Z' };
    },
    cleanupSpawnedChild: async () => { unboundCleanupCount += 1; alive = false; return true; },
    isChildExited: async () => exited,
    requestGatewayModels: async () => {
      requestCount += 1;
      if (requestCount <= requestFailures) throw new ClaudexError('GATEWAY_UNHEALTHY', 'not ready');
      return { object: 'list', data: [{ id: 'gpt-fixture', object: 'model', created: 1, owned_by: 'codex' }] };
    },
    randomUUID: () => '22222222-2222-4222-8222-222222222222',
    randomBytes: (size) => Buffer.alloc(size, 3 + randomCount++),
    now: () => new Date(nowMs).toISOString(),
    monotonicNow: () => nowMs,
    sleep: async (milliseconds) => { nowMs += milliseconds; },
    startupTimeoutMs: 100,
    pollIntervalMs: 25,
    gracefulTimeoutMs: 50,
    forceTimeoutMs: 50,
    baseEnvironment: { SystemRoot: 'C:\\Windows', TEMP: 'C:\\Temp', PATH: 'ATTACKER', MANAGEMENT_PASSWORD: 'SECRET_CANARY', ANTHROPIC_AUTH_TOKEN: 'SECRET_CANARY' }
  };
  if (installed) {
    current = {
      schemaVersion: 1, installationId: INSTALLATION_ID, instanceId: '22222222-2222-4222-8222-222222222222',
      pid: 3210, processGroupId: 3210, processStartTime: '2026-08-13T10:11:12.000Z',
      executableCanonicalPath: EXECUTABLE_PATH, configCanonicalPath: CONFIG_PATH, version: '7.2.130',
      host: '127.0.0.1', port: 8317, nonce: Buffer.alloc(32, 3).toString('base64url'),
      readinessIdentity: '', lastSuccessfulReadinessAt: '2026-08-13T10:11:13.000Z'
    };
    current.readinessIdentity = authenticatedReadinessIdentity(current);
    alive = true;
  }
  return {
    ctx, runtimeStore, processAdapter, signals, writes, removals, invocations, exitAnswers,
    get current() { return current; }, get alive() { return alive; }, get spawnCount() { return spawnCount; },
    get requestCount() { return requestCount; },
    get unboundCleanupCount() { return unboundCleanupCount; },
    set exited(value) { exited = value; }, set treeMutation(value) { treeMutation = value; },
    set signalResult(value) { processAdapter.signalTree = async (request) => { signals.push(structuredClone(request)); return value; }; }
  };
}

test('healthy readiness requires the exact owned listener, process tree, and authenticated models', async () => {
  const fixture = makeContext({ installed: true });
  const result = await ensureGatewayHealthy(fixture.ctx);
  assert.equal(result.state, 'healthy');
  assert.equal(await verifyOwnedProcess(fixture.current, fixture.processAdapter).then(() => true), true);
  fixture.ctx.requestGatewayModels = async () => { throw new ClaudexError('GATEWAY_UNHEALTHY', 'wrong bearer'); };
  await assert.rejects(ensureGatewayHealthy(fixture.ctx), (error) => error.code === 'GATEWAY_UNHEALTHY');
});

test('readiness rejects a forged runtime binding before sending the bearer', async () => {
  const fixture = makeContext({ installed: true });
  fixture.current.readinessIdentity = Buffer.alloc(32, 9).toString('base64url');
  await assert.rejects(ensureGatewayHealthy(fixture.ctx), (error) => error.code === 'PROCESS_IDENTITY_MISMATCH');
  assert.equal(fixture.requestCount, 0);
});

test('readiness refuses a validly authenticated runtime record that is not bound to the configured installation', async () => {
  for (const mutation of [
    { installationId: '33333333-3333-4333-8333-333333333333' },
    { version: '7.2.131' },
    { port: 9000 },
    { configCanonicalPath: 'C:\\Users\\fixture\\Claudex\\other.yaml' },
    { executableCanonicalPath: 'C:\\Program Files\\Claudex\\other.exe' }
  ]) {
    const fixture = makeContext({ installed: true });
    Object.assign(fixture.current, mutation);
    fixture.current.readinessIdentity = authenticatedReadinessIdentity(fixture.current);
    await assert.rejects(
      ensureGatewayHealthy(fixture.ctx),
      (error) => error.code === 'PROCESS_IDENTITY_MISMATCH',
      JSON.stringify(mutation)
    );
    assert.equal(fixture.requestCount, 0, JSON.stringify(mutation));
  }
});

test('readiness rechecks the exact listener and process identity after authenticated HTTP completes', async () => {
  const fixture = makeContext({ installed: true });
  let inspections = 0;
  fixture.ctx.inspectListeners = async () => {
    inspections += 1;
    const pid = inspections < 3 ? fixture.current.pid : 9000;
    return { state: 'listening', bindings: [{
      host: '127.0.0.1', port: 8317, pid, processStartTime: fixture.current.processStartTime
    }] };
  };
  await assert.rejects(ensureGatewayHealthy(fixture.ctx), (error) => error.code === 'PORT_IN_USE');
  assert.equal(fixture.requestCount, 1);
});

test('start is idempotent for an authenticated healthy owned process', async () => {
  const fixture = makeContext({ installed: true });
  const result = await startOwnedGateway(fixture.ctx);
  assert.equal(result.state, 'already-running');
  assert.equal(fixture.spawnCount, 0);
});

test('start spawns only the fixed verified executable and config with a scrubbed bounded invocation', async () => {
  const fixture = makeContext();
  const result = await startOwnedGateway(fixture.ctx);
  assert.equal(result.state, 'started');
  assert.equal(fixture.spawnCount, 1);
  assert.deepEqual(fixture.invocations[0].args, ['--config', CONFIG_PATH]);
  assert.equal(fixture.invocations[0].shell, false);
  assert.equal(fixture.invocations[0].foreground, false);
  assert.deepEqual(fixture.invocations[0].env, { SystemRoot: 'C:\\Windows', TEMP: 'C:\\Temp' });
  assert.equal(JSON.stringify(fixture.invocations[0]).includes('SECRET_CANARY'), false);
  assert.equal(fixture.writes.length, 2);
});

test('foreground uses the same owned readiness path without detached background mode', async () => {
  const fixture = makeContext();
  const result = await startOwnedGateway(fixture.ctx, { foreground: true });
  assert.equal(result.state, 'foreground');
  assert.equal(fixture.invocations[0].foreground, true);
  assert.equal(fixture.invocations[0].detached, false);
});

test('early child exit, startup timeout, cancellation, and record write failure leave no owned tree or runtime record', async () => {
  for (const scenario of ['early', 'timeout', 'cancel', 'write']) {
    const fixture = makeContext({ requestFailures: scenario === 'timeout' ? 99 : 0, writeFails: scenario === 'write' });
    const controller = new AbortController();
    if (scenario === 'early') fixture.exited = true;
    if (scenario === 'cancel') {
      fixture.ctx.requestGatewayModels = async () => { controller.abort(); throw new ClaudexError('GATEWAY_UNHEALTHY', 'cancel'); };
    }
    await assert.rejects(
      startOwnedGateway({ ...fixture.ctx, signal: controller.signal }),
      (error) => ['GATEWAY_UNHEALTHY', 'PROCESS_IDENTITY_MISMATCH'].includes(error.code),
      scenario
    );
    assert.equal(fixture.alive, false, scenario);
    assert.equal(fixture.current, null, scenario);
  }
});

test('malformed spawned identity is cleaned through its bound pre-record child capability', async () => {
  const fixture = makeContext();
  fixture.ctx.spawnGateway = async () => ({ pid: 0, processGroupId: 0, processStartTime: 'invalid' });
  await assert.rejects(startOwnedGateway(fixture.ctx), (error) => error.code === 'PROCESS_IDENTITY_MISMATCH');
  assert.equal(fixture.unboundCleanupCount, 1);
  assert.equal(fixture.alive, false);
  assert.equal(fixture.current, null);
});

test('failed start redacts injected error text from diagnostics and the public failure', async () => {
  const fixture = makeContext({ requestFailures: 99 });
  const diagnostics = [];
  fixture.ctx.requestGatewayModels = async () => {
    throw new ClaudexError('GATEWAY_UNHEALTHY', 'TASK8_SECRET_CANARY');
  };
  fixture.ctx.onLifecycleDiagnostic = (value) => diagnostics.push(value);
  await assert.rejects(startOwnedGateway(fixture.ctx), (error) => {
    assert.equal(`${error.message} ${JSON.stringify(error.details)}`.includes('TASK8_SECRET_CANARY'), false);
    return error.code === 'GATEWAY_UNHEALTHY';
  });
  assert.equal(JSON.stringify(diagnostics).includes('TASK8_SECRET_CANARY'), false);
  assert.equal(Object.hasOwn(diagnostics[0], 'stack'), false);
});

test('a throwing diagnostic observer cannot prevent failed-start tree cleanup', async () => {
  const fixture = makeContext({ requestFailures: 99 });
  fixture.ctx.onLifecycleDiagnostic = () => { throw new Error('observer failed'); };
  await assert.rejects(startOwnedGateway(fixture.ctx), (error) => error.code === 'GATEWAY_UNHEALTHY');
  assert.equal(fixture.alive, false);
  assert.equal(fixture.current, null);
});

test('a port ownership race fails without adopting the changed listener and cleans only the spawned tree', async () => {
  const fixture = makeContext();
  let inspections = 0;
  fixture.ctx.inspectListeners = async () => {
    inspections += 1;
    if (inspections < 3) return inspections === 1 ? { state: 'free' } : {
      state: 'listening', bindings: [{ host: '127.0.0.1', port: 8317, pid: fixture.current.pid, processStartTime: fixture.current.processStartTime }]
    };
    return { state: 'listening', bindings: [{ host: '127.0.0.1', port: 8317, pid: 9000, processStartTime: fixture.current.processStartTime }] };
  };
  await assert.rejects(startOwnedGateway(fixture.ctx), (error) => error.code === 'PORT_IN_USE' || error.code === 'GATEWAY_UNHEALTHY');
  assert.ok(fixture.signals.every((signal) => signal.pids.every((pid) => pid === 3210 || pid === 3211)));
});

test('stop twice is idempotent after one exact graceful tree termination', async () => {
  const fixture = makeContext({ installed: true });
  assert.equal((await stopOwnedGateway(fixture.ctx)).state, 'stopped');
  assert.equal((await stopOwnedGateway(fixture.ctx)).state, 'already-stopped');
  assert.deepEqual(fixture.signals.map((signal) => signal.force), [false]);
  assert.deepEqual(fixture.signals[0].pids, [3210, 3211]);
  assert.equal(fixture.current, null);
});

test('stop revalidates the unchanged exact tree before a bounded hard fallback', async () => {
  const fixture = makeContext({ installed: true, graceful: false });
  fixture.exitAnswers.push(false, true);
  await stopOwnedGateway(fixture.ctx);
  assert.deepEqual(fixture.signals.map((signal) => signal.force), [false, true]);
  assert.ok(fixture.signals.every((signal) => JSON.stringify(signal.pids) === '[3210,3211]'));
});

test('hard fallback targets only verified survivors when an owned descendant exits after graceful signaling', async () => {
  const fixture = makeContext({ installed: true, graceful: false });
  fixture.exitAnswers.push(false, true);
  fixture.treeMutation = (tree, captureCount) => captureCount >= 3 ? { ...tree, descendants: [] } : tree;
  await stopOwnedGateway(fixture.ctx);
  assert.deepEqual(fixture.signals.map(({ force, pids }) => ({ force, pids })), [
    { force: false, pids: [3210, 3211] },
    { force: true, pids: [3210] }
  ]);
});

test('tree changes or signal denial prevent force escalation and retain runtime evidence', async () => {
  const changed = makeContext({ installed: true, graceful: false });
  changed.exitAnswers.push(false);
  changed.treeMutation = (tree, captureCount) => captureCount >= 3
    ? { ...tree, descendants: [{ ...tree.descendants[0], pid: 9999 }] } : tree;
  await assert.rejects(stopOwnedGateway(changed.ctx), (error) => error.code === 'PROCESS_IDENTITY_MISMATCH');
  assert.deepEqual(changed.signals.map((signal) => signal.force), [false]);
  assert.notEqual(changed.current, null);

  const denied = makeContext({ installed: true });
  denied.signalResult = { acknowledged: false };
  await assert.rejects(stopOwnedGateway(denied.ctx), (error) => error.code === 'GATEWAY_UNHEALTHY');
  assert.notEqual(denied.current, null);
});

test('an unrelated listener blocks stop and restart without signaling anything', async () => {
  const fixture = makeContext({ installed: true });
  fixture.ctx.inspectListeners = async () => ({
    state: 'listening', bindings: [{ host: '127.0.0.1', port: 8317, pid: 9000, processStartTime: '2026-08-13T10:11:12.000Z' }]
  });
  await assert.rejects(stopOwnedGateway(fixture.ctx), (error) => error.code === 'PORT_IN_USE');
  await assert.rejects(restartOwnedGateway(fixture.ctx), (error) => error.code === 'PORT_IN_USE');
  assert.deepEqual(fixture.signals, []);
});

test('restart stops the exact owned instance before starting a new authenticated instance', async () => {
  const fixture = makeContext({ installed: true });
  const result = await restartOwnedGateway(fixture.ctx);
  assert.equal(result.state, 'started');
  assert.equal(fixture.spawnCount, 1);
  assert.deepEqual(fixture.signals.map((signal) => signal.force), [false]);
});

test('runtime load proves protection and exact file identity before and after reading bytes', async () => {
  const fixture = makeContext({ installed: true });
  const root = 'C:\\Users\\fixture\\Claudex';
  const target = `${root}\\gateway-runtime.json`;
  const events = [];
  let swapped = false;
  const entry = (directory, ino) => ({
    dev: 7n, ino: BigInt(ino), isDirectory: () => directory, isFile: () => !directory,
    isSymbolicLink: () => false, isReparsePoint: false
  });
  const fsApi = {
    realpath: async (value) => value,
    lstat: async (value) => value === root ? entry(true, 1) : entry(false, swapped ? 3 : 2),
    readFile: async (value) => {
      events.push(`read:${value}`);
      swapped = true;
      return Buffer.from(JSON.stringify(fixture.current), 'utf8');
    }
  };
  const store = createRuntimeStore({ root, platform: 'win32' }, {
    fsApi,
    assertProtected: async (value) => { events.push(`protected:${value}`); return true; },
    canonicalize: async (value) => value
  });
  await assert.rejects(store.load(), (error) => error.code === 'PROCESS_IDENTITY_MISMATCH');
  assert.equal(events[0], `protected:${target}`);

  const disappears = createRuntimeStore({ root, platform: 'win32' }, {
    fsApi: {
      realpath: async (value) => value,
      lstat: async (value) => value === root ? entry(true, 1) : entry(false, 2),
      readFile: async () => { throw Object.assign(new Error('gone'), { code: 'ENOENT' }); }
    },
    assertProtected: async () => true,
    canonicalize: async (value) => value
  });
  await assert.rejects(disappears.load(), (error) => error.code === 'PROCESS_IDENTITY_MISMATCH');
});

test('runtime removal refuses an identity swap and never calls pathname deletion', async () => {
  const root = 'C:\\Users\\fixture\\Claudex';
  const target = `${root}\\gateway-runtime.json`;
  let targetStats = 0;
  let removals = 0;
  const entry = (directory, ino) => ({
    dev: 7n, ino: BigInt(ino), isDirectory: () => directory, isFile: () => !directory,
    isSymbolicLink: () => false, isReparsePoint: false
  });
  const fsApi = {
    realpath: async (value) => value,
    lstat: async (value) => {
      if (value === root) return entry(true, 1);
      targetStats += 1;
      return entry(false, targetStats < 3 ? 2 : 3);
    },
    rm: async () => { removals += 1; }
  };
  const store = createRuntimeStore({ root, platform: 'win32' }, {
    fsApi,
    assertProtected: async (value) => value === target
  });
  await assert.rejects(store.remove(), (error) => error.code === 'PROCESS_IDENTITY_MISMATCH');
  assert.equal(removals, 0);
});

test('runtime write refuses success unless the exact protected record is readable afterward', async () => {
  const fixture = makeContext({ installed: true });
  const root = 'C:\\Users\\fixture\\Claudex';
  const missing = Object.assign(new Error('missing'), { code: 'ENOENT' });
  const fsApi = {
    realpath: async (value) => value,
    lstat: async (value) => {
      if (value === root) return { isDirectory: () => true, isSymbolicLink: () => false, isReparsePoint: false };
      throw missing;
    },
    readFile: async () => { throw missing; }
  };
  const store = createRuntimeStore({ root, platform: 'win32' }, {
    fsApi,
    atomicReplace: async () => true,
    assertProtected: async () => true,
    canonicalize: async (value) => value
  });
  await assert.rejects(store.write(fixture.current), (error) => error.code === 'PROCESS_IDENTITY_MISMATCH');
});
