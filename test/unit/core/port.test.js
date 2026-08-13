import assert from 'node:assert/strict';
import test from 'node:test';

import { createRuntimeRecord, isOwnedProcess } from '../../../src/core/process.js';
import { inspectPortOwnership } from '../../../src/core/port.js';

const installationId = '11111111-1111-4111-8111-111111111111';
const instanceId = '22222222-2222-4222-8222-222222222222';
const nonce = Buffer.alloc(32, 3).toString('base64url');

function runtime() {
  return createRuntimeRecord({
    schemaVersion: 1, installationId, instanceId, pid: 3210, processGroupId: 3210,
    processStartTime: '2026-08-13T10:11:12.000Z',
    executableCanonicalPath: 'C:\\Program Files\\Claudex\\CLIProxyAPI.exe',
    configCanonicalPath: 'C:\\Users\\fixture\\Claudex\\config.yaml', version: '7.2.130',
    host: '127.0.0.1', port: 8317, nonce,
    readinessIdentity: Buffer.alloc(32, 4).toString('base64url'),
    lastSuccessfulReadinessAt: '2026-08-13T10:11:13.000Z'
  }, { platform: 'win32' });
}

function tree() {
  return {
    complete: true,
    root: {
      pid: 3210, parentPid: 100, processGroupId: 3210, processStartTime: '2026-08-13T10:11:12.000Z',
      executableCanonicalPath: 'C:\\Program Files\\Claudex\\CLIProxyAPI.exe',
      configCanonicalPath: 'C:\\Users\\fixture\\Claudex\\config.yaml', installationId, instanceId, nonce
    },
    descendants: []
  };
}

function listener(binding) {
  return { state: 'listening', bindings: [binding] };
}

const ownedBinding = Object.freeze({ host: '127.0.0.1', port: 8317, pid: 3210, processStartTime: '2026-08-13T10:11:12.000Z' });

test('distinguishes a free exact loopback port without inspecting any process', async () => {
  let processInspected = false;
  const result = await inspectPortOwnership({ host: '127.0.0.1', port: 8317, runtimeRecord: null }, {
    inspectListeners: async () => ({ state: 'free' }),
    processAdapter: { captureProcessTree: async () => { processInspected = true; } }
  });
  assert.deepEqual(result, { state: 'free' });
  assert.equal(processInspected, false);
});

test('returns an exact owned listener only after listener and complete process identity remain stable', async () => {
  const result = await inspectPortOwnership({ host: '127.0.0.1', port: 8317, runtimeRecord: runtime() }, {
    inspectListeners: async () => listener(ownedBinding),
    processAdapter: { captureProcessTree: async () => tree() }
  });
  assert.equal(result.state, 'owned');
  assert.equal(isOwnedProcess(result.ownership), true);
});

test('refuses an unrelated exact listener without authenticating to, adopting, or inspecting its process', async () => {
  let inspected = false;
  let authenticated = false;
  await assert.rejects(
    inspectPortOwnership({ host: '127.0.0.1', port: 8317, runtimeRecord: runtime() }, {
      inspectListeners: async () => listener({ ...ownedBinding, pid: 9000 }),
      processAdapter: { captureProcessTree: async () => { inspected = true; return tree(); } },
      requestGatewayModels: async () => { authenticated = true; }
    }),
    (error) => error.code === 'PORT_IN_USE'
  );
  assert.equal(inspected, false);
  assert.equal(authenticated, false);
});

test('refuses wildcard, IPv6, non-loopback, multiple, malformed, and missing-identity listeners', async () => {
  const cases = [
    listener({ ...ownedBinding, host: '0.0.0.0' }),
    listener({ ...ownedBinding, host: '::1' }),
    listener({ ...ownedBinding, host: '192.0.2.1' }),
    { state: 'listening', bindings: [ownedBinding, { ...ownedBinding, host: '::1' }] },
    { state: 'listening', bindings: [{ host: '127.0.0.1', port: 8317 }] },
    { state: 'unknown' }
  ];
  for (const result of cases) {
    await assert.rejects(
      inspectPortOwnership({ host: '127.0.0.1', port: 8317, runtimeRecord: runtime() }, {
        inspectListeners: async () => result,
        processAdapter: { captureProcessTree: async () => tree() }
      }),
      (error) => error.code === 'PORT_IN_USE'
    );
  }
});

test('refuses non-loopback configuration before querying listener state', async () => {
  let queried = false;
  await assert.rejects(
    inspectPortOwnership({ host: 'localhost', port: 8317, runtimeRecord: runtime() }, { inspectListeners: async () => { queried = true; } }),
    (error) => error.code === 'PORT_IN_USE'
  );
  assert.equal(queried, false);
});

test('refuses ownership that changes between listener inspection and process verification', async () => {
  let call = 0;
  await assert.rejects(
    inspectPortOwnership({ host: '127.0.0.1', port: 8317, runtimeRecord: runtime() }, {
      inspectListeners: async () => ++call === 1 ? listener(ownedBinding) : listener({ ...ownedBinding, pid: 9000 }),
      processAdapter: { captureProcessTree: async () => tree() }
    }),
    (error) => error.code === 'PORT_IN_USE'
  );
});
