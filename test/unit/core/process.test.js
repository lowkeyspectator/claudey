import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  buildProcessHelperRequest,
  createRuntimeRecord,
  isOwnedProcess,
  parseProcessHelperResponse,
  parseRuntimeRecord,
  revalidateOwnedProcess,
  signalOwnedProcess,
  verifyProcessIdentity
} from '../../../src/core/process.js';

const INSTALLATION_ID = '11111111-1111-4111-8111-111111111111';
const INSTANCE_ID = '22222222-2222-4222-8222-222222222222';
const NONCE = Buffer.alloc(32, 3).toString('base64url');
const READINESS = Buffer.alloc(32, 4).toString('base64url');
const POWERSHELL_PATH = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const nativeCimProbe = process.platform === 'win32' ? spawnSync(POWERSHELL_PATH, [
  '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
  `$item = Get-CimInstance -ClassName Win32_Process -Filter 'ProcessId = ${process.pid}'; if ($null -eq $item) { exit 1 }`
], { encoding: 'utf8', timeout: 10_000 }) : null;
const nativeCimSkip = process.platform !== 'win32'
  ? 'Native Windows CIM inspection applies only on Windows.'
  : nativeCimProbe.status === 0 ? false : 'Native Windows CIM inspection is unavailable in this sandbox; fail-closed behavior remains covered.';


function record(overrides = {}) {
  return {
    schemaVersion: 1,
    installationId: INSTALLATION_ID,
    instanceId: INSTANCE_ID,
    pid: 3210,
    processGroupId: 3210,
    processStartTime: '2026-08-13T10:11:12.000Z',
    executableCanonicalPath: 'C:\\Program Files\\Claudey\\CLIProxyAPI.exe',
    configCanonicalPath: 'C:\\Users\\fixture\\Claudey\\config.yaml',
    version: '7.2.130',
    host: '127.0.0.1',
    port: 8317,
    nonce: NONCE,
    readinessIdentity: READINESS,
    lastSuccessfulReadinessAt: '2026-08-13T10:11:13.000Z',
    ...overrides
  };
}

function snapshot(overrides = {}) {
  return {
    complete: true,
    root: {
      pid: 3210,
      parentPid: 100,
      processGroupId: 3210,
      processStartTime: '2026-08-13T10:11:12.000Z',
      executableCanonicalPath: 'C:\\Program Files\\Claudey\\CLIProxyAPI.exe',
      configCanonicalPath: 'C:\\Users\\fixture\\Claudey\\config.yaml',
      installationId: INSTALLATION_ID,
      instanceId: INSTANCE_ID,
      nonce: NONCE
    },
    descendants: [{
      pid: 3211,
      parentPid: 3210,
      processGroupId: 3210,
      processStartTime: '2026-08-13T10:11:12.500Z',
      executableCanonicalPath: 'C:\\Program Files\\Claudey\\worker.exe'
    }],
    ...overrides
  };
}

function adapter(initial = snapshot()) {
  let current = structuredClone(initial);
  return {
    captureProcessTree: async () => structuredClone(current),
    replace(next) { current = structuredClone(next); }
  };
}

test('accepts only the exact closed runtime schema with bounded canonical identity fields', () => {
  const valid = createRuntimeRecord(record(), { platform: 'win32' });
  assert.deepEqual(valid, record());
  assert.equal(Object.isFrozen(valid), true);

  const invalid = [
    { extra: true }, { schemaVersion: 2 }, { installationId: 'not-uuid' }, { instanceId: 'not-uuid' },
    { pid: 0 }, { processGroupId: -1 }, { processStartTime: 'yesterday' },
    { executableCanonicalPath: 'CLIProxyAPI.exe' }, { configCanonicalPath: 'C:\\managed\\..\\config.yaml' },
    { version: 'v7.2.130' }, { host: 'localhost' }, { port: 80 }, { nonce: 'short' },
    { readinessIdentity: 'short' }, { lastSuccessfulReadinessAt: null }
  ];
  for (const mutation of invalid) {
    assert.throws(() => createRuntimeRecord(record(mutation), { platform: 'win32' }), (error) => error.code === 'PROCESS_IDENTITY_MISMATCH');
  }
  const missing = record();
  delete missing.nonce;
  assert.throws(() => createRuntimeRecord(missing, { platform: 'win32' }), (error) => error.code === 'PROCESS_IDENTITY_MISMATCH');
});

test('loads a runtime record only after protection and canonical paths are independently revalidated', async () => {
  const bytes = Buffer.from(JSON.stringify(record()), 'utf8');
  const calls = [];
  const loaded = await parseRuntimeRecord(bytes, {
    platform: 'win32',
    assertProtected: async () => { calls.push('protected'); return true; },
    canonicalize: async (value) => { calls.push(value); return value; }
  });
  assert.deepEqual(loaded, record());
  assert.equal(calls[0], 'protected');
  await assert.rejects(
    parseRuntimeRecord(bytes, { platform: 'win32', assertProtected: async () => false, canonicalize: async (value) => value }),
    (error) => error.code === 'PROCESS_IDENTITY_MISMATCH'
  );
  await assert.rejects(
    parseRuntimeRecord(bytes, { platform: 'win32', assertProtected: async () => true, canonicalize: async () => 'C:\\swapped\\target.exe' }),
    (error) => error.code === 'PROCESS_IDENTITY_MISMATCH'
  );
  await assert.rejects(
    parseRuntimeRecord(Buffer.from('{not-json'), { platform: 'win32', assertProtected: async () => true, canonicalize: async (value) => value }),
    (error) => error.code === 'PROCESS_IDENTITY_MISMATCH'
  );
});

test('creates ownership only after exact root and complete descendant identity match', async () => {
  const runtime = createRuntimeRecord(record(), { platform: 'win32' });
  const processAdapter = adapter();
  const ownership = await verifyProcessIdentity(runtime, processAdapter);
  assert.equal(isOwnedProcess(ownership), true);
  assert.deepEqual(ownership.pids, [3210, 3211]);
  assert.equal(await revalidateOwnedProcess(ownership), true);
  assert.equal(isOwnedProcess({ pids: [3210, 3211] }), false);
});

test('refuses stale PID reuse and every missing, forged, inaccessible, or swapped root identity field', async () => {
  const runtime = createRuntimeRecord(record(), { platform: 'win32' });
  const fields = [
    ['pid', 9999], ['processGroupId', 9999], ['processStartTime', '2026-08-13T10:11:13.000Z'],
    ['executableCanonicalPath', 'C:\\attacker\\CLIProxyAPI.exe'], ['configCanonicalPath', 'C:\\attacker\\config.yaml'],
    ['installationId', '33333333-3333-4333-8333-333333333333'],
    ['instanceId', '33333333-3333-4333-8333-333333333333'], ['nonce', Buffer.alloc(32, 5).toString('base64url')]
  ];
  for (const [field, value] of fields) {
    const bad = snapshot();
    bad.root[field] = value;
    await assert.rejects(verifyProcessIdentity(runtime, adapter(bad)), (error) => error.code === 'PROCESS_IDENTITY_MISMATCH', field);
  }
  await assert.rejects(
    verifyProcessIdentity(runtime, { captureProcessTree: async () => { throw Object.assign(new Error('denied'), { code: 'EACCES' }); } }),
    (error) => error.code === 'PROCESS_IDENTITY_MISMATCH'
  );
});

test('refuses incomplete, unknown, duplicate, cross-group, and unrelated descendant trees', async () => {
  const runtime = createRuntimeRecord(record(), { platform: 'win32' });
  const cases = [];
  cases.push({ ...snapshot(), complete: false });
  cases.push({ ...snapshot(), unknown: true });
  cases.push({ ...snapshot(), descendants: [...snapshot().descendants, snapshot().descendants[0]] });
  cases.push({ ...snapshot(), descendants: [{ ...snapshot().descendants[0], processGroupId: 7777 }] });
  cases.push({ ...snapshot(), descendants: [{ ...snapshot().descendants[0], parentPid: 8888 }] });
  cases.push({ ...snapshot(), descendants: [{ ...snapshot().descendants[0], executableCanonicalPath: '' }] });
  for (const tree of cases) {
    await assert.rejects(verifyProcessIdentity(runtime, adapter(tree)), (error) => error.code === 'PROCESS_IDENTITY_MISMATCH');
  }
});

test('revalidation refuses a descendant or path swap instead of authorizing a stale tree capability', async () => {
  const processAdapter = adapter();
  const ownership = await verifyProcessIdentity(createRuntimeRecord(record(), { platform: 'win32' }), processAdapter);
  processAdapter.replace({ ...snapshot(), descendants: [{ ...snapshot().descendants[0], pid: 4000 }] });
  await assert.rejects(revalidateOwnedProcess(ownership), (error) => error.code === 'PROCESS_IDENTITY_MISMATCH');
});

test('force signaling revalidates and targets an exact surviving descendant after the root exits', async () => {
  let rootPresent = true;
  const signals = [];
  const processAdapter = {
    captureProcessTree: async () => {
      if (!rootPresent) throw Object.assign(new Error('root exited'), { code: 'ESRCH' });
      return snapshot();
    },
    captureProcessSet: async (pids) => ({
      complete: true,
      requestedPids: [...pids],
      processes: [{
        pid: 3211,
        parentPid: 3210,
        processGroupId: 3210,
        processStartTime: '2026-08-13T10:11:12.500Z',
        executableCanonicalPath: 'C:\\Program Files\\Claudey\\worker.exe'
      }]
    }),
    signalTree: async (request) => { signals.push(structuredClone(request)); return { acknowledged: true }; }
  };
  const ownership = await verifyProcessIdentity(createRuntimeRecord(record(), { platform: 'win32' }), processAdapter);
  rootPresent = false;
  await signalOwnedProcess(ownership, { force: true });
  assert.deepEqual(signals, [{ pid: 3210, processGroupId: 3210, pids: [3211], force: true }]);
});

test('Windows helper protocol accepts PID-only operations and rejects broad or malformed responses', () => {
  assert.deepEqual(buildProcessHelperRequest({ requestId: INSTALLATION_ID, operation: 'inspectProcess', pid: 3210 }), {
    schemaVersion: 1, requestId: INSTALLATION_ID, operation: 'inspectProcess', pid: 3210
  });
  assert.deepEqual(buildProcessHelperRequest({ requestId: INSTALLATION_ID, operation: 'signalProcess', pid: 3210, force: true }), {
    schemaVersion: 1, requestId: INSTALLATION_ID, operation: 'signalProcess', pid: 3210, force: true
  });
  assert.throws(() => buildProcessHelperRequest({ requestId: INSTALLATION_ID, operation: 'signalProcess', pid: 3210, imageName: 'CLIProxyAPI.exe' }));
  const response = JSON.stringify({
    schemaVersion: 1, requestId: INSTALLATION_ID, ok: true,
    result: { pid: 3210, parentPid: 100, processStartTime: '2026-08-13T10:11:12.000Z', executableCanonicalPath: 'C:\\Program Files\\Claudey\\CLIProxyAPI.exe' }
  });
  assert.deepEqual(parseProcessHelperResponse(response, { requestId: INSTALLATION_ID, operation: 'inspectProcess', pid: 3210 }).pid, 3210);
  assert.throws(() => parseProcessHelperResponse(response.replace('3210', '3211'), { requestId: INSTALLATION_ID, operation: 'inspectProcess', pid: 3210 }));
  assert.throws(() => parseProcessHelperResponse(response.replace('C:\\\\Program Files\\\\Claudey\\\\CLIProxyAPI.exe', 'relative.exe'), { requestId: INSTALLATION_ID, operation: 'inspectProcess', pid: 3210 }));
  assert.throws(() => parseProcessHelperResponse(`${response}\nnoise`, { requestId: INSTALLATION_ID, operation: 'inspectProcess', pid: 3210 }));

  const descendants = JSON.stringify({
    schemaVersion: 1, requestId: INSTALLATION_ID, ok: true,
    result: {
      rootPid: 3210, complete: true, processes: [{
        pid: 3211, parentPid: 3210, processStartTime: '2026-08-13T10:11:12.500Z',
        executableCanonicalPath: 'C:\\Program Files\\Claudey\\worker.exe'
      }]
    }
  });
  assert.equal(parseProcessHelperResponse(descendants, {
    requestId: INSTALLATION_ID, operation: 'listDescendants', pid: 3210
  }).processes[0].pid, 3211);
  for (const mutation of [
    (value) => { value.result.processes[0].pid = 0; },
    (value) => { value.result.processes[0].processStartTime = 'invalid'; },
    (value) => { value.result.processes[0].executableCanonicalPath = 'relative.exe'; },
    (value) => { value.result.processes[0].extra = true; },
    (value) => { value.result.processes.push(structuredClone(value.result.processes[0])); }
  ]) {
    const value = JSON.parse(descendants);
    mutation(value);
    assert.throws(() => parseProcessHelperResponse(JSON.stringify(value), {
      requestId: INSTALLATION_ID, operation: 'listDescendants', pid: 3210
    }));
  }
  const signal = JSON.stringify({
    schemaVersion: 1, requestId: INSTALLATION_ID, ok: true,
    result: { pid: 3210, force: false, acknowledged: true, exitCode: 0 }
  });
  assert.throws(() => parseProcessHelperResponse(signal, {
    requestId: INSTALLATION_ID, operation: 'signalProcess', pid: 3210, force: true
  }));
  assert.throws(() => parseProcessHelperResponse(signal.replace('"exitCode":0', '"exitCode":5'), {
    requestId: INSTALLATION_ID, operation: 'signalProcess', pid: 3210, force: false
  }));
});

test('native Windows helper returns exact CIM identity for one PID without image-name targeting', { skip: nativeCimSkip }, () => {
  const powershell = POWERSHELL_PATH;
  const icacls = 'C:\\Windows\\System32\\icacls.exe';
  const helper = path.resolve('scripts/windows/process-helper.ps1');
  const directory = mkdtempSync(path.join(os.tmpdir(), 'claudeyctl-process-request-'));
  const requestPath = path.join(directory, 'request.json');
  const ownerSid = execFileSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'], { encoding: 'utf8' }).trim();
  try {
    execFileSync(icacls, [directory, '/inheritance:r', '/grant:r', `*${ownerSid}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F', '/q']);
    writeFileSync(requestPath, JSON.stringify(buildProcessHelperRequest({ requestId: INSTANCE_ID, operation: 'inspectProcess', pid: process.pid })), 'utf8');
    execFileSync(icacls, [requestPath, '/inheritance:r', '/grant:r', `*${ownerSid}:F`, '*S-1-5-18:F', '/q']);
    const result = spawnSync(powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helper, '-RequestPath', requestPath], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(result.status, 0, result.stdout);
    const identity = parseProcessHelperResponse(result.stdout, { requestId: INSTANCE_ID, operation: 'inspectProcess', pid: process.pid });
    assert.equal(identity.pid, process.pid);
    assert.equal(path.resolve(identity.executableCanonicalPath).toLowerCase(), path.resolve(process.execPath).toLowerCase());
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
