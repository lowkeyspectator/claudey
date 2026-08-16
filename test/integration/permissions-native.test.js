import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { assertWindowsDacl, runWindowsSecurityHelper } from '../../src/platform/windows-helpers.js';

const helperPath = path.resolve('scripts/windows/security-helper.ps1');
const powershellPath = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const icaclsPath = 'C:\\Windows\\System32\\icacls.exe';

function invokeRawHelper(request) {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'claudeyctl-request-'));
  const requestPath = path.join(directory, 'request.json');
  const ownerSid = execFileSync(powershellPath, [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'
  ], { encoding: 'utf8' }).trim();
  execFileSync(icaclsPath, [directory, '/inheritance:r', '/grant:r', `*${ownerSid}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F', '/q']);
  writeFileSync(requestPath, JSON.stringify(request), { encoding: 'utf8' });
  execFileSync(icaclsPath, [requestPath, '/inheritance:r', '/grant:r', `*${ownerSid}:F`, '*S-1-5-18:F', '/q']);
  try {
    return spawnSync(powershellPath, [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helperPath, '-RequestPath', requestPath
    ], { encoding: 'utf8' });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('Windows helper inspects a private directory with one JSON response', { skip: process.platform !== 'win32' }, async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-dacl-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const currentUserSid = execFileSync(powershellPath, [
    '-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'
  ], { encoding: 'utf8' }).trim();

  const result = await runWindowsSecurityHelper({
    helperPath,
    request: {
      requestId: '22222222-2222-4222-8222-222222222222', operation: 'inspect', path: root,
      expectedType: 'directory', currentUserSid
    }
  });
  assert.equal(result.ok, true);
  assert.equal(result.result.type, 'directory');
  assert.equal(result.result.isReparsePoint, false);
});

test('Windows helper protects a private directory with exactly the owner and LocalSystem ACEs', { skip: process.platform !== 'win32' }, async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-dacl-protect-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const currentUserSid = execFileSync(powershellPath, [
    '-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'
  ], { encoding: 'utf8' }).trim();

  const result = await runWindowsSecurityHelper({
    helperPath,
    request: {
      requestId: '33333333-3333-4333-8333-333333333333', operation: 'protect', path: root,
      expectedType: 'directory', currentUserSid
    }
  });
  assertWindowsDacl(result.result, { expectedType: 'directory', currentUserSid });
});

test('Windows helper refuses a direct relative managed path before inspecting it', { skip: process.platform !== 'win32' }, () => {
  const result = invokeRawHelper({
    schemaVersion: 1, requestId: '44444444-4444-4444-8444-444444444444', operation: 'inspect',
    path: '.', expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
  });
  assert.notEqual(result.status, 0);
  assert.equal(JSON.parse(result.stdout).code, 'SAFETY_REFUSAL');
});

test('Windows helper refuses a direct request that names a foreign user SID', { skip: process.platform !== 'win32' }, async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-dacl-foreign-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const result = invokeRawHelper({
    schemaVersion: 1, requestId: '55555555-5555-4555-8555-555555555555', operation: 'inspect',
    path: root, expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
  });
  assert.notEqual(result.status, 0);
  assert.equal(JSON.parse(result.stdout).code, 'SAFETY_REFUSAL');
});

test('Windows helper refuses a junction before inspecting its target', { skip: process.platform !== 'win32' }, async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-dacl-reparse-'));
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-dacl-reparse-outside-'));
  t.after(async () => {
    await fs.rm(root, { recursive: true, force: true });
    await fs.rm(outside, { recursive: true, force: true });
  });
  const junction = path.join(root, 'junction');
  await fs.symlink(outside, junction, 'junction');
  const currentUserSid = execFileSync(powershellPath, [
    '-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'
  ], { encoding: 'utf8' }).trim();
  const result = invokeRawHelper({
    schemaVersion: 1, requestId: '66666666-6666-4666-8666-666666666666', operation: 'inspect',
    path: junction, expectedType: 'directory', currentUserSid
  });
  assert.notEqual(result.status, 0);
  assert.equal(JSON.parse(result.stdout).code, 'SAFETY_REFUSAL');
});

test('Windows helper refuses a reparse-point ancestor without following it', { skip: process.platform !== 'win32' }, async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-dacl-ancestor-'));
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-dacl-ancestor-outside-'));
  t.after(async () => { await fs.rm(root, { recursive: true, force: true }); await fs.rm(outside, { recursive: true, force: true }); });
  await fs.writeFile(path.join(outside, 'child.txt'), 'outside');
  const ancestor = path.join(root, 'ancestor');
  await fs.symlink(outside, ancestor, 'junction');
  const currentUserSid = execFileSync(powershellPath, ['-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'], { encoding: 'utf8' }).trim();
  const result = invokeRawHelper({ schemaVersion: 1, requestId: '99999999-9999-4999-8999-999999999999', operation: 'inspect', path: path.join(ancestor, 'child.txt'), expectedType: 'file', currentUserSid });
  assert.notEqual(result.status, 0);
  assert.equal(JSON.parse(result.stdout).code, 'SAFETY_REFUSAL');
});

test('Windows helper stdout is a single UTF-8 JSON object', { skip: process.platform !== 'win32' }, async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-dacl-utf8-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const currentUserSid = execFileSync(powershellPath, ['-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'], { encoding: 'utf8' }).trim();
  const result = invokeRawHelper({ schemaVersion: 1, requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', operation: 'inspect', path: root, expectedType: 'directory', currentUserSid });
  assert.equal(result.stderr, '');
  assert.equal(result.stdout.includes('\n'), false);
  assert.equal(JSON.parse(Buffer.from(result.stdout, 'utf8').toString('utf8')).ok, true);
});
test('Windows helper refuses an unprotected request file before reading valid content', { skip: process.platform !== 'win32' }, async (t) => {
  const target = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-dacl-unprotected-target-'));
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-dacl-unprotected-request-'));
  t.after(async () => { await fs.rm(target, { recursive: true, force: true }); await fs.rm(directory, { recursive: true, force: true }); });
  const requestPath = path.join(directory, 'request.json');
  const currentUserSid = execFileSync('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'
  ], { encoding: 'utf8' }).trim();
  await fs.writeFile(requestPath, JSON.stringify({
    schemaVersion: 1, requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', operation: 'inspect',
    path: target, expectedType: 'directory', currentUserSid
  }));
  const result = spawnSync(powershellPath, [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', helperPath, '-RequestPath', requestPath
  ], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.equal(result.stderr, '');
  assert.equal(result.stdout.includes('\n'), false);
  assert.equal(JSON.parse(result.stdout).code, 'SAFETY_REFUSAL');
});

test('Windows helper emits one UTF-8 JSON error for unsafe RequestPath before parsing', { skip: process.platform !== 'win32' }, () => {
  const result = spawnSync(powershellPath, [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', helperPath, '-RequestPath', '.'
  ], { encoding: 'buffer' });
  const stdout = result.stdout.toString('utf8');
  assert.notEqual(result.status, 0);
  assert.equal(result.stderr.length, 0);
  assert.equal(stdout.includes('\n'), false);
  assert.deepEqual(Object.keys(JSON.parse(stdout)).sort(), ['code', 'message', 'ok', 'requestId', 'schemaVersion']);
});
test('Windows helper refuses a protected request file with a foreign Everyone ACE', { skip: process.platform !== 'win32' }, async (t) => {
  const target = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-dacl-foreign-ace-target-'));
  const directory = mkdtempSync(path.join(os.tmpdir(), 'claudeyctl-dacl-foreign-ace-request-'));
  t.after(async () => { await fs.rm(target, { recursive: true, force: true }); rmSync(directory, { recursive: true, force: true }); });
  const requestPath = path.join(directory, 'request.json');
  const ownerSid = execFileSync(powershellPath, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'], { encoding: 'utf8' }).trim();
  execFileSync(icaclsPath, [directory, '/inheritance:r', '/grant:r', `*${ownerSid}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F', '/q']);
  writeFileSync(requestPath, JSON.stringify({
    schemaVersion: 1, requestId: '14141414-1414-4141-8141-141414141414', operation: 'inspect',
    path: target, expectedType: 'directory', currentUserSid: ownerSid
  }), { encoding: 'utf8' });
  execFileSync(icaclsPath, [requestPath, '/inheritance:r', '/grant:r', `*${ownerSid}:F`, '*S-1-5-18:F', '*S-1-1-0:R', '/q']);
  const result = spawnSync(powershellPath, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helperPath, '-RequestPath', requestPath], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.equal(JSON.parse(result.stdout).code, 'SAFETY_REFUSAL');
});

test('Windows helper emits one UTF-8 JSON error for malformed protected request JSON', { skip: process.platform !== 'win32' }, () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'claudeyctl-dacl-malformed-request-'));
  const requestPath = path.join(directory, 'request.json');
  const ownerSid = execFileSync(powershellPath, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'], { encoding: 'utf8' }).trim();
  execFileSync(icaclsPath, [directory, '/inheritance:r', '/grant:r', `*${ownerSid}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F', '/q']);
  writeFileSync(requestPath, '{not-json', { encoding: 'utf8' });
  execFileSync(icaclsPath, [requestPath, '/inheritance:r', '/grant:r', `*${ownerSid}:F`, '*S-1-5-18:F', '/q']);
  try {
    const result = spawnSync(powershellPath, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helperPath, '-RequestPath', requestPath], { encoding: 'buffer' });
    const stdout = result.stdout.toString('utf8');
    assert.notEqual(result.status, 0);
    assert.equal(result.stderr.length, 0);
    assert.equal(stdout.includes('\n'), false);
    assert.equal(JSON.parse(stdout).requestId, '');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('Windows helper refuses request directory ACE propagation flags before reading valid content', { skip: process.platform !== 'win32' }, async (t) => {
  const target = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-dacl-propagation-target-'));
  const directory = mkdtempSync(path.join(os.tmpdir(), 'claudeyctl-dacl-propagation-request-'));
  t.after(async () => { await fs.rm(target, { recursive: true, force: true }); rmSync(directory, { recursive: true, force: true }); });
  const requestPath = path.join(directory, 'request.json');
  const ownerSid = execFileSync(powershellPath, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'], { encoding: 'utf8' }).trim();
  execFileSync(icaclsPath, [directory, '/inheritance:r', '/grant:r', `*${ownerSid}:(OI)(CI)(NP)F`, '*S-1-5-18:(OI)(CI)(NP)F', '/q']);
  writeFileSync(requestPath, JSON.stringify({
    schemaVersion: 1, requestId: '21212121-2121-4121-8121-212121212121', operation: 'inspect',
    path: target, expectedType: 'directory', currentUserSid: ownerSid
  }), { encoding: 'utf8' });
  execFileSync(icaclsPath, [requestPath, '/inheritance:r', '/grant:r', `*${ownerSid}:F`, '*S-1-5-18:F', '/q']);
  const result = spawnSync(powershellPath, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helperPath, '-RequestPath', requestPath], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.equal(JSON.parse(result.stdout).code, 'SAFETY_REFUSAL');
});
test('adapter rejects a retained foreign directory ACE before writing request.json', { skip: process.platform !== 'win32' }, async () => {
  const target = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-dacl-prewrite-target-'));
  const ownerSid = execFileSync(powershellPath, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'], { encoding: 'utf8' }).trim();
  let requestWasAbsent = false;
  try {
    await assert.rejects(() => runWindowsSecurityHelper({
      request: {
        requestId: '18181818-1818-4181-8181-181818181818', operation: 'inspect',
        path: target, expectedType: 'directory', currentUserSid: ownerSid
      }
    }, {
      afterDirectoryProtection: async ({ directoryPath }) => {
        execFileSync(icaclsPath, [directoryPath, '/grant', '*S-1-1-0:R', '/q']);
      },
      beforeCleanup: async ({ directoryPath }) => {
        await assert.rejects(() => fs.access(path.join(directoryPath, 'request.json')), { code: 'ENOENT' });
        requestWasAbsent = true;
      }
    }), (error) => error?.code === 'SAFETY_REFUSAL');
    assert.equal(requestWasAbsent, true);
  } finally {
    await fs.rm(target, { recursive: true, force: true });
  }
});

test('adapter rejects directory ACEs without object inheritance before writing request.json', { skip: process.platform !== 'win32' }, async () => {
  const target = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-dacl-prewrite-inheritance-target-'));
  const ownerSid = execFileSync(powershellPath, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'], { encoding: 'utf8' }).trim();
  let requestWasAbsent = false;
  try {
    await assert.rejects(() => runWindowsSecurityHelper({
      request: {
        requestId: '20202020-2020-4020-8020-202020202020', operation: 'inspect',
        path: target, expectedType: 'directory', currentUserSid: ownerSid
      }
    }, {
      afterDirectoryProtection: async ({ directoryPath }) => {
        execFileSync(icaclsPath, [directoryPath, '/remove:g', `*${ownerSid}`, '*S-1-5-18', '/q']);
        execFileSync(icaclsPath, [directoryPath, '/grant', `*${ownerSid}:(CI)F`, '*S-1-5-18:(CI)F', '/q']);
      },
      beforeCleanup: async ({ directoryPath }) => {
        await assert.rejects(() => fs.access(path.join(directoryPath, 'request.json')), { code: 'ENOENT' });
        requestWasAbsent = true;
      }
    }), (error) => error?.code === 'SAFETY_REFUSAL');
    assert.equal(requestWasAbsent, true);
  } finally {
    await fs.rm(target, { recursive: true, force: true });
  }
});
