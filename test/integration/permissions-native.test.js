import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { assertWindowsDacl, runWindowsSecurityHelper } from '../../src/platform/windows-helpers.js';

const helperPath = path.resolve('scripts/windows/security-helper.ps1');

function invokeRawHelper(request) {
  return spawnSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helperPath
  ], { input: JSON.stringify(request), encoding: 'utf8' });
}

test('Windows helper inspects a private directory with one JSON response', { skip: process.platform !== 'win32' }, async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudexctl-dacl-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const currentUserSid = execFileSync('powershell.exe', [
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
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudexctl-dacl-protect-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const currentUserSid = execFileSync('powershell.exe', [
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
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudexctl-dacl-foreign-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const result = invokeRawHelper({
    schemaVersion: 1, requestId: '55555555-5555-4555-8555-555555555555', operation: 'inspect',
    path: root, expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
  });
  assert.notEqual(result.status, 0);
  assert.equal(JSON.parse(result.stdout).code, 'SAFETY_REFUSAL');
});

test('Windows helper refuses a junction before inspecting its target', { skip: process.platform !== 'win32' }, async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudexctl-dacl-reparse-'));
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'claudexctl-dacl-reparse-outside-'));
  t.after(async () => {
    await fs.rm(root, { recursive: true, force: true });
    await fs.rm(outside, { recursive: true, force: true });
  });
  const junction = path.join(root, 'junction');
  await fs.symlink(outside, junction, 'junction');
  const currentUserSid = execFileSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'
  ], { encoding: 'utf8' }).trim();
  const result = invokeRawHelper({
    schemaVersion: 1, requestId: '66666666-6666-4666-8666-666666666666', operation: 'inspect',
    path: junction, expectedType: 'directory', currentUserSid
  });
  assert.notEqual(result.status, 0);
  assert.equal(JSON.parse(result.stdout).code, 'SAFETY_REFUSAL');
});
