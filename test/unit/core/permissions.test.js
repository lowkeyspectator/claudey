import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { assertProtected, atomicReplace } from '../../../src/core/permissions.js';
import { assertPosixProtection } from '../../../src/platform/posix.js';
import {
  buildSecurityHelperRequest,
  parseSecurityHelperResponse,
  runWindowsSecurityHelper
} from '../../../src/platform/windows-helpers.js';

async function tempRoot(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudexctl-permissions-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

test('atomically replaces an owned file with the requested protected mode', async (t) => {
  const root = await tempRoot(t);
  await fs.mkdir(path.join(root, 'state'));
  const target = path.join(root, 'state', 'config.json');
  await fs.writeFile(target, 'old', { mode: 0o600 });

  await atomicReplace({ root, child: path.join('state', 'config.json'), bytes: Buffer.from('new'), mode: 0o600 });

  assert.equal(await fs.readFile(target, 'utf8'), 'new');
  if (process.platform !== 'win32') {
    assert.equal((await fs.lstat(target)).mode & 0o777, 0o600);
  }
});

test('rejects a link swap before rename without writing outside the managed root', async (t) => {
  const root = await tempRoot(t);
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'claudexctl-permissions-outside-'));
  t.after(() => fs.rm(outside, { recursive: true, force: true }));
  await fs.mkdir(path.join(root, 'state'));
  const outsideTarget = path.join(outside, 'config.json');
  await fs.writeFile(outsideTarget, 'outside');
  let linkAvailable = true;

  await assert.rejects(
    () => atomicReplace(
      { root, child: path.join('state', 'config.json'), bytes: Buffer.from('new'), mode: 0o600 },
      {
        beforeFinalRecheck: async () => {
          try {
            await fs.rm(path.join(root, 'state'), { recursive: true, force: true });
            await fs.symlink(outside, path.join(root, 'state'), process.platform === 'win32' ? 'junction' : 'dir');
          } catch (error) {
            if (error.code === 'EPERM' || error.code === 'EACCES') {
              linkAvailable = false;
              throw error;
            }
            throw error;
          }
        }
      }
    ),
    (error) => linkAvailable ? error?.code === 'SAFETY_REFUSAL' : ['EPERM', 'EACCES'].includes(error?.code)
  );
  assert.equal(await fs.readFile(outsideTarget, 'utf8'), 'outside');
});

test('rejects a staged temporary file that becomes a link before activation', async (t) => {
  const root = await tempRoot(t);
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'claudexctl-permissions-temp-outside-'));
  t.after(() => fs.rm(outside, { recursive: true, force: true }));
  await fs.mkdir(path.join(root, 'state'));
  const outsideTarget = path.join(outside, 'config.json');
  await fs.writeFile(outsideTarget, 'outside');
  let linkAvailable = true;

  await assert.rejects(
    () => atomicReplace(
      { root, child: path.join('state', 'config.json'), bytes: Buffer.from('new'), mode: 0o600 },
      {
        beforeFinalRecheck: async ({ temporary }) => {
          try {
            await fs.rm(temporary, { force: true });
            await fs.symlink(outsideTarget, temporary, 'file');
          } catch (error) {
            if (error.code === 'EPERM' || error.code === 'EACCES') {
              linkAvailable = false;
              throw error;
            }
            throw error;
          }
        }
      }
    ),
    (error) => linkAvailable ? error?.code === 'SAFETY_REFUSAL' : ['EPERM', 'EACCES'].includes(error?.code)
  );
  assert.equal(await fs.readFile(outsideTarget, 'utf8'), 'outside');
});

test('rejects permissive POSIX secret modes', async (t) => {
  const root = await tempRoot(t);
  const target = path.join(root, 'secret');
  await fs.writeFile(target, 'secret', { mode: 0o644 });
  if (process.platform === 'win32') {
    await assert.rejects(
      () => assertProtected({ target, type: 'file', mode: 0o600, platform: 'posix' }),
      (error) => error?.code === 'SAFETY_REFUSAL'
    );
    return;
  }
  await assert.rejects(
    () => assertPosixProtection({ target, type: 'file', mode: 0o600 }),
    (error) => error?.code === 'SAFETY_REFUSAL'
  );
});

test('builds and parses the strict schema-1 Windows helper protocol', async () => {
  const request = buildSecurityHelperRequest({
    requestId: '11111111-1111-4111-8111-111111111111',
    operation: 'inspect',
    path: 'C:\\Users\\Casey\\AppData\\Local\\claudexctl\\state',
    expectedType: 'directory',
    currentUserSid: 'S-1-5-21-1-2-3-4'
  });
  assert.deepEqual(JSON.parse(request), {
    schemaVersion: 1,
    requestId: '11111111-1111-4111-8111-111111111111',
    operation: 'inspect',
    path: 'C:\\Users\\Casey\\AppData\\Local\\claudexctl\\state',
    expectedType: 'directory',
    currentUserSid: 'S-1-5-21-1-2-3-4'
  });

  const parsed = parseSecurityHelperResponse(JSON.stringify({
    ok: true,
    schemaVersion: 1,
    requestId: '11111111-1111-4111-8111-111111111111',
    result: {
      canonicalPath: 'C:\\Users\\Casey\\AppData\\Local\\claudexctl\\state',
      type: 'directory',
      isReparsePoint: false,
      ownerSid: 'S-1-5-21-1-2-3-4',
      daclProtected: true,
      aces: [
        { type: 'allow', sid: 'S-1-5-21-1-2-3-4', rights: 'full-control', inherited: false },
        { type: 'allow', sid: 'S-1-5-18', rights: 'full-control', inherited: false }
      ]
    }
  }), { requestId: '11111111-1111-4111-8111-111111111111' });
  assert.equal(parsed.result.daclProtected, true);
  assert.equal(parsed.result.aces.length, 2);

  assert.throws(
    () => parseSecurityHelperResponse(`${request}\n${request}`, { requestId: '11111111-1111-4111-8111-111111111111' }),
    (error) => error?.code === 'SAFETY_REFUSAL'
  );
});

test('rejects unexpected Windows helper output after a fixed no-stdin invocation', async (t) => {
  const root = await tempRoot(t);
  const launches = [];
  await assert.rejects(
    () => runWindowsSecurityHelper({
      helperPath: 'C:\\managed\\security-helper.ps1', requestDirectory: root,
      powershellPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      request: {
        requestId: '11111111-1111-4111-8111-111111111111', operation: 'inspect',
        path: 'C:\\managed\\state', expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
      },
      spawn: async (command, args, options) => {
        launches.push({ command, args, options });
        return { code: 0, stdout: '{}\nnoise', stderr: '' };
      }
    }),
    (error) => error?.code === 'SAFETY_REFUSAL'
  );
  assert.equal(launches.length, 1);
  assert.equal(launches[0].command, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
  assert.deepEqual(launches[0].args.slice(0, -1), [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', 'C:\\managed\\security-helper.ps1', '-RequestPath'
  ]);
  assert.equal(launches[0].options.input, undefined);
  assert.equal(launches[0].options.shell, false);
  assert.equal(launches[0].options.windowsHide, true);
});
test('writes one private request file, passes its path, and removes it after the helper exits', async (t) => {
  const root = await tempRoot(t);
  const request = {
    requestId: '77777777-7777-4777-8777-777777777777', operation: 'inspect',
    path: 'C:\\managed\\state', expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
  };
  let requestPath;
  const response = await runWindowsSecurityHelper({
    helperPath: 'C:\\managed\\security-helper.ps1', request, requestDirectory: root,
    powershellPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    spawn: async (command, args, options) => {
      requestPath = args.at(-1);
      assert.equal(command, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
      assert.deepEqual(args.slice(0, -1), [
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', 'C:\\managed\\security-helper.ps1', '-RequestPath'
      ]);
      assert.equal(options.input, undefined);
      assert.deepEqual(JSON.parse(await fs.readFile(requestPath, 'utf8')), JSON.parse(buildSecurityHelperRequest(request)));
      return { code: 0, stderr: '', stdout: JSON.stringify({
        ok: true, schemaVersion: 1, requestId: request.requestId,
        result: {
          canonicalPath: request.path, type: 'directory', isReparsePoint: false,
          ownerSid: request.currentUserSid, daclProtected: true,
          aces: [
            { type: 'allow', sid: request.currentUserSid, rights: 'full-control', inherited: false },
            { type: 'allow', sid: 'S-1-5-18', rights: 'full-control', inherited: false }
          ]
        }
      }) };
    }
  });
  assert.equal(response.ok, true);
  assert.equal(path.dirname(requestPath), root);
  await assert.rejects(() => fs.access(requestPath), { code: 'ENOENT' });
});
test('fails closed when either helper output stream exceeds its cap', async (t) => {
  const root = await tempRoot(t);
  await assert.rejects(() => runWindowsSecurityHelper({
    helperPath: 'C:\\managed\\security-helper.ps1', requestDirectory: root,
    powershellPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    maxOutputBytes: 8,
    request: {
      requestId: '88888888-8888-4888-8888-888888888888', operation: 'inspect',
      path: 'C:\\managed\\state', expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
    },
    spawn: async () => ({ code: 0, stdout: '{}', stderr: 'too much diagnostic output' })
  }), (error) => error?.code === 'SAFETY_REFUSAL');
});