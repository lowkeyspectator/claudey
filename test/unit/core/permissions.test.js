import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import test from 'node:test';

import { assertProtected, atomicReplace } from '../../../src/core/permissions.js';
import { assertPosixProtection } from '../../../src/platform/posix.js';
import {
  assertWindowsDacl,
  buildSecurityHelperRequest,
  parseSecurityHelperResponse,
  runWindowsSecurityHelper
} from '../../../src/platform/windows-helpers.js';

async function tempRoot(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-permissions-'));
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
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-permissions-outside-'));
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
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-permissions-temp-outside-'));
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
    path: 'C:\\Users\\Casey\\AppData\\Local\\claudeyctl\\state',
    expectedType: 'directory',
    currentUserSid: 'S-1-5-21-1-2-3-4'
  });
  assert.deepEqual(JSON.parse(request), {
    schemaVersion: 1,
    requestId: '11111111-1111-4111-8111-111111111111',
    operation: 'inspect',
    path: 'C:\\Users\\Casey\\AppData\\Local\\claudeyctl\\state',
    expectedType: 'directory',
    currentUserSid: 'S-1-5-21-1-2-3-4'
  });

  const parsed = parseSecurityHelperResponse(JSON.stringify({
    ok: true,
    schemaVersion: 1,
    requestId: '11111111-1111-4111-8111-111111111111',
    result: {
      canonicalPath: 'C:\\Users\\Casey\\AppData\\Local\\claudeyctl\\state',
      type: 'directory',
      isReparsePoint: false,
      ownerSid: 'S-1-5-21-1-2-3-4',
      daclProtected: true,
      aces: [
        { type: 'allow', sid: 'S-1-5-21-1-2-3-4', rights: 'full-control', inherited: false, inheritanceFlags: 3, propagationFlags: 0 },
        { type: 'allow', sid: 'S-1-5-18', rights: 'full-control', inherited: false, inheritanceFlags: 3, propagationFlags: 0 }
      ]
    }
  }), { requestId: '11111111-1111-4111-8111-111111111111' });
  assert.equal(parsed.result.daclProtected, true);
  assert.equal(parsed.result.aces.length, 2);

  assert.throws(
    () => parseSecurityHelperResponse(`${request}\n${request}`, { requestId: '11111111-1111-4111-8111-111111111111' }),
    (error) => error?.code === 'CAPABILITY_UNSUPPORTED'
  );
});

test('rejects directory ACE propagation flags even with exact principals and rights', () => {
  const currentUserSid = 'S-1-5-21-1-2-3-4';
  assert.throws(() => assertWindowsDacl({
    canonicalPath: 'C:\\managed\\private',
    type: 'directory',
    isReparsePoint: false,
    ownerSid: currentUserSid,
    daclProtected: true,
    aces: [
      { type: 'allow', sid: currentUserSid, rights: 'full-control', inherited: false, inheritanceFlags: 3, propagationFlags: 1 },
      { type: 'allow', sid: 'S-1-5-18', rights: 'full-control', inherited: false, inheritanceFlags: 3, propagationFlags: 0 }
    ]
  }, {
    expectedType: 'directory', currentUserSid
  }), (error) => error?.code === 'SAFETY_REFUSAL');
});

function isDaclVerifier(args) {
  return args.includes('-File') && args[args.indexOf('-File') + 1].endsWith('request-dacl-helper.ps1');
}

function verifierResponse(args) {
  return successfulHelperResponse({
    requestId: args[args.indexOf('-RequestId') + 1],
    path: args[args.indexOf('-Path') + 1],
    expectedType: args[args.indexOf('-ExpectedType') + 1],
    currentUserSid: args[args.indexOf('-CurrentUserSid') + 1]
  });
}
function successfulHelperResponse(request) {
  return JSON.stringify({
    ok: true, schemaVersion: 1, requestId: request.requestId,
    result: {
      canonicalPath: request.path, type: request.expectedType, isReparsePoint: false,
      ownerSid: request.currentUserSid, daclProtected: true,
      aces: [
        { type: 'allow', sid: request.currentUserSid, rights: 'full-control', inherited: false, inheritanceFlags: request.expectedType === 'directory' ? 3 : 0, propagationFlags: 0 },
        { type: 'allow', sid: 'S-1-5-18', rights: 'full-control', inherited: false, inheritanceFlags: request.expectedType === 'directory' ? 3 : 0, propagationFlags: 0 }
      ]
    }
  });
}

test('uses only canonical fixed system executables and the bundled helper identity', async () => {
  const request = {
    requestId: '77777777-7777-4777-8777-777777777777', operation: 'inspect',
    path: 'C:\\managed\\state', expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
  };
  const launches = [];
  const response = await runWindowsSecurityHelper({
    request,
    helperPath: 'C:\\attacker\\System32\\WindowsPowerShell\\v1.0\\security-helper.ps1',
    powershellPath: 'D:\\attacker\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    icaclsPath: 'D:\\attacker\\System32\\icacls.exe',
    requestDirectory: 'C:\\attacker\\requests'
  }, {
    spawn: async (command, args, options) => {
      launches.push({ command, args, options });
      if (command.endsWith('\\icacls.exe')) return { code: 0, stdout: 'processed', stderr: '' };
      if (isDaclVerifier(args)) return { code: 0, stdout: verifierResponse(args), stderr: '' };
      const requestPath = args.at(-1);
      assert.deepEqual(JSON.parse(await fs.readFile(requestPath, 'utf8')), JSON.parse(buildSecurityHelperRequest(request)));
      return { code: 0, stderr: '', stdout: successfulHelperResponse(request) };
    }
  });
  assert.equal(response.ok, true);
  assert.equal(launches.length, 5);
  assert.equal(launches[0].command, 'C:\\Windows\\System32\\icacls.exe');
  assert.equal(launches[2].command, 'C:\\Windows\\System32\\icacls.exe');
  assert.equal(launches[4].command, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
  assert.deepEqual(launches[4].args.slice(0, -1), [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', path.resolve('scripts/windows/security-helper.ps1'), '-RequestPath'
  ]);
  assert.equal(launches[4].options.shell, false);
  assert.equal(launches[4].options.input, undefined);
  assert.notEqual(path.dirname(launches[4].args.at(-1)), 'C:\\attacker\\requests');
  await assert.rejects(() => fs.access(path.dirname(launches[4].args.at(-1))), { code: 'ENOENT' });
});

test('fails closed when either helper output stream exceeds its cap', async () => {
  await assert.rejects(() => runWindowsSecurityHelper({
    maxOutputBytes: 8,
    request: {
      requestId: '88888888-8888-4888-8888-888888888888', operation: 'inspect',
      path: 'C:\\managed\\state', expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
    }
  }, {
    spawn: async (command, args) => command.endsWith('\\icacls.exe')
      ? { code: 0, stdout: '', stderr: '' }
      : isDaclVerifier(args)
        ? { code: 0, stdout: verifierResponse(args), stderr: '' }
        : { code: 0, stdout: '{}', stderr: 'too much diagnostic output' }
  }), (error) => error?.code === 'CAPABILITY_UNSUPPORTED');
});
function fakeProtectedRun(request, extraDeps = {}) {
  return runWindowsSecurityHelper({ request, timeoutMs: 50 }, {
    spawn: async (command, args) => command.endsWith('\\icacls.exe')
      ? { code: 0, stdout: '', stderr: '' }
      : { code: 0, stdout: isDaclVerifier(args) ? verifierResponse(args) : successfulHelperResponse(request), stderr: '' },
    ...extraDeps
  });
}

test('assertProtected derives the bundled Windows helper without a caller path', async () => {
  const launches = [];
  const currentUserSid = 'S-1-5-21-1-2-3-4';
  const result = await assertProtected({
    target: 'C:\\managed\\state', type: 'directory', platform: 'win32', currentUserSid
  }, {
    spawn: async (command, args) => {
      launches.push({ command, args });
      if (command.endsWith('\\icacls.exe')) return { code: 0, stdout: '', stderr: '' };
      if (isDaclVerifier(args)) return { code: 0, stdout: verifierResponse(args), stderr: '' };
      const request = JSON.parse(await fs.readFile(args.at(-1), 'utf8'));
      return { code: 0, stdout: successfulHelperResponse(request), stderr: '' };
    }
  });
  assert.equal(result.ownerSid, currentUserSid);
  assert.equal(launches.at(-1).args.at(-3), path.resolve('scripts/windows/security-helper.ps1'));
});

test('fails closed and retains evidence when request cleanup encounters residue', async () => {
  const request = {
    requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', operation: 'inspect',
    path: 'C:\\managed\\state', expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
  };
  let directoryPath;
  await assert.rejects(() => fakeProtectedRun(request, {
    beforeCleanup: async (storage) => {
      directoryPath = storage.directoryPath;
      await fs.writeFile(path.join(directoryPath, 'unexpected.txt'), 'residue');
    }
  }), (error) => error?.code === 'SAFETY_REFUSAL');
  assert.equal(await fs.readFile(path.join(directoryPath, 'unexpected.txt'), 'utf8'), 'residue');
  await fs.rm(directoryPath, { recursive: true, force: true });
});

test('fails closed without deleting through a swapped request directory', async () => {
  const request = {
    requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', operation: 'inspect',
    path: 'C:\\managed\\state', expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
  };
  let originalDirectory;
  let replacementDirectory;
  await assert.rejects(() => fakeProtectedRun(request, {
    beforeCleanup: async ({ directoryPath }) => {
      replacementDirectory = directoryPath;
      originalDirectory = `${directoryPath}-original`;
      await fs.rename(directoryPath, originalDirectory);
      await fs.mkdir(replacementDirectory);
      await fs.writeFile(path.join(replacementDirectory, 'sentinel.txt'), 'replacement');
    }
  }), (error) => error?.code === 'SAFETY_REFUSAL');
  assert.equal(await fs.readFile(path.join(replacementDirectory, 'sentinel.txt'), 'utf8'), 'replacement');
  assert.equal(JSON.parse(await fs.readFile(path.join(originalDirectory, 'request.json'), 'utf8')).requestId, request.requestId);
  await fs.rm(originalDirectory, { recursive: true, force: true });
  await fs.rm(replacementDirectory, { recursive: true, force: true });
});

test('fails closed when deletion fails and confirms request residue remains', async () => {
  const request = {
    requestId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', operation: 'inspect',
    path: 'C:\\managed\\state', expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
  };
  let directoryPath;
  const fsApi = {
    ...fs,
    rm: async (target, options) => {
      if (path.basename(target) === 'request.json') {
        const error = new Error('simulated deletion failure');
        error.code = 'EACCES';
        throw error;
      }
      return fs.rm(target, options);
    }
  };
  await assert.rejects(() => fakeProtectedRun(request, {
    fsApi,
    beforeCleanup: ({ directoryPath: value }) => { directoryPath = value; }
  }), (error) => error?.code === 'SAFETY_REFUSAL');
  assert.equal(JSON.parse(await fs.readFile(path.join(directoryPath, 'request.json'), 'utf8')).requestId, request.requestId);
  await fs.rm(directoryPath, { recursive: true, force: true });
});

test('rejects a canonical executable identity mismatch before launching anything', async () => {
  const request = {
    requestId: 'ffffffff-ffff-4fff-8fff-ffffffffffff', operation: 'inspect',
    path: 'C:\\managed\\state', expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
  };
  let launches = 0;
  const fsApi = {
    ...fs,
    realpath: async (target) => target.toLowerCase().endsWith('\\powershell.exe')
      ? 'D:\\attacker\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
      : fs.realpath(target)
  };
  await assert.rejects(() => runWindowsSecurityHelper({ request }, {
    fsApi,
    spawn: async () => { launches += 1; return { code: 0, stdout: '', stderr: '' }; }
  }), (error) => error?.code === 'CAPABILITY_UNSUPPORTED');
  assert.equal(launches, 0);
});

test('timeout kills the child and waits for confirmed close before rejecting', async () => {
  const request = {
    requestId: '12121212-1212-4121-8121-121212121212', operation: 'inspect',
    path: 'C:\\managed\\state', expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
  };
  const events = [];
  let confirmClose;
  let reportKilled;
  const killed = new Promise((resolve) => { reportKilled = resolve; });
  const spawnChild = (command) => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = () => {
      events.push('kill');
      confirmClose = () => { events.push('close'); child.emit('close', 1); };
      reportKilled();
      return true;
    };
    if (command.endsWith('\\icacls.exe')) setImmediate(() => child.emit('close', 0));
    return child;
  };
  let settled = false;
  const outcome = runWindowsSecurityHelper({ request, timeoutMs: 20 }, { spawnChild });
  outcome.catch(() => { settled = true; });
  await killed;
  await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(settled, false);
  confirmClose();
  await assert.rejects(() => outcome,
    (error) => { events.push('rejected'); return error?.code === 'CAPABILITY_UNSUPPORTED'; });
  assert.deepEqual(events, ['kill', 'close', 'rejected']);
});
test('refuses a bundled helper that resolves through a reparse identity', async () => {
  const request = {
    requestId: '13131313-1313-4131-8131-131313131313', operation: 'inspect',
    path: 'C:\\managed\\state', expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
  };
  const expectedHelper = path.resolve('scripts/windows/security-helper.ps1').toLowerCase();
  let launches = 0;
  const fsApi = {
    ...fs,
    lstat: async (target) => {
      const stats = await fs.lstat(target);
      if (path.normalize(target).toLowerCase() !== expectedHelper) return stats;
      return {
        ...stats,
        isSymbolicLink: () => true,
        isFile: () => stats.isFile(),
        isDirectory: () => stats.isDirectory()
      };
    }
  };
  await assert.rejects(() => runWindowsSecurityHelper({ request }, {
    fsApi,
    spawn: async () => { launches += 1; return { code: 0, stdout: '', stderr: '' }; }
  }), (error) => error?.code === 'CAPABILITY_UNSUPPORTED');
  assert.equal(launches, 0);
});
test('cleans the exact dedicated directory when DACL bootstrap fails before request creation', async () => {
  const request = {
    requestId: '15151515-1515-4151-8151-151515151515', operation: 'inspect',
    path: 'C:\\managed\\state', expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
  };
  const listRequestDirectories = async () => new Set((await fs.readdir(os.tmpdir()))
    .filter((name) => name.startsWith('claudeyctl-security-')));
  const before = await listRequestDirectories();
  let extras = [];
  try {
    await assert.rejects(() => runWindowsSecurityHelper({ request }, {
      spawn: async (command) => command.endsWith('\\icacls.exe')
        ? { code: 1, stdout: '', stderr: '' }
        : { code: 0, stdout: successfulHelperResponse(request), stderr: '' }
    }), (error) => error?.code === 'CAPABILITY_UNSUPPORTED');
    const after = await listRequestDirectories();
    extras = [...after].filter((name) => !before.has(name));
    assert.deepEqual(extras, []);
  } finally {
    await Promise.all(extras.map((name) => fs.rm(path.join(os.tmpdir(), name), { recursive: true, force: true })));
  }
});
test('cleans the exact request file and directory when file DACL protection fails', async () => {
  const request = {
    requestId: '16161616-1616-4161-8161-161616161616', operation: 'inspect',
    path: 'C:\\managed\\state', expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
  };
  const listRequestDirectories = async () => new Set((await fs.readdir(os.tmpdir()))
    .filter((name) => name.startsWith('claudeyctl-security-')));
  const before = await listRequestDirectories();
  let icaclsCalls = 0;
  let extras = [];
  try {
    await assert.rejects(() => runWindowsSecurityHelper({ request }, {
      spawn: async (command, args) => {
        if (command.endsWith('\\icacls.exe')) {
          icaclsCalls += 1;
          return { code: icaclsCalls === 2 ? 1 : 0, stdout: '', stderr: '' };
        }
        return { code: 0, stdout: isDaclVerifier(args) ? verifierResponse(args) : successfulHelperResponse(request), stderr: '' };
      }
    }), (error) => error?.code === 'CAPABILITY_UNSUPPORTED');
    const after = await listRequestDirectories();
    extras = [...after].filter((name) => !before.has(name));
    assert.deepEqual(extras, []);
  } finally {
    await Promise.all(extras.map((name) => fs.rm(path.join(os.tmpdir(), name), { recursive: true, force: true })));
  }
});
test('escalates a timed-out child once and still rejects only after close', async () => {
  const request = {
    requestId: '17171717-1717-4171-8171-171717171717', operation: 'inspect',
    path: 'C:\\managed\\state', expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
  };
  const signals = [];
  const spawnChild = (command) => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    let fallbackClose;
    child.kill = (signal) => {
      signals.push(signal ?? 'TERM');
      if (signal === 'SIGKILL') {
        clearTimeout(fallbackClose);
        setImmediate(() => child.emit('close', 1));
      } else {
        fallbackClose = setTimeout(() => child.emit('close', 1), 500);
      }
      return true;
    };
    if (command.endsWith('\\icacls.exe')) setImmediate(() => child.emit('close', 0));
    return child;
  };
  await assert.rejects(() => runWindowsSecurityHelper({ request, timeoutMs: 20 }, { spawnChild }),
    (error) => error?.code === 'CAPABILITY_UNSUPPORTED');
  assert.deepEqual(signals, ['TERM', 'SIGKILL']);
});
test('bounds unconfirmed termination and retains protected request storage', async () => {
  const request = {
    requestId: '19191919-1919-4191-8191-191919191919', operation: 'inspect',
    path: 'C:\\managed\\state', expectedType: 'directory', currentUserSid: 'S-1-5-21-1-2-3-4'
  };
  const signals = [];
  let retainedDirectory;
  const spawnChild = (command, args) => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = (signal) => { signals.push(signal ?? 'TERM'); return true; };
    if (command.endsWith('\\icacls.exe')) {
      setImmediate(() => child.emit('close', 0));
    } else if (args.includes('-File') && args[args.indexOf('-File') + 1].endsWith('request-dacl-helper.ps1')) {
      const target = args[args.indexOf('-Path') + 1];
      const expectedType = args[args.indexOf('-ExpectedType') + 1];
      const currentUserSid = args[args.indexOf('-CurrentUserSid') + 1];
      const requestId = args[args.indexOf('-RequestId') + 1];
      child.stdout.end(successfulHelperResponse({ requestId, path: target, expectedType, currentUserSid }));
      setImmediate(() => child.emit('close', 0));
    } else {
      retainedDirectory = path.dirname(args.at(-1));
    }
    return child;
  };
  const outcome = runWindowsSecurityHelper({ request, timeoutMs: 20, terminationGraceMs: 20, terminationDeadlineMs: 40 }, { spawnChild });
  const bounded = Promise.race([
    outcome,
    new Promise((resolve) => setTimeout(() => resolve('UNBOUNDED'), 150))
  ]);
  try {
    await assert.rejects(() => bounded,
      (error) => error?.code === 'CAPABILITY_UNSUPPORTED' && error?.details?.requestStorageRetained === true);
    assert.deepEqual(signals, ['TERM', 'SIGKILL']);
    assert.equal(JSON.parse(await fs.readFile(path.join(retainedDirectory, 'request.json'), 'utf8')).requestId, request.requestId);
  } finally {
    if (retainedDirectory) await fs.rm(retainedDirectory, { recursive: true, force: true });
  }
});
