import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import test, { after } from 'node:test';

import { resolveVerifiedExecutable } from '../../../src/core/executable.js';
import { assessPrerequisites } from '../../../src/core/prerequisites.js';

const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudey-prerequisites-'));
after(() => fs.rm(root, { recursive: true, force: true }));

function tagged(stats, tag = 0) { Object.defineProperty(stats, 'reparseTag', { value: tag, configurable: true }); return stats; }
function adapter() {
  return {
    realpath: async (value) => { try { return await fs.realpath(value); } catch (error) { if (error?.code === 'EPERM') return value; throw error; } },
    lstat: async (value) => tagged(await fs.lstat(value)),
    stat: async (value) => tagged(await fs.stat(value)),
    openNoFollow: async (value) => {
      const before = tagged(await fs.lstat(value));
      if (before.isSymbolicLink()) throw new Error('link');
      const handle = await fs.open(value, 'r');
      return { noFollow: true, read: handle.read.bind(handle), close: handle.close.bind(handle), stat: async () => tagged(await handle.stat()) };
    }
  };
}

async function windowsFixtures() {
  const windowsRoot = path.join(root, 'AltWindows');
  const systemDirectory = path.join(windowsRoot, 'SysNative');
  const powershellPath = path.join(systemDirectory, 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const taskkillPath = path.join(systemDirectory, 'taskkill.exe');
  const gitPath = path.join(root, 'Git', 'git.exe');
  for (const target of [powershellPath, taskkillPath, gitPath]) { await fs.mkdir(path.dirname(target), { recursive: true }); await fs.copyFile(process.execPath, target); }
  const fsAdapter = adapter();
  return {
    systemDirectory,
    powerShell: await resolveVerifiedExecutable({ command: 'powershell', platform: 'win32', candidates: [{ path: powershellPath }], adapter: fsAdapter }),
    taskkill: await resolveVerifiedExecutable({ command: 'taskkill', platform: 'win32', candidates: [{ path: taskkillPath }], adapter: fsAdapter }),
    git: await resolveVerifiedExecutable({ command: 'git', platform: 'win32', candidates: [{ path: gitPath }], adapter: fsAdapter })
  };
}

const windows = await windowsFixtures();
function input(overrides = {}) {
  return {
    platform: 'win32', nodeVersion: '22.20.0', supportedNodeMajors: [22, 24, 26],
    powerShell: windows.powerShell, taskkill: windows.taskkill, git: windows.git,
    systemAdapter: {
      systemDirectory: async () => windows.systemDirectory,
      probePowerShellVersion: async () => '5.1',
      probeGitVersion: async () => ({ code: 0, stdout: 'git version 2.50.1\n', stderr: '' })
    },
    ...overrides
  };
}

test('accepts the Node floor and supported lines only with branded alternate-root Windows prerequisites', async () => {
  for (const nodeVersion of ['22.20.0', '24.0.0', '26.7.0']) {
    const result = await assessPrerequisites(input({ nodeVersion }));
    assert.equal(result.ready, true, nodeVersion);
    assert.equal(result.capabilities.powerShell.version, '5.1');
    assert.equal(result.capabilities.taskkill.available, true);
  }
});

test('refuses malformed, below-floor, odd, unsupported, and caller-expanded Node lines', async () => {
  for (const nodeVersion of ['22.19.9', '23.0.0', '28.0.0', 'v22.20.0', ' 22.20.0', '22.20.0x', '22.20.999999999999999999999']) {
    const result = await assessPrerequisites(input({ nodeVersion, supportedNodeMajors: [22, 24, 26, 28] }));
    assert.equal(result.capabilities.node.code, 'PREREQUISITE_MISSING', nodeVersion);
  }
});

test('does not accept nonexistent Git or fabricated PowerShell/taskkill records', async () => {
  const forged = Object.freeze({ path: 'C:\\definitely-not-git.exe', canonicalPath: 'C:\\definitely-not-git.exe', isLink: false, response: { schemaVersion: 1, ok: true, result: { version: '99.0' } } });
  const result = await assessPrerequisites(input({ cursorWorktreeRequested: true, git: forged, powerShell: forged, taskkill: forged }));
  assert.equal(result.ready, false);
  assert.equal(result.capabilities.git.code, 'PREREQUISITE_MISSING');
  assert.equal(result.capabilities.powerShell.code, 'PREREQUISITE_MISSING');
  assert.equal(result.capabilities.taskkill.code, 'PREREQUISITE_MISSING');
});

test('derives PowerShell and taskkill only from the trusted alternate system directory', async () => {
  const wrongRoot = await assessPrerequisites(input({ systemAdapter: { systemDirectory: async () => 'D:\\OtherWindows\\System32', probePowerShellVersion: async () => '5.1' } }));
  assert.equal(wrongRoot.ready, false);
  const old = await assessPrerequisites(input({ systemAdapter: { systemDirectory: async () => windows.systemDirectory, probePowerShellVersion: async () => '5.0' } }));
  assert.equal(old.capabilities.powerShell.code, 'PREREQUISITE_MISSING');
});

test('requires Git only for the Cursor worktree capability', async () => {
  assert.equal((await assessPrerequisites(input({ git: null }))).ready, true);
  const available = await assessPrerequisites(input({ cursorWorktreeRequested: true }));
  assert.equal(available.ready, true);
  assert.equal(available.capabilities.git.version, '2.50.1');
  const required = await assessPrerequisites(input({ git: null, cursorWorktreeRequested: true }));
  assert.equal(required.ready, false);
  assert.equal(required.capabilities.git.code, 'PREREQUISITE_MISSING');
});

test('rejects a branded non-Git executable before the fixed Git version probe', async () => {
  const fakeGitPath = path.join(root, 'not-git', 'node.exe');
  await fs.mkdir(path.dirname(fakeGitPath), { recursive: true });
  await fs.copyFile(process.execPath, fakeGitPath);
  const brandedClaude = await resolveVerifiedExecutable({
    command: 'claude', platform: 'win32', candidates: [{ path: fakeGitPath }], adapter: adapter()
  });
  let probes = 0;
  const result = await assessPrerequisites(input({
    cursorWorktreeRequested: true,
    git: brandedClaude,
    systemAdapter: {
      systemDirectory: async () => windows.systemDirectory,
      probePowerShellVersion: async () => '5.1',
      probeGitVersion: async () => { probes += 1; return { code: 0, stdout: 'git version 2.50.1\n', stderr: '' }; }
    }
  }));
  assert.equal(result.capabilities.git.code, 'PREREQUISITE_MISSING');
  assert.equal(probes, 0);
});

test('uses an exact bounded Git version probe and rejects confused output', async () => {
  let observed;
  const systemAdapter = {
    systemDirectory: async () => windows.systemDirectory,
    probePowerShellVersion: async () => '5.1',
    probeGitVersion: async (request) => {
      observed = request;
      return { code: 0, stdout: 'git version 2.50.1.windows.1\n', stderr: '' };
    }
  };
  const accepted = await assessPrerequisites(input({ cursorWorktreeRequested: true, systemAdapter }));
  assert.equal(accepted.capabilities.git.version, '2.50.1.windows.1');
  assert.deepEqual(observed.args, ['--version']);
  assert.equal(observed.executable, windows.git);
  assert.equal(observed.shell, false);
  assert.equal(observed.timeoutMs, 3_000);
  assert.equal(observed.maxStdoutBytes, 256);
  assert.equal(observed.maxStderrBytes, 256);
  assert.equal(Object.isFrozen(observed), true);
  assert.equal(Object.isFrozen(observed.args), true);

  const apple = await assessPrerequisites(input({
    cursorWorktreeRequested: true,
    systemAdapter: {
      ...systemAdapter,
      probeGitVersion: async () => ({ code: 0, stdout: 'git version 2.39.5 (Apple Git-154)\n', stderr: '' })
    }
  }));
  assert.equal(apple.capabilities.git.version, '2.39.5');
  for (const response of [
    { code: 1, stdout: 'git version 2.50.1\n', stderr: '' },
    { code: 0, stdout: 'git version 2.50.1\n', stderr: 'warning' },
    { code: 0, stdout: 'git version 2.50\n', stderr: '' },
    { code: 0, stdout: 'prefix git version 2.50.1\n', stderr: '' },
    { code: 0, stdout: 'git version 2.39.5 (Other Git-154)\n', stderr: '' }
  ]) {
    const refused = await assessPrerequisites(input({
      cursorWorktreeRequested: true,
      systemAdapter: { ...systemAdapter, probeGitVersion: async () => response }
    }));
    assert.equal(refused.capabilities.git.code, 'PREREQUISITE_MISSING');
  }
});
test('accepts only a branded fixed POSIX tar resolved through real filesystem handles', async (t) => {
  const hostRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'claudey-posix-root-'));
  t.after(() => fs.rm(hostRoot, { recursive: true, force: true }));
  const hostTar = path.join(hostRoot, 'usr', 'bin', 'tar');
  await fs.mkdir(path.dirname(hostTar), { recursive: true });
  await fs.writeFile(hostTar, 'host-tar-fixture');
  const hostPath = (value) => value === '/' ? hostRoot : path.join(hostRoot, ...value.slice(1).split('/'));
  const virtualPath = (value) => {
    const relative = path.relative(hostRoot, value);
    return relative === '' ? '/' : `/${relative.split(path.sep).join('/')}`;
  };
  const posixStats = (stats) => new Proxy(stats, {
    get(record, field) {
      if (field === 'mode') return Number(record.mode) | 0o111;
      const value = Reflect.get(record, field, record);
      return typeof value === 'function' ? value.bind(record) : value;
    }
  });
  const posixAdapter = {
    realpath: async (value) => virtualPath(await fs.realpath(hostPath(value))),
    lstat: async (value) => posixStats(await fs.lstat(hostPath(value))),
    stat: async (value) => posixStats(await fs.stat(hostPath(value))),
    openNoFollow: async (value) => {
      const target = hostPath(value);
      const before = await fs.lstat(target);
      if (before.isSymbolicLink()) throw new Error('link');
      const handle = await fs.open(target, 'r');
      return { noFollow: true, read: handle.read.bind(handle), close: handle.close.bind(handle), stat: async () => posixStats(await handle.stat()) };
    }
  };
  const tar = await resolveVerifiedExecutable({ command: 'tar', platform: 'linux', candidates: [{ path: '/usr/bin/tar' }], adapter: posixAdapter });
  const result = await assessPrerequisites({ platform: 'linux', nodeVersion: '22.20.0', supportedNodeMajors: [22], tar });
  assert.equal(result.ready, true);
  assert.equal(result.capabilities.tar.available, true);
});

test('rejects an unbranded fixed POSIX tar identity instead of trusting path metadata', async () => {
  const result = await assessPrerequisites({
    platform: 'linux', nodeVersion: '22.20.0', supportedNodeMajors: [22],
    tar: { path: '/usr/bin/tar', canonicalPath: '/usr/bin/tar', isLink: false }
  });
  assert.equal(result.ready, false);
  assert.equal(result.capabilities.tar.code, 'PREREQUISITE_MISSING');
});
