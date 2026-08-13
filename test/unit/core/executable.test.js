import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { resolveVerifiedExecutable, revalidateExecutable } from '../../../src/core/executable.js';
import { probeRequiredCapabilities } from '../../../src/providers/capabilities.js';

const SHIM_BYTES = '@ECHO off\r\n"%~dp0\\node.exe" "%~dp0\\node_modules\\@anthropic-ai\\claude-code\\cli.js" %*\r\n';

function fsAdapter(overrides = {}) {
  return {
    realpath: async (target) => {
      try { return await fs.realpath(target); }
      catch (error) { if (error?.code === 'EPERM') return target; throw error; }
    },
    lstat: (target) => fs.lstat(target),
    stat: (target) => fs.stat(target),
    openNoFollow: async (target) => {
      const before = await fs.lstat(target);
      if (before.isSymbolicLink()) throw Object.assign(new Error('link'), { code: 'ELOOP' });
      return fs.open(target, 'r');
    },
    ...overrides
  };
}

async function makeWindowsInstall(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudex-executable-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const nativeDir = path.join(root, 'native');
  const npmDir = path.join(root, 'npm');
  const entryDir = path.join(npmDir, 'node_modules', '@anthropic-ai', 'claude-code');
  await fs.mkdir(nativeDir, { recursive: true });
  await fs.mkdir(entryDir, { recursive: true });
  const nativePath = path.join(nativeDir, 'claude.exe');
  const shimPath = path.join(npmDir, 'claude.cmd');
  const nodePath = path.join(npmDir, 'node.exe');
  const entryPath = path.join(entryDir, 'cli.js');
  await fs.writeFile(nativePath, 'native-v1');
  await fs.writeFile(shimPath, SHIM_BYTES);
  await fs.writeFile(nodePath, 'node-v1');
  await fs.writeFile(entryPath, 'entry-v1');
  return { root, nativeDir, npmDir, nativePath, shimPath, nodePath, entryPath };
}

function assertDeepFrozen(value, seen = new Set()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return;
  seen.add(value);
  assert.equal(Object.isFrozen(value), true);
  for (const child of Object.values(value)) assertDeepFrozen(child, seen);
}

test('prefers a real native executable and binds every canonical ancestor plus the leaf', async (t) => {
  const install = await makeWindowsInstall(t);
  const result = await resolveVerifiedExecutable({
    command: 'claude', platform: 'win32', candidates: [{ path: install.shimPath }, { path: install.nativePath }], adapter: fsAdapter()
  });
  assert.equal(result.kind, 'native');
  assert.equal(result.executablePath, await fs.realpath(install.nativePath));
  assert.deepEqual(result.argsPrefix, []);
  assert.equal(result.identity.schemaVersion, 1);
  assert.equal(result.identity.components.at(-1).path, result.executablePath);
  assert.ok(result.identity.components.some((component) => component.path.toLowerCase() === install.nativeDir.toLowerCase()));
  assert.ok(result.identity.components.length >= 3);
  assertDeepFrozen(result);
  assert.equal(await revalidateExecutable(result, fsAdapter()), true);
});

test('resolves a real native Cursor Agent command through the same complete identity contract', async (t) => {
  const install = await makeWindowsInstall(t);
  const cursorPath = path.join(install.nativeDir, 'cursor-agent.exe');
  await fs.writeFile(cursorPath, 'cursor-native');
  const result = await resolveVerifiedExecutable({
    command: 'cursor-agent', platform: 'win32', candidates: [{ path: cursorPath }], adapter: fsAdapter()
  });
  assert.equal(result.kind, 'native');
  assert.equal(result.identity.command, 'cursor-agent');
  assert.equal(await result.revalidate(), true);
});
test('reads the real npm shim through a bounded no-follow handle and binds shim, node, entry, and all ancestors', async (t) => {
  const install = await makeWindowsInstall(t);
  const result = await resolveVerifiedExecutable({
    command: 'claude', platform: 'win32',
    candidates: [{ path: install.shimPath, script: 'caller-spoof', entryPath: 'C:\\spoof.js' }], adapter: fsAdapter()
  });
  assert.equal(result.kind, 'node-entry');
  assert.equal(result.executablePath, await fs.realpath(install.nodePath));
  assert.deepEqual(result.argsPrefix, [await fs.realpath(install.entryPath)]);
  assert.match(result.identity.shimSha256, /^[a-f0-9]{64}$/);
  for (const required of [install.shimPath, install.nodePath, install.entryPath, install.npmDir]) {
    assert.ok(result.identity.components.some((component) => component.path.toLowerCase() === required.toLowerCase()), required);
  }
  assertDeepFrozen(result);
  assert.equal(await revalidateExecutable(result, fsAdapter()), true);
});

test('rejects unsafe actual shim bytes, links, ADS/control/relative paths, ambiguous native aliases, and incomplete adapters', async (t) => {
  const install = await makeWindowsInstall(t);
  await fs.writeFile(install.shimPath, `${SHIM_BYTES}whoami\r\n`);
  await assert.rejects(
    resolveVerifiedExecutable({ command: 'claude', platform: 'win32', candidates: [{ path: install.shimPath, script: SHIM_BYTES }], adapter: fsAdapter() }),
    (error) => error.code === 'PREREQUISITE_MISSING'
  );
  const outsideDirectory = path.join(install.root, 'outside-directory');
  const linkDirectory = path.join(install.root, 'linked-directory');
  await fs.mkdir(outsideDirectory);
  await fs.writeFile(path.join(outsideDirectory, 'linked.exe'), 'outside');
  await fs.symlink(outsideDirectory, linkDirectory, 'junction');
  const linkPath = path.join(linkDirectory, 'linked.exe');
  for (const candidatePath of ['claude.exe', `${install.nativePath}:stream`, `${install.nativePath}\nother`, linkPath]) {
    await assert.rejects(
      resolveVerifiedExecutable({ command: 'claude', platform: 'win32', candidates: [{ path: candidatePath }], adapter: fsAdapter() }),
      (error) => error.code === 'PREREQUISITE_MISSING', candidatePath
    );
  }
  const secondNative = path.join(install.nativeDir, 'claude-two.exe');
  await fs.writeFile(secondNative, 'native-v2');
  await assert.rejects(
    resolveVerifiedExecutable({ command: 'claude', platform: 'win32', candidates: [{ path: install.nativePath }, { path: secondNative }], adapter: fsAdapter() }),
    (error) => error.code === 'PREREQUISITE_MISSING'
  );
  for (const missing of ['realpath', 'lstat', 'stat', 'openNoFollow']) {
    const adapter = fsAdapter(); delete adapter[missing];
    await assert.rejects(
      resolveVerifiedExecutable({ command: 'claude', platform: 'win32', candidates: [{ path: install.nativePath }], adapter }),
      (error) => error.code === 'PREREQUISITE_MISSING', missing
    );
  }
  await assert.rejects(
    resolveVerifiedExecutable({ command: 'claude', platform: 'win32', candidates: [{ path: install.nativePath }], adapter: fsAdapter({ lstat: async () => ({ isFile: () => true }) }) }),
    (error) => error.code === 'PREREQUISITE_MISSING'
  );
  await assert.rejects(
    resolveVerifiedExecutable({
      command: 'claude',
      platform: 'win32',
      candidates: [{ path: install.nativePath }],
      adapter: fsAdapter({
        lstat: async (target) => {
          const stats = await fs.lstat(target);
          if (target.toLowerCase() !== install.nativePath.toLowerCase()) return stats;
          return new Proxy(stats, {
            get: (record, field) => { const value = Reflect.get(record, field, record); return field === 'isFile' ? () => 'yes' : typeof value === 'function' ? value.bind(record) : value; }
          });
        }
      })
    }),
    (error) => error.code === 'PREREQUISITE_MISSING'
  );
});

test('requires native and Node file types/extensions plus a contained regular JavaScript entry', async (t) => {
  const install = await makeWindowsInstall(t);
  const directoryExe = path.join(install.root, 'directory.exe');
  await fs.mkdir(directoryExe);
  await assert.rejects(
    resolveVerifiedExecutable({ command: 'claude', platform: 'win32', candidates: [{ path: directoryExe }], adapter: fsAdapter() }),
    (error) => error.code === 'PREREQUISITE_MISSING'
  );
  const outsideDirectory = path.join(install.root, 'outside-entry');
  await fs.mkdir(outsideDirectory);
  await fs.writeFile(path.join(outsideDirectory, 'cli.js'), 'outside');
  await fs.rm(path.dirname(install.entryPath), { recursive: true });
  await fs.symlink(outsideDirectory, path.dirname(install.entryPath), 'junction');
  await assert.rejects(
    resolveVerifiedExecutable({ command: 'claude', platform: 'win32', candidates: [{ path: install.shimPath }], adapter: fsAdapter() }),
    (error) => error.code === 'PREREQUISITE_MISSING'
  );
});

test('revalidation refuses every native leaf, ancestor, shim-byte, Node, and entry swap', async (t) => {
  async function assertSwap(mutator, useShim = false) {
    const install = await makeWindowsInstall(t);
    const result = await resolveVerifiedExecutable({
      command: 'claude', platform: 'win32', candidates: [{ path: useShim ? install.shimPath : install.nativePath }], adapter: fsAdapter()
    });
    await mutator(install);
    assert.equal(await revalidateExecutable(result, fsAdapter()), false);
    let spawned = false;
    const outcome = await probeRequiredCapabilities({
      cliProxy: result,
      claude: result,
      run: async () => { spawned = true; return { code: 0, stdout: '', stderr: '' }; }
    });
    assert.equal(outcome.ready, false);
    assert.equal(spawned, false);
  }
  await assertSwap(async ({ nativePath }) => { await fs.rename(nativePath, `${nativePath}.old`); await fs.writeFile(nativePath, 'replacement'); });
  await assertSwap(async ({ nativeDir, nativePath }) => {
    const old = `${nativeDir}-old`; await fs.rename(nativeDir, old); await fs.mkdir(nativeDir); await fs.writeFile(nativePath, 'native-v1');
  });
  await assertSwap(async ({ shimPath }) => { await fs.writeFile(shimPath, SHIM_BYTES.replace('@ECHO off', '@echo off')); }, true);
  await assertSwap(async ({ nodePath }) => { await fs.rename(nodePath, `${nodePath}.old`); await fs.writeFile(nodePath, 'node-v2'); }, true);
  await assertSwap(async ({ entryPath }) => { await fs.rename(entryPath, `${entryPath}.old`); await fs.writeFile(entryPath, 'entry-v2'); }, true);
});
