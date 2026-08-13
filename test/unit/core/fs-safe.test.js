import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  assertContainedNoLinks,
  assertManagedRoot,
  assertRelativeManagedChild,
  lstatNoFollow,
  resolveManagedChild
} from '../../../src/core/fs-safe.js';

function safetyRefusal(operation, message) {
  assert.throws(operation, (error) => error?.code === 'SAFETY_REFUSAL', message);
}

test('rejects syntactically unsafe managed child paths before filesystem access', () => {
  const cases = [
    ['posix', '../outside'], ['posix', 'state/../../outside'], ['posix', '/tmp/file'],
    ['posix', 'state/a\0b'], ['posix', 'state/a\nb'], ['posix', 'state/a\rb'], ['posix', '.'], ['posix', ''],
    ['win32', 'D:\\temp\\file'], ['win32', 'C:temp\\file'], ['win32', '\\Windows\\temp'],
    ['win32', '\\\\server\\share\\file'], ['win32', '\\\\?\\UNC\\server\\share\\file'],
    ['win32', '\\\\.\\PhysicalDrive0'], ['win32', 'state\\file.txt:alternate'], ['win32', 'state\\..\\..\\outside']
  ];
  for (const [platform, child] of cases) {
    safetyRefusal(() => assertRelativeManagedChild(child, { platform }), `${platform}: ${JSON.stringify(child)}`);
  }
});

test('resolves safe nested Unicode children with platform-specific containment semantics', () => {
  assert.equal(
    resolveManagedChild('/srv/claudexctl', 'releases/日本語 build/file.txt', { platform: 'posix' }),
    '/srv/claudexctl/releases/日本語 build/file.txt'
  );
  assert.equal(
    resolveManagedChild('C:\\Users\\Casey\\AppData\\Local\\claudexctl', 'state\\locks\\install.lock', { platform: 'win32' }),
    'C:\\Users\\Casey\\AppData\\Local\\claudexctl\\state\\locks\\install.lock'
  );
  assert.equal(
    resolveManagedChild('C:\\Users\\Casey\\AppData\\Local\\claudexctl', 'STATE\\locks\\install.lock', { platform: 'win32' }),
    'C:\\Users\\Casey\\AppData\\Local\\claudexctl\\STATE\\locks\\install.lock'
  );
});

test('rejects roots that are filesystem roots, home roots, repository roots, or unexpected canonical paths', () => {
  safetyRefusal(() => assertManagedRoot('/', { platform: 'posix' }), 'filesystem root');
  safetyRefusal(() => assertManagedRoot('/home/casey', { platform: 'posix', homeRoot: '/home/casey' }), 'home root');
  safetyRefusal(() => assertManagedRoot('/work/repository', { platform: 'posix', repositoryRoot: '/work/repository' }), 'repository root');
  safetyRefusal(
    () => assertManagedRoot('/srv/claudexctl', { platform: 'posix', expectedRoot: '/srv/other' }),
    'unexpected canonical root'
  );
});

test('rejects a real symbolic-link ancestor instead of following it outside the managed root', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudexctl-fs-safe-'));
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'claudexctl-outside-'));
  t.after(async () => {
    await fs.rm(root, { recursive: true, force: true });
    await fs.rm(outside, { recursive: true, force: true });
  });
  try {
    await fs.symlink(outside, path.join(root, 'state'), process.platform === 'win32' ? 'junction' : 'dir');
  } catch (error) {
    if (error.code === 'EPERM' || error.code === 'EACCES') {
      t.skip('native symbolic-link creation is unavailable on this host');
      return;
    }
    throw error;
  }

  await assert.rejects(
    () => assertContainedNoLinks({ root, child: 'state/target.txt' }),
    (error) => error?.code === 'SAFETY_REFUSAL'
  );
});

test('treats an injected reparse point as unsafe before the leaf is used', async () => {
  const root = 'C:\\Users\\Casey\\AppData\\Local\\claudexctl';
  const normal = { isSymbolicLink: () => false, isDirectory: () => true, isReparsePoint: false };
  const reparse = { isSymbolicLink: () => false, isDirectory: () => false, isReparsePoint: true };
  await assert.rejects(
    () => assertContainedNoLinks(
      { root, child: 'state\\runtime.json', platform: 'win32' },
      {
        canonicalize: async (value) => value,
        lstat: async (value) => value.endsWith('runtime.json') ? reparse : normal
      }
    ),
    (error) => error?.code === 'SAFETY_REFUSAL'
  );
});

test('lstatNoFollow refuses symbolic and reparse entries returned by an adapter', async () => {
  await assert.rejects(
    () => lstatNoFollow('/safe/target', { lstat: async () => ({ isSymbolicLink: () => true }) }),
    (error) => error?.code === 'SAFETY_REFUSAL'
  );
  await assert.rejects(
    () => lstatNoFollow('/safe/target', { lstat: async () => ({ isSymbolicLink: () => false, isReparsePoint: true }) }),
    (error) => error?.code === 'SAFETY_REFUSAL'
  );
});
