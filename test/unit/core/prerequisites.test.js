import assert from 'node:assert/strict';
import test from 'node:test';

import { assessPrerequisites } from '../../../src/core/prerequisites.js';

const POSIX_TAR = { path: '/usr/bin/tar', canonicalPath: '/usr/bin/tar', isLink: false };
const WINDOWS_POWERSHELL = {
  path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  canonicalPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  isLink: false,
  response: { schemaVersion: 1, ok: true, result: { version: '5.1' } }
};

function input(overrides = {}) {
  return {
    platform: 'linux',
    nodeVersion: '22.20.0',
    supportedNodeMajors: [22, 24, 26],
    tar: POSIX_TAR,
    git: { path: '/usr/bin/git', canonicalPath: '/usr/bin/git', isLink: false },
    cursorWorktreeRequested: false,
    ...overrides
  };
}

test('accepts the Node 22.20.0 floor and supported newer even release lines', () => {
  for (const nodeVersion of ['22.20.0', '24.0.0', '26.7.0']) {
    const result = assessPrerequisites(input({ nodeVersion }));
    assert.equal(result.ready, true, nodeVersion);
    assert.deepEqual(result.capabilities.node, { available: true, code: 'AVAILABLE', version: nodeVersion });
  }
});

test('refuses malformed, leading-junk, overflow, below-floor, odd, and unsupported Node releases', () => {
  for (const nodeVersion of ['22.19.9', '23.0.0', '28.0.0', 'v22.20.0', ' 22.20.0', '22.20.0x', '22.20.999999999999999999999']) {
    const result = assessPrerequisites(input({ nodeVersion }));
    assert.equal(result.ready, false, nodeVersion);
    assert.equal(result.capabilities.node.code, 'PREREQUISITE_MISSING', nodeVersion);
  }
});

test('requires the fixed absolute POSIX tar identity and Git only for Cursor worktree requests', () => {
  const noGitWithoutWorktree = assessPrerequisites(input({ git: null }));
  assert.equal(noGitWithoutWorktree.ready, true);
  assert.equal(noGitWithoutWorktree.capabilities.git.code, 'NOT_REQUIRED');

  const missingGitWithWorktree = assessPrerequisites(input({ cursorWorktreeRequested: true, git: null }));
  assert.equal(missingGitWithWorktree.ready, false);
  assert.equal(missingGitWithWorktree.capabilities.git.code, 'PREREQUISITE_MISSING');

  for (const tar of [
    null,
    { ...POSIX_TAR, canonicalPath: '/usr/local/bin/tar' },
    { ...POSIX_TAR, isLink: true },
    { ...POSIX_TAR, path: 'tar' }
  ]) {
    const result = assessPrerequisites(input({ tar }));
    assert.equal(result.ready, false);
    assert.equal(result.capabilities.tar.code, 'PREREQUISITE_MISSING');
  }
});

test('requires the fixed Windows PowerShell identity and an exact helper response protocol', () => {
  const accepted = assessPrerequisites(input({ platform: 'win32', tar: undefined, powerShell: WINDOWS_POWERSHELL }));
  assert.equal(accepted.ready, true);
  assert.deepEqual(accepted.capabilities.powerShell, { available: true, code: 'AVAILABLE', version: '5.1' });

  for (const powerShell of [
    null,
    { ...WINDOWS_POWERSHELL, isLink: true },
    { ...WINDOWS_POWERSHELL, canonicalPath: 'C:\\Windows\\pwsh.exe' },
    { ...WINDOWS_POWERSHELL, response: { schemaVersion: 2, ok: true, result: { version: '5.1' } } },
    { ...WINDOWS_POWERSHELL, response: { schemaVersion: 1, ok: true, result: { version: '5.1' }, extra: true } },
    { ...WINDOWS_POWERSHELL, response: { schemaVersion: 1, ok: true, result: { version: 5.1 } } }
  ]) {
    const result = assessPrerequisites(input({ platform: 'win32', tar: undefined, powerShell }));
    assert.equal(result.ready, false);
    assert.equal(result.capabilities.powerShell.code, 'PREREQUISITE_MISSING');
  }
});

test('does not let a caller expand the trusted Node lines and requires Windows PowerShell 5.1 plus a canonical Windows Git identity', () => {
  const expanded = assessPrerequisites(input({ nodeVersion: '28.0.0', supportedNodeMajors: [22, 24, 26, 28] }));
  assert.equal(expanded.capabilities.node.code, 'PREREQUISITE_MISSING');
  const oldPowerShell = assessPrerequisites(input({ platform: 'win32', tar: undefined, powerShell: { ...WINDOWS_POWERSHELL, response: { schemaVersion: 1, ok: true, result: { version: '5.0' } } } }));
  assert.equal(oldPowerShell.capabilities.powerShell.code, 'PREREQUISITE_MISSING');
  const windowsGit = assessPrerequisites(input({ platform: 'win32', tar: undefined, powerShell: WINDOWS_POWERSHELL, cursorWorktreeRequested: true, git: { path: 'C:\\Program Files\\Git\\cmd\\git.exe', canonicalPath: 'C:\\Program Files\\Git\\cmd\\git.exe', isLink: false } }));
  assert.equal(windowsGit.capabilities.git.code, 'AVAILABLE');
});
