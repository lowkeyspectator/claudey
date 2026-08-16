import assert from 'node:assert/strict';
import test from 'node:test';

import {
  applyPathMutation,
  loadPathMutationRecord,
  planPathMutation,
  restorePathMutation
} from '../../../src/core/path-mutation.js';

const BIN = 'C:\\Users\\Casey\\AppData\\Local\\claudexctl\\bin';

test('Windows user PATH mutation deduplicates case-insensitively and never targets the system PATH', async () => {
  const writes = [];
  const plan = planPathMutation({
    platform: 'win32',
    binDirectory: BIN,
    userPath: `C:\\Windows;${BIN.toUpperCase()};C:\\Tools;${BIN}`,
    currentShellPath: 'C:\\Windows;C:\\Tools'
  });
  assert.equal(plan.kind, 'windows-user-path');
  assert.equal(plan.after, `C:\\Windows;${BIN.toUpperCase()};C:\\Tools`);
  assert.equal(plan.changed, true);
  assert.equal(plan.shellVisible, false);
  assert.deepEqual(plan.remediation, {
    restartShell: true,
    absoluteLauncher: `${BIN}\\claudeyctl.exe`
  });
  await applyPathMutation(plan, {
    writeUserPath: async (value) => writes.push(value),
    writeSystemPath: async () => assert.fail('system PATH must never be written')
  });
  assert.deepEqual(writes, [plan.after]);
});

test('Windows PATH restoration is exact and refuses to overwrite a later user edit', async () => {
  const plan = planPathMutation({ platform: 'windows', binDirectory: BIN, userPath: 'C:\\Windows' });
  const writes = [];
  assert.deepEqual(await restorePathMutation(plan, {
    readUserPath: async () => plan.after,
    writeUserPath: async (value) => writes.push(value)
  }), { action: 'restored', reason: 'owned-change' });
  assert.deepEqual(writes, ['C:\\Windows']);

  assert.deepEqual(await restorePathMutation(plan, {
    readUserPath: async () => `${plan.after};C:\\Later`,
    writeUserPath: async () => assert.fail('modified PATH must be preserved')
  }), { action: 'preserved', reason: 'modified' });
});

test('a persisted PATH ownership record is strictly revalidated and restores duplicate cleanup exactly', async () => {
  const original = `C:\\Windows;${BIN.toUpperCase()};${BIN}`;
  const plan = planPathMutation({ platform: 'win32', binDirectory: BIN, userPath: original });
  const loaded = loadPathMutationRecord(JSON.parse(JSON.stringify(plan)), { binDirectory: BIN });
  const writes = [];
  assert.equal(loaded.owned, true);
  assert.deepEqual(await restorePathMutation(loaded, {
    readUserPath: async () => loaded.after,
    writeUserPath: async (value) => writes.push(value)
  }), { action: 'restored', reason: 'owned-change' });
  assert.deepEqual(writes, [original]);
  assert.throws(() => loadPathMutationRecord({ ...JSON.parse(JSON.stringify(plan)), after: 'C:\\Forged' }, { binDirectory: BIN }),
    (error) => error.code === 'SAFETY_REFUSAL');
});

test('Windows mutation preserves unrelated empty PATH segments byte-for-byte', () => {
  const plan = planPathMutation({ platform: 'win32', binDirectory: BIN, userPath: 'C:\\Windows;;C:\\Tools;' });
  assert.equal(plan.after, `C:\\Windows;;C:\\Tools;;${BIN}`);
  assert.equal(plan.before, 'C:\\Windows;;C:\\Tools;');
});

test('an already present Windows entry is an idempotent no-op and is not owned for restoration', async () => {
  const plan = planPathMutation({ platform: 'win32', binDirectory: BIN, userPath: `C:\\Windows;${BIN}` });
  assert.equal(plan.changed, false);
  await applyPathMutation(plan, { writeUserPath: async () => assert.fail('must not write') });
  assert.deepEqual(await restorePathMutation(plan, {
    readUserPath: async () => plan.after,
    writeUserPath: async () => assert.fail('must not remove a pre-existing entry')
  }), { action: 'preserved', reason: 'not-owned' });
});

test('POSIX profile mutation uses one bounded marker block and restoration removes only that block', async () => {
  const profile = 'export EDITOR=vi\n';
  const plan = planPathMutation({
    platform: 'linux',
    binDirectory: '/home/casey/.local/bin',
    profilePath: '/home/casey/.profile',
    profileText: profile,
    currentShellPath: '/usr/bin:/bin'
  });
  assert.equal(plan.kind, 'posix-profile-block');
  assert.match(plan.after, /# >>> claudeyctl PATH >>>/u);
  assert.match(plan.after, /export PATH="\/home\/casey\/\.local\/bin:\$PATH"/u);
  assert.equal((plan.after.match(/claudeyctl PATH/gu) ?? []).length, 2);
  const later = `${plan.after}export PAGER=less\n`;
  const writes = [];
  assert.deepEqual(await restorePathMutation(plan, {
    readProfile: async () => later,
    writeProfile: async (path, value) => writes.push([path, value])
  }), { action: 'restored', reason: 'owned-change' });
  assert.deepEqual(writes, [['/home/casey/.profile', `${profile}export PAGER=less\n`]]);
});

test('POSIX refuses ambiguous or modified marker blocks', async () => {
  const plan = planPathMutation({
    platform: 'darwin', binDirectory: '/Users/casey/.local/bin', profilePath: '/Users/casey/.profile', profileText: ''
  });
  const changed = plan.after.replace('$PATH', '$HOME/bin:$PATH');
  assert.deepEqual(await restorePathMutation(plan, {
    readProfile: async () => changed,
    writeProfile: async () => assert.fail('changed marker must be preserved')
  }), { action: 'preserved', reason: 'modified' });
  assert.throws(() => planPathMutation({
    platform: 'linux', binDirectory: '/home/casey/.local/bin', profilePath: '/home/casey/.profile',
    profileText: '# >>> claudeyctl PATH >>>\nforeign\n'
  }), (error) => error.code === 'SAFETY_REFUSAL');
  assert.throws(() => planPathMutation({
    platform: 'linux', binDirectory: '/home/casey/.local/bin', profilePath: '/home/casey/.profile',
    profileText: `foreign ${plan.block}`
  }), (error) => error.code === 'SAFETY_REFUSAL');
});

test('--no-path produces a closed no-op plan with current-shell remediation only', async () => {
  const plan = planPathMutation({
    platform: 'win32', binDirectory: BIN, userPath: 'C:\\Windows', currentShellPath: 'C:\\Windows', noPath: true
  });
  assert.deepEqual(plan, {
    schemaVersion: 1,
    kind: 'none',
    changed: false,
    binDirectory: BIN,
    shellVisible: false,
    remediation: { restartShell: false, absoluteLauncher: `${BIN}\\claudeyctl.exe` }
  });
  await applyPathMutation(plan, new Proxy({}, { get: () => assert.fail('adapter must not be used') }));
  assert.deepEqual(await restorePathMutation(plan, {}), { action: 'preserved', reason: 'not-owned' });
});

test('malformed option types, control characters, unknown fields, and hostile accessors fail closed', () => {
  for (const options of [
    { platform: 'win32', binDirectory: `${BIN}\nmalicious`, userPath: '' },
    { platform: 'win32', binDirectory: BIN, userPath: null },
    { platform: 'win32', binDirectory: BIN, noPath: 1 },
    { platform: 'win32', binDirectory: BIN, extra: true }
  ]) assert.throws(() => planPathMutation(options), (error) => error.code === 'SAFETY_REFUSAL');
  const hostile = new Proxy({}, { ownKeys: () => { throw new Error('private PATH canary'); } });
  assert.throws(() => planPathMutation(hostile),
    (error) => error.code === 'SAFETY_REFUSAL' && !error.message.includes('canary'));
});
