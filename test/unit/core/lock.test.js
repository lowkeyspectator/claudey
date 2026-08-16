import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { openExclusive } from '../../../src/core/lock.js';

const owner = {
  pid: 4242,
  processStartTime: 1_700_000_000_000,
  executableCanonicalPath: process.execPath
};

function fixedNow(value = '2026-08-12T00:00:00.000Z') {
  return () => new Date(value);
}

async function tempRoot(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-lock-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

function staleRecord(overrides = {}) {
  return {
    schemaVersion: 1,
    kind: 'installation-lock',
    nonce: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    acquiredAt: '2026-08-11T23:50:00.000Z',
    owner,
    ...overrides
  };
}

test('acquires a complete owner record and releases only its own lock', async (t) => {
  const root = await tempRoot(t);
  const lock = await openExclusive({ root, child: path.join('state', 'install.lock'), owner, now: fixedNow() });
  assert.deepEqual(lock.record.owner, owner);
  assert.equal(lock.record.schemaVersion, 1);
  assert.equal(lock.record.kind, 'installation-lock');
  assert.match(lock.record.nonce, /^[A-Za-z0-9_-]{43}$/);

  await lock.release();
  await lock.release();
  await assert.rejects(() => fs.readFile(path.join(root, 'state', 'install.lock')), { code: 'ENOENT' });
});

test('allows one real concurrent exclusive lock acquisition and reports the other as busy', async (t) => {
  const root = await tempRoot(t);
  const options = {
    root,
    child: path.join('state', 'install.lock'),
    owner,
    now: fixedNow(),
    inspectOwner: async () => ({ exists: true, startTime: owner.processStartTime, executableCanonicalPath: owner.executableCanonicalPath })
  };
  const results = await Promise.allSettled([openExclusive(options), openExclusive(options)]);
  const acquired = results.filter((result) => result.status === 'fulfilled');
  const refused = results.filter((result) => result.status === 'rejected');
  assert.equal(acquired.length, 1);
  assert.equal(refused.length, 1);
  assert.equal(refused[0].reason.code, 'LOCK_BUSY');
  await acquired[0].value.release();
});

test('recovers an expired dead lock with a new nonce without signaling a process', async (t) => {
  const root = await tempRoot(t);
  const state = path.join(root, 'state');
  await fs.mkdir(state);
  await fs.writeFile(path.join(state, 'install.lock'), JSON.stringify(staleRecord()), { mode: 0o600 });

  const lock = await openExclusive({
    root, child: path.join('state', 'install.lock'), owner, now: fixedNow(), staleAfterMs: 60_000,
    inspectOwner: async () => ({ exists: false })
  });
  assert.notEqual(lock.record.nonce, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  await lock.release();
});

test('does not steal a live, fresh-dead, future-clock, or malformed lock', async (t) => {
  const root = await tempRoot(t);
  const state = path.join(root, 'state');
  await fs.mkdir(state);
  const lockPath = path.join(state, 'install.lock');
  const cases = [
    {
      name: 'live', record: staleRecord(), inspectOwner: async () => ({
        exists: true, startTime: owner.processStartTime, executableCanonicalPath: owner.executableCanonicalPath
      })
    },
    { name: 'fresh-dead', record: staleRecord({ acquiredAt: '2026-08-11T23:59:30.000Z' }), inspectOwner: async () => ({ exists: false }) },
    { name: 'future-clock', record: staleRecord({ acquiredAt: '2026-08-12T00:01:00.000Z' }), inspectOwner: async () => ({ exists: false }) },
    { name: 'malformed', record: 'not-json', inspectOwner: async () => ({ exists: false }) }
  ];
  for (const item of cases) {
    const text = typeof item.record === 'string' ? item.record : JSON.stringify(item.record);
    await fs.writeFile(lockPath, text, { mode: 0o600 });
    await assert.rejects(
      () => openExclusive({ root, child: path.join('state', 'install.lock'), owner, now: fixedNow(), staleAfterMs: 60_000, inspectOwner: item.inspectOwner }),
      (error) => error?.code === 'LOCK_BUSY',
      item.name
    );
    assert.equal(await fs.readFile(lockPath, 'utf8'), text, item.name);
  }
});

test('treats a reused PID as stale only after expiry and refuses swapped release records', async (t) => {
  const root = await tempRoot(t);
  const state = path.join(root, 'state');
  await fs.mkdir(state);
  const lockPath = path.join(state, 'install.lock');
  await fs.writeFile(lockPath, JSON.stringify(staleRecord()), { mode: 0o600 });
  const recovered = await openExclusive({
    root, child: path.join('state', 'install.lock'), owner, now: fixedNow(), staleAfterMs: 60_000,
    inspectOwner: async () => ({ exists: true, startTime: owner.processStartTime + 1, executableCanonicalPath: owner.executableCanonicalPath })
  });
  await fs.writeFile(lockPath, JSON.stringify(staleRecord({ nonce: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' })), { mode: 0o600 });
  await assert.rejects(() => recovered.release(), (error) => error?.code === 'SAFETY_REFUSAL');
  assert.match(await fs.readFile(lockPath, 'utf8'), /bbbbbbbb/);
});

test('refuses a link lock path rather than following it', async (t) => {
  const root = await tempRoot(t);
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-lock-outside-'));
  t.after(() => fs.rm(outside, { recursive: true, force: true }));
  await fs.mkdir(path.join(root, 'state'));
  try {
    await fs.symlink(path.join(outside, 'lock'), path.join(root, 'state', 'install.lock'), 'file');
  } catch (error) {
    if (!['EPERM', 'EACCES'].includes(error.code) || process.platform !== 'win32') throw error;
    await fs.rm(path.join(root, 'state'), { recursive: true, force: true });
    await fs.symlink(outside, path.join(root, 'state'), 'junction');
  }
  await assert.rejects(
    () => openExclusive({ root, child: path.join('state', 'install.lock'), owner, now: fixedNow() }),
    (error) => error?.code === 'SAFETY_REFUSAL'
  );
});
