import assert from 'node:assert/strict';
import test from 'node:test';

import { createCursorRepositoryRegistry } from '../../../src/cursor/registry.js';

const HOME = 'C:\\Users\\Casey';
const REPO = 'C:\\src\\project';
const UUID = '11111111-1111-4111-8111-111111111111';

function fixture({ initial = [], inspection = {} } = {}) {
  const writes = [];
  let record = { schemaVersion: 1, installationId: UUID, repositories: initial };
  const registry = createCursorRepositoryRegistry({
    platform: 'win32', homeRoot: HOME, installationId: UUID,
    readRecord: async () => structuredClone(record),
    writeRecord: async (next) => { record = structuredClone(next); writes.push(structuredClone(next)); },
    inspectRepository: async (candidate) => ({
      exists: true, type: 'directory', canonicalPath: candidate, gitRoot: candidate,
      isLink: false, isJunction: false, isReparsePoint: false, isBare: false, owner: 'current',
      ...inspection
    })
  });
  return { registry, writes, record: () => record };
}

test('local current-project registration is canonical, idempotent, and exempt from confirmation', async () => {
  const f = fixture({ inspection: { canonicalPath: `${REPO}\\subdir`, gitRoot: REPO } });
  const first = await f.registry.add({ path: `${REPO}\\subdir`, scope: 'local', currentProject: REPO, confirmed: false });
  assert.deepEqual(first, { action: 'added', root: REPO, scope: 'local' });
  const second = await f.registry.add({ path: REPO.toLowerCase(), scope: 'local', currentProject: REPO, confirmed: false });
  assert.deepEqual(second, { action: 'preserved', reason: 'already-registered', root: REPO, scope: 'local' });
  assert.equal(f.writes.length, 1);
  assert.deepEqual(await f.registry.list(), [{ root: REPO, scope: 'local' }]);
});

test('user-scope registration and non-current local registration require explicit confirmation', async () => {
  for (const input of [
    { path: REPO, scope: 'user', currentProject: REPO, confirmed: false },
    { path: REPO, scope: 'local', currentProject: 'C:\\src\\other', confirmed: false }
  ]) {
    const f = fixture();
    await assert.rejects(f.registry.add(input), (error) => error.code === 'INTERACTION_REQUIRED');
    assert.equal(f.writes.length, 0);
  }
});

test('remove revokes only the exact owned registration and repeated remove is a no-op', async () => {
  const f = fixture({ initial: [{ root: REPO, scope: 'user' }] });
  await assert.rejects(f.registry.remove({ path: REPO, confirmed: false }),
    (error) => error.code === 'INTERACTION_REQUIRED');
  assert.deepEqual(await f.registry.remove({ path: REPO, confirmed: true }), { action: 'removed', root: REPO });
  assert.deepEqual(await f.registry.remove({ path: REPO, confirmed: true }),
    { action: 'preserved', reason: 'not-registered', root: REPO });
  assert.deepEqual(await f.registry.list(), []);
});

test('an exact stale registration remains removable after the repository disappears', async () => {
  const f = fixture({ initial: [{ root: REPO, scope: 'user' }], inspection: { exists: false } });
  assert.deepEqual(await f.registry.remove({ path: REPO, confirmed: true }), { action: 'removed', root: REPO });
  assert.deepEqual(await f.registry.list(), []);
});

test('rejects filesystem root, home, bare, unresolved, foreign-owned, non-Git, link, junction, and reparse candidates', async () => {
  const cases = [
    ['C:\\', {}], [HOME, {}], [REPO, { isBare: true }], [REPO, { exists: false }],
    [REPO, { owner: 'other' }], [REPO, { gitRoot: null }], [REPO, { isLink: true }],
    [REPO, { isJunction: true }], [REPO, { isReparsePoint: true }]
  ];
  for (const [candidate, inspection] of cases) {
    const f = fixture({ inspection });
    await assert.rejects(f.registry.add({ path: candidate, scope: 'user', currentProject: REPO, confirmed: true }),
      (error) => error.code === 'SAFETY_REFUSAL', JSON.stringify(inspection));
    assert.equal(f.writes.length, 0);
  }
});

test('rejects foreign installation records, malformed entries, duplicate roots, hostile inputs, and adapter diagnostics', async () => {
  const records = [
    { schemaVersion: 1, installationId: '22222222-2222-4222-8222-222222222222', repositories: [] },
    { schemaVersion: 1, installationId: UUID, repositories: [{ root: 'relative', scope: 'user' }] },
    { schemaVersion: 1, installationId: UUID, repositories: [{ root: REPO, scope: 'user' }, { root: REPO.toLowerCase(), scope: 'local' }] }
  ];
  for (const record of records) {
    const registry = createCursorRepositoryRegistry({
      platform: 'win32', homeRoot: HOME, installationId: UUID,
      readRecord: async () => record, writeRecord: async () => assert.fail('must not write'),
      inspectRepository: async () => assert.fail('must not inspect')
    });
    await assert.rejects(registry.list(), (error) => error.code === 'SAFETY_REFUSAL');
  }
  const f = fixture();
  const hostile = new Proxy({}, { ownKeys: () => { throw new Error('private registry canary'); } });
  await assert.rejects(f.registry.add(hostile), (error) => error.code === 'SAFETY_REFUSAL' && !error.message.includes('canary'));
});
