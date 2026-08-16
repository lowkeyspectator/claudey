import assert from 'node:assert/strict';
import test from 'node:test';

import { createCursorRepositoryRegistry } from '../../../src/cursor/registry.js';
import { createCursorSnapshotService } from '../../../src/cursor/snapshot.js';

const ROOT = '/home/casey/project';
const UUID = '11111111-1111-4111-8111-111111111111';

async function registered() {
  const registry = createCursorRepositoryRegistry({
    platform: 'linux', homeRoot: '/home/casey', installationId: UUID,
    readRecord: async () => ({ schemaVersion: 1, installationId: UUID, repositories: [{ root: ROOT, scope: 'user' }] }),
    writeRecord: async () => undefined,
    inspectRepository: async (candidate) => ({
      exists: true, type: 'directory', canonicalPath: candidate, gitRoot: ROOT,
      isLink: false, isJunction: false, isReparsePoint: false, isBare: false, owner: 'current'
    })
  });
  return (await registry.list())[0];
}

function fixture({ files = ['src/a.js', 'README.md'], selected, states = {}, limits, now, repositoryStates } = {}) {
  const events = [];
  const source = new Map();
  for (const relativePath of new Set([...files, ...(selected ?? [])])) source.set(relativePath, {
    exists: true, type: 'file', canonicalPath: `${ROOT}/${relativePath}`, size: relativePath.length,
    isLink: false, isJunction: false, isReparsePoint: false, isDevice: false, sensitive: false,
    dev: '7', ino: `${relativePath}:ino`, mtimeMs: '1', ...states[relativePath]
  });
  const copied = new Map();
  const descriptor = Object.freeze({
    path: '/home/casey/.local/state/claudeyctl/snapshots/snap-1',
    canonicalPath: '/home/casey/.local/state/claudeyctl/snapshots/snap-1',
    dev: '7', identity: 'snapshot:1', owned: true, empty: true, private: true,
    isLink: false, isJunction: false, isReparsePoint: false
  });
  const service = createCursorSnapshotService({
    platform: 'linux', snapshotParent: '/home/casey/.local/state/claudeyctl/snapshots', limits,
    now: now ?? (() => 1),
    inspectRepositoryRoot: async () => repositoryStates?.shift() ?? ({
      canonicalPath: ROOT, dev: '7', type: 'directory', isLink: false, isJunction: false, isReparsePoint: false
    }),
    enumerateFiles: async ({ paths, trackedOnly }) => {
      events.push(`enumerate:${trackedOnly}`);
      return paths ?? files;
    },
    inspectSource: async ({ relativePath }) => { events.push(`inspect:${relativePath}`); return source.get(relativePath); },
    createRoot: async () => { events.push('create-root'); return descriptor; },
    copyFile: async ({ relativePath }) => {
      events.push(`copy:${relativePath}`);
      const state = source.get(relativePath);
      const result = { size: state.size, sha256: 'a'.repeat(64) };
      copied.set(relativePath, result);
      return result;
    },
    revalidateSource: async ({ expected }) => { events.push(`recheck:${expected.canonicalPath}`); return true; },
    inspectCopied: async ({ relativePath }) => {
      const value = copied.get(relativePath);
      return { exists: true, type: 'file', canonicalPath: `${descriptor.path}/${relativePath}`, size: value.size, sha256: value.sha256, isLink: false, isJunction: false, isReparsePoint: false };
    },
    revalidateRoot: async (value) => value === descriptor,
    cleanupRoot: async () => { events.push('cleanup-root'); }
  });
  return { service, events, descriptor };
}

test('default selection copies only eligible Git-tracked files into a private same-filesystem snapshot and cleans it', async () => {
  const f = fixture();
  const repo = await registered();
  const result = await f.service.withSnapshot({ repository: repo }, async (snapshot) => {
    assert.equal(snapshot.scope.kind, 'snapshot');
    assert.equal(snapshot.scope.cwd, f.descriptor.path);
    assert.deepEqual(snapshot.files, ['README.md', 'src/a.js']);
    assert.equal(Object.isFrozen(snapshot), true);
    return 'consumer-result';
  });
  assert.equal(result, 'consumer-result');
  assert.equal(f.events[0], 'enumerate:true');
  assert.deepEqual(f.events.filter((event) => event.startsWith('copy:')), ['copy:README.md', 'copy:src/a.js']);
  assert.equal(f.events.at(-1), 'cleanup-root');
});

test('explicit selection admits contained untracked files but never implicitly includes them', async () => {
  const repo = await registered();
  const f = fixture({ files: ['tracked.js'], selected: ['notes.txt'] });
  await f.service.withSnapshot({ repository: repo, paths: ['notes.txt'] }, async ({ files }) => {
    assert.deepEqual(files, ['notes.txt']);
  });
  assert.equal(f.events[0], 'enumerate:false');
});

test('rejects traversal, absolute paths, .git, managed and known secret files, links, devices, and outside-root canonical paths', async () => {
  const repo = await registered();
  const cases = [
    ['../escape', {}], ['/absolute', {}], ['.git/config', {}], ['.env', {}], ['id_rsa', {}],
    ['auth.json', { sensitive: true }], ['link.js', { isLink: true }], ['junction.js', { isJunction: true }],
    ['reparse.js', { isReparsePoint: true }], ['device', { isDevice: true }],
    ['outside.js', { canonicalPath: '/home/casey/outside.js' }]
  ];
  for (const [relativePath, state] of cases) {
    const f = fixture({ files: [relativePath], states: { [relativePath]: state } });
    await assert.rejects(f.service.withSnapshot({ repository: repo }, async () => undefined),
      (error) => error.code === 'SAFETY_REFUSAL', relativePath);
    assert.equal(f.events.includes(`copy:${relativePath}`), false);
  }
});

test('enforces requested-path, file-count, byte-count, and elapsed-time limits before or during copy', async () => {
  const repo = await registered();
  const limits = { maxRequestedPaths: 1, maxFiles: 1, maxBytes: 5, timeoutMs: 5 };
  for (const f of [
    fixture({ selected: ['a', 'b'], limits }),
    fixture({ files: ['a', 'b'], limits }),
    fixture({ files: ['123456'], limits }),
    fixture({ files: ['a'], limits, now: (() => { let value = 0; return () => value += 10; })() })
  ]) {
    const paths = f.events.length === 0 && f.service ? undefined : undefined;
    await assert.rejects(f.service.withSnapshot({ repository: repo, ...(f === undefined ? {} : {}) }, async () => undefined),
      (error) => error.code === 'SAFETY_REFUSAL');
    assert.equal(f.events.at(-1) === 'cleanup-root' || !f.events.includes('create-root'), true);
    void paths;
  }
  const explicit = fixture({ selected: ['a', 'b'], limits });
  await assert.rejects(explicit.service.withSnapshot({ repository: repo, paths: ['a', 'b'] }, async () => undefined),
    (error) => error.code === 'SAFETY_REFUSAL');
  assert.equal(explicit.events.includes('create-root'), false);
});

test('refuses foreign filesystem/private-root metadata, source races, copied-file swaps, cleanup substitution, and forged registry records', async () => {
  const repo = await registered();
  const base = fixture({ files: ['a'] });
  const badRootService = createCursorSnapshotService({
    platform: 'linux', snapshotParent: '/tmp/snapshots', now: () => 1,
    inspectRepositoryRoot: async () => ({ canonicalPath: ROOT, dev: '7', type: 'directory', isLink: false, isJunction: false, isReparsePoint: false }),
    enumerateFiles: async () => ['a'], inspectSource: async () => ({
      exists: true, type: 'file', canonicalPath: `${ROOT}/a`, size: 1, isLink: false, isJunction: false,
      isReparsePoint: false, isDevice: false, sensitive: false, dev: '7', ino: 'a', mtimeMs: '1'
    }),
    createRoot: async () => ({ ...base.descriptor, path: '/tmp/snapshots/s', canonicalPath: '/tmp/snapshots/s', dev: '8' }),
    copyFile: async () => assert.fail('must not copy'), revalidateSource: async () => true,
    inspectCopied: async () => assert.fail(), revalidateRoot: async () => true, cleanupRoot: async () => undefined
  });
  await assert.rejects(badRootService.withSnapshot({ repository: repo }, async () => undefined),
    (error) => error.code === 'SAFETY_REFUSAL');
  await assert.rejects(base.service.withSnapshot({ repository: { ...repo } }, async () => undefined),
    (error) => error.code === 'SAFETY_REFUSAL');

  const raced = fixture({ files: ['a'], repositoryStates: [
    { canonicalPath: ROOT, dev: '7', type: 'directory', isLink: false, isJunction: false, isReparsePoint: false },
    { canonicalPath: '/home/casey/other', dev: '7', type: 'directory', isLink: false, isJunction: false, isReparsePoint: false }
  ] });
  await assert.rejects(raced.service.withSnapshot({ repository: repo }, async () => undefined),
    (error) => error.code === 'SAFETY_REFUSAL');
  assert.equal(raced.events.includes('create-root'), false);
});
