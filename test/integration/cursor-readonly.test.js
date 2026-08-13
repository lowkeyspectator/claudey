import assert from 'node:assert/strict';
import test from 'node:test';

import { createCursorRepositoryRegistry } from '../../src/cursor/registry.js';
import { createCursorRunScope } from '../../src/cursor/runner.js';
import { createCursorReadonlyService } from '../../src/cursor/service.js';

const ROOT = '/home/casey/project';
const UUID = '11111111-1111-4111-8111-111111111111';

async function repository() {
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

function fixture({ mutateSource = false, fingerprintFailure = false, runnerFailure = false } = {}) {
  const source = { files: 'files:1', index: 'index:1', head: 'head:1', branch: 'main', refs: 'refs:1', untracked: 'untracked:1' };
  const snapshotFiles = { 'src/a.js': 'original' };
  const events = [];
  const scope = createCursorRunScope({ kind: 'snapshot', cwd: '/tmp/snapshot-1', platform: 'linux' });
  const snapshotService = {
    async withSnapshot(request, consumer) {
      events.push(['snapshot-open', request]);
      try { return await consumer(Object.freeze({ scope, files: Object.freeze(['src/a.js']), totalBytes: 8 })); }
      finally { events.push(['snapshot-cleanup']); }
    }
  };
  const runner = {
    async run(request) {
      events.push(['runner', request]);
      snapshotFiles['src/a.js'] = 'aggressive write';
      snapshotFiles['new.js'] = 'new write';
      if (mutateSource) source.files = 'files:changed';
      if (runnerFailure) throw new Error('private cursor failure canary');
      return Object.freeze({ type: 'cursor-result', untrusted: true, value: Object.freeze({ text: 'answer' }) });
    }
  };
  const captureSourceFingerprint = async () => {
    events.push(['fingerprint']);
    if (fingerprintFailure) throw new Error('private fingerprint canary');
    return structuredClone(source);
  };
  return {
    service: createCursorReadonlyService({ snapshotService, runner, captureSourceFingerprint }),
    source, snapshotFiles, events
  };
}

function input(repo, overrides = {}) {
  return { repository: repo, prompt: 'private prompt', model: 'cursor-model', paths: ['src/a.js'], ...overrides };
}

test('ask and plan run only in disposable snapshots and leave source files/index/HEAD/branch/refs/untracked invariant', async () => {
  const repo = await repository();
  for (const mode of ['ask', 'plan']) {
    const f = fixture();
    const result = await f.service[mode](input(repo));
    assert.equal(result.mode, mode);
    assert.equal(result.result.untrusted, true);
    assert.deepEqual(f.source, { files: 'files:1', index: 'index:1', head: 'head:1', branch: 'main', refs: 'refs:1', untracked: 'untracked:1' });
    assert.equal(f.snapshotFiles['src/a.js'], 'aggressive write');
    assert.equal(f.events.filter(([event]) => event === 'fingerprint').length, 2);
    assert.equal(f.events.at(-1)[0], 'fingerprint');
    const run = f.events.find(([event]) => event === 'runner')[1];
    assert.equal(run.mode, mode);
    assert.equal(run.scope.cwd, '/tmp/snapshot-1');
    assert.equal(Object.hasOwn(run, 'repository'), false);
  }
});

test('any source fingerprint mutation is refused after snapshot cleanup', async () => {
  const repo = await repository();
  const f = fixture({ mutateSource: true });
  await assert.rejects(f.service.ask(input(repo)), (error) => error.code === 'SAFETY_REFUSAL');
  assert.equal(f.events.some(([event]) => event === 'snapshot-cleanup'), true);
  assert.equal(f.events.filter(([event]) => event === 'fingerprint').length, 2);
});

test('runner and fingerprint failures are sanitized while cleanup and post-run fingerprint checks still occur', async () => {
  const repo = await repository();
  const runner = fixture({ runnerFailure: true });
  await assert.rejects(runner.service.plan(input(repo)),
    (error) => error.code === 'SAFETY_REFUSAL' && !error.message.includes('canary'));
  assert.equal(runner.events.some(([event]) => event === 'snapshot-cleanup'), true);
  assert.equal(runner.events.filter(([event]) => event === 'fingerprint').length, 2);

  const fingerprint = fixture({ fingerprintFailure: true });
  await assert.rejects(fingerprint.service.ask(input(repo)),
    (error) => error.code === 'SAFETY_REFUSAL' && !error.message.includes('canary'));
  assert.equal(fingerprint.events.some(([event]) => event === 'runner'), false);
});

test('forged repository records, unknown fields, empty prompts, malformed paths, and hostile accessors fail before snapshot creation', async () => {
  const repo = await repository();
  const cases = [
    input({ ...repo }), input(repo, { extra: true }), input(repo, { prompt: '' }),
    input(repo, { paths: [] }), input(repo, { paths: ['../escape'] })
  ];
  for (const candidate of cases) {
    const f = fixture();
    await assert.rejects(f.service.ask(candidate), (error) => error.code === 'SAFETY_REFUSAL');
    assert.equal(f.events.length, 0);
  }
  const f = fixture();
  const hostile = new Proxy({}, { ownKeys: () => { throw new Error('private input canary'); } });
  await assert.rejects(f.service.ask(hostile), (error) => error.code === 'SAFETY_REFUSAL' && !error.message.includes('canary'));
});
