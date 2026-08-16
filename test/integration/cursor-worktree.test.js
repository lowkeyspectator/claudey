import assert from 'node:assert/strict';
import test from 'node:test';

import { createCursorRepositoryRegistry } from '../../src/cursor/registry.js';
import { createCursorWorktreeService } from '../../src/cursor/worktree.js';

const ROOT = '/home/casey/project';
const COMMIT = 'a'.repeat(40);
const UUID = '11111111-1111-4111-8111-111111111111';

async function repository() {
  const registry = createCursorRepositoryRegistry({
    platform: 'linux', homeRoot: '/home/casey', installationId: UUID,
    readRecord: async () => ({ schemaVersion: 1, installationId: UUID, repositories: [{ root: ROOT, scope: 'user' }] }),
    writeRecord: async () => undefined,
    inspectRepository: async (candidate) => ({ exists: true, type: 'directory', canonicalPath: candidate, gitRoot: ROOT,
      isLink: false, isJunction: false, isReparsePoint: false, isBare: false, owner: 'current' })
  });
  return (await registry.list())[0];
}

function fixture({
  runnerFailure = false, linksSafe = true, writesEnabled = true, platform = 'linux',
  worktreeRoot = platform === 'win32' ? 'C:\\Users\\Casey\\AppData\\Local\\claudeyctl\\worktrees'
    : '/home/casey/.local/state/claudeyctl/worktrees',
  requestResult, consumeResult, addResult, addFailure = false, collectFailure = false
} = {}) {
  const events = [];
  const approvalService = {
    request: async (binding) => { events.push(['request-approval', binding]); return requestResult
      ?? { code: 'APPROVAL_REQUIRED', approvalId: 'approval-1', expiresAt: 300_000 }; },
    consume: async (id, binding) => { events.push(['consume-approval', id, binding]); return consumeResult
      ?? { action: 'consumed', approvalId: id }; }
  };
  const git = {
    resolveBase: async (base) => { events.push(['resolve-base', base]); return COMMIT; },
    addWorktree: async (request) => {
      events.push(['add-worktree', request]);
      if (addFailure) throw new Error('private git canary');
      return addResult ?? { action: 'created', ...request };
    }
  };
  const runner = {
    run: async (request) => {
      events.push(['run-cursor', request]);
      if (runnerFailure) throw new Error('private cursor canary');
      return { type: 'cursor-result', untrusted: true, value: { text: 'done' } };
    }
  };
  const service = createCursorWorktreeService({
    installationId: UUID, writesEnabled, platform, worktreeRoot,
    approvalService, git, runner, randomId: () => 'abc123',
    assertWorktreeNoLinks: async (path) => { events.push(['scan-links', path]); return linksSafe; },
    collectResult: async (path) => { events.push(['collect-result', path]);
      if (collectFailure) throw new Error('private status canary');
      return {
      status: ' M src/a.js', diff: { files: 1, insertions: 2, deletions: 0 }, sharedMetadata: { branchCreated: true, worktreeRegistered: true }
      }; }
  });
  return { service, events };
}

function input(repo, overrides = {}) {
  return { repository: repo, prompt: 'exact private prompt', model: 'cursor-model', baseRef: 'refs/heads/main', ...overrides };
}

test('first write request creates only a bound approval and neither worktree nor branch', async () => {
  const repo = await repository();
  const f = fixture();
  const result = await f.service.run(input(repo));
  assert.equal(result.code, 'APPROVAL_REQUIRED');
  assert.deepEqual(f.events.map(([event]) => event), ['resolve-base', 'request-approval']);
  assert.equal(f.events[1][1].baseCommit, COMMIT);
  assert.equal(f.events[1][1].installationId, UUID);
});

test('second request consumes exact approval immediately before fixed worktree creation, scans links, runs, and retains result', async () => {
  const repo = await repository();
  const f = fixture();
  const controller = new AbortController();
  const result = await f.service.run(input(repo, { approvalId: 'approval-1' }), { signal: controller.signal });
  assert.deepEqual(f.events.map(([event]) => event), [
    'resolve-base', 'consume-approval', 'add-worktree', 'scan-links', 'run-cursor', 'collect-result'
  ]);
  assert.deepEqual(f.events[2][1], {
    branch: 'claudey/cursor-abc123', path: '/home/casey/.local/state/claudeyctl/worktrees/abc123', commit: COMMIT
  });
  assert.equal(f.events[4][1].scope.kind, 'worktree');
  assert.equal(f.events[4][1].signal, controller.signal);
  assert.equal(Object.hasOwn(f.events[4][1], 'repository'), false);
  assert.equal(result.state, 'retained');
  assert.equal(result.branch, 'claudey/cursor-abc123');
  assert.equal(result.baseCommit, COMMIT);
  assert.equal(result.status, ' M src/a.js');
  assert.deepEqual(result.diff, { files: 1, insertions: 2, deletions: 0 });
});

test('post-materialization link scan failure and Cursor failure retain the worktree and never clean, commit, merge, push, or copy back', async () => {
  const repo = await repository();
  const linked = fixture({ linksSafe: false });
  await assert.rejects(linked.service.run(input(repo, { approvalId: 'approval-1' })),
    (error) => error.code === 'SAFETY_REFUSAL');
  assert.equal(linked.events.some(([event]) => event === 'run-cursor'), false);
  assert.equal(linked.events.some(([event]) => /clean|commit|merge|push|copy/iu.test(event)), false);

  const failed = fixture({ runnerFailure: true });
  const result = await failed.service.run(input(repo, { approvalId: 'approval-1' }));
  assert.equal(result.state, 'retained-failed');
  assert.equal(JSON.stringify(result).includes('private cursor canary'), false);
  assert.equal(failed.events.some(([event]) => /clean|commit|merge|push|copy/iu.test(event)), false);
});

test('writes-disabled, forged repo, unknown fields, hostile base/approval/model/prompt, and unsafe result schemas fail closed', async () => {
  const repo = await repository();
  const disabled = fixture({ writesEnabled: false });
  await assert.rejects(disabled.service.run(input(repo)), (error) => error.code === 'CAPABILITY_UNSUPPORTED');
  assert.deepEqual(disabled.events, []);
  const cases = [
    input({ ...repo }), input(repo, { extra: true }), input(repo, { baseRef: '--help' }),
    input(repo, { approvalId: '' }), input(repo, { model: '--help' }), input(repo, { prompt: '' })
  ];
  for (const candidate of cases) {
    const f = fixture();
    await assert.rejects(f.service.run(candidate), (error) => error.code === 'SAFETY_REFUSAL');
  }
});

test('uses the declared Windows path family for generated worktrees and the runner scope', async () => {
  const repo = await repository();
  const f = fixture({ platform: 'win32' });
  const result = await f.service.run(input(repo, { approvalId: 'approval-1' }));
  assert.equal(result.path, 'C:\\Users\\Casey\\AppData\\Local\\claudeyctl\\worktrees\\abc123');
  assert.equal(f.events.find(([event]) => event === 'run-cursor')[1].scope.platform, 'win32');
});

test('refuses malformed approval, consumption, and Git creation boundary results', async () => {
  const repo = await repository();
  for (const options of [
    { requestResult: { code: 'APPROVAL_REQUIRED', approvalId: 'approval-1', expiresAt: 300_000, secret: 'leak' } },
    { consumeResult: { action: 'preserved', approvalId: 'approval-1' } },
    { addResult: { action: 'created', branch: 'different', path: '/tmp/other', commit: COMMIT } }
  ]) {
    const f = fixture(options);
    const candidate = options.requestResult ? input(repo) : input(repo, { approvalId: 'approval-1' });
    await assert.rejects(f.service.run(candidate), (error) => error.code === 'SAFETY_REFUSAL');
    assert.equal(f.events.some(([event]) => event === 'run-cursor'), false);
  }
});

test('reports the retained recovery identity when creation or result collection is unconfirmed', async () => {
  const repo = await repository();
  for (const options of [{ addFailure: true }, { runnerFailure: true, collectFailure: true }]) {
    const f = fixture(options);
    await assert.rejects(f.service.run(input(repo, { approvalId: 'approval-1' })), (error) => {
      assert.equal(error.code, 'SAFETY_REFUSAL');
      assert.deepEqual(error.details, {
        retained: true, path: '/home/casey/.local/state/claudeyctl/worktrees/abc123',
        branch: 'claudey/cursor-abc123', baseCommit: COMMIT
      });
      assert.equal(JSON.stringify(error).includes('private'), false);
      return true;
    });
  }
});
