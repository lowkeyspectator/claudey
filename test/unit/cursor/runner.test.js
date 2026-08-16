import assert from 'node:assert/strict';
import test from 'node:test';

import { probeCursorCapabilities } from '../../../src/cursor/capabilities.js';
import { buildCursorEnvironment } from '../../../src/cursor/env.js';
import { resolveCursorAgentExecutable } from '../../../src/cursor/executable.js';
import { listCursorModels } from '../../../src/cursor/models.js';
import { createCursorRunner, createCursorRunScope } from '../../../src/cursor/runner.js';

const TARGET = Object.freeze({ name: 'verified-cursor' });
const BINDING = await resolveCursorAgentExecutable({
  candidates: [{ command: 'cursor-agent', source: 'path', target: TARGET }],
  verifyTarget: async ({ target }) => target, verifyVersion: async () => true
});
const OTHER_BINDING = await resolveCursorAgentExecutable({
  candidates: [{ command: 'cursor-agent', source: 'fallback', target: Object.freeze({ name: 'other-cursor' }) }],
  verifyTarget: async ({ target }) => target, verifyVersion: async () => true
});

function probeInvoke({ args, stdin }) {
  const key = args.join(' ');
  const values = {
    '--version': 'Cursor Agent 1.0.0\n', 'status --json': '{"authenticated":true}\n',
    'models --json': '{"models":[{"id":"cursor-model"}]}\n',
    'probe json --json': '{"type":"probe","capability":"json","framing":"json-lines"}\n',
    'probe mode ask --json': '{"type":"probe","capability":"ask","supported":true}\n',
    'probe mode plan --json': '{"type":"probe","capability":"plan","supported":true}\n',
    'probe mode worktree --json': '{"type":"probe","capability":"worktree","supported":true}\n',
    'probe sandbox read-only --json': '{"type":"probe","capability":"sandbox","supported":true}\n'
  };
  const stdout = key === 'probe stdin --json'
    ? `${JSON.stringify({ type: 'probe', capability: 'stdin', echo: stdin })}\n` : values[key];
  return { code: stdout ? 0 : 2, stdout: stdout ?? '', stderr: '' };
}

const CAPS = await probeCursorCapabilities(BINDING, { invoke: probeInvoke, nonceFactory: () => 'runner' });
const CATALOG = await listCursorModels(BINDING, CAPS, { invoke: probeInvoke });
const ENV = buildCursorEnvironment({ HOME: '/home/casey', PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' }, { platform: 'linux' });
const SNAPSHOT = createCursorRunScope({ kind: 'snapshot', cwd: '/tmp/claudey-snapshot-1', platform: 'linux' });
const WORKTREE = createCursorRunScope({ kind: 'worktree', cwd: '/tmp/claudey-worktree-1', platform: 'linux' });

function request(mode, scope, overrides = {}) {
  return {
    binding: BINDING, capabilities: CAPS, catalog: CATALOG, environment: ENV,
    mode, prompt: 'private prompt canary', model: 'cursor-model', scope, ...overrides
  };
}

function makeRunner(services) {
  return createCursorRunner({ revalidateModel: async () => true, ...services });
}

test('ask, plan, and worktree use fixed argv/cwd/env/caps with prompt only on stdin', async () => {
  const calls = [];
  const rechecks = [];
  let bindingRechecks = 0;
  const runner = makeRunner({
    revalidateBinding: async () => { bindingRechecks += 1; return true; },
    revalidateScope: async (scope) => { rechecks.push(scope); return true; },
    invoke: async (invocation) => {
      calls.push(invocation);
      return { code: 0, stdout: '{"answer":"untrusted"}\n', stderr: '', cleanupConfirmed: true };
    }
  });
  for (const [mode, scope] of [['ask', SNAPSHOT], ['plan', SNAPSHOT], ['worktree', WORKTREE]]) {
    const result = await runner.run(request(mode, scope));
    assert.deepEqual(result, { type: 'cursor-result', untrusted: true, value: { answer: 'untrusted' } });
  }
  assert.deepEqual(calls.map(({ args }) => args), [
    ['--mode', 'ask', '--print', '--output-format', 'json', '--sandbox', 'read-only', '--model', 'cursor-model'],
    ['--mode', 'plan', '--print', '--output-format', 'json', '--sandbox', 'read-only', '--model', 'cursor-model'],
    ['--mode', 'worktree', '--print', '--output-format', 'json', '--model', 'cursor-model']
  ]);
  assert.deepEqual(calls.map(({ cwd }) => cwd), [SNAPSHOT.cwd, SNAPSHOT.cwd, WORKTREE.cwd]);
  for (const call of calls) {
    assert.equal(call.stdin, 'private prompt canary');
    assert.equal(JSON.stringify(call.args).includes('private prompt canary'), false);
    assert.equal(JSON.stringify(call.env).includes('private prompt canary'), false);
    assert.equal(call.timeoutMs, 120_000);
    assert.equal(call.maxStdoutBytes, 1_048_576);
    assert.equal(call.maxStderrBytes, 16_384);
  }
  assert.deepEqual(rechecks, [SNAPSHOT, SNAPSHOT, WORKTREE]);
  assert.equal(bindingRechecks, 3);
});

test('rejects unknown and option-shaped models before scope revalidation or spawn', async () => {
  let sideEffects = 0;
  const runner = makeRunner({
    revalidateScope: async () => { sideEffects += 1; return true; },
    invoke: async () => { sideEffects += 1; return { code: 0, stdout: '{}\n', stderr: '' }; }
  });
  for (const model of ['missing', '--help', 'x\nprivate']) {
    await assert.rejects(runner.run(request('ask', SNAPSHOT, { model })), (error) => error.code === 'MODEL_NOT_FOUND');
  }
  assert.equal(sideEffects, 0);
});

test('refuses arbitrary executable, flags, environment, cwd, wrong scope kind, and forged records', async () => {
  const runner = makeRunner({ revalidateScope: async () => true, invoke: async () => ({ code: 0, stdout: '{}\n', stderr: '' }) });
  const hostileRequests = [
    { ...request('ask', SNAPSHOT), executable: 'evil' },
    { ...request('ask', SNAPSHOT), args: ['--evil'] },
    { ...request('ask', SNAPSHOT), env: { TOKEN: 'private' } },
    { ...request('ask', SNAPSHOT), cwd: '/foreign' },
    request('ask', WORKTREE), request('worktree', SNAPSHOT),
    request('ask', SNAPSHOT, { binding: { ...BINDING } }),
    request('ask', SNAPSHOT, { binding: OTHER_BINDING }),
    request('ask', SNAPSHOT, { capabilities: structuredClone(CAPS) }),
    request('ask', SNAPSHOT, { catalog: structuredClone(CATALOG) }),
    request('ask', SNAPSHOT, { environment: { ...ENV } }),
    request('ask', { ...SNAPSHOT })
  ];
  for (const hostile of hostileRequests) {
    await assert.rejects(runner.run(hostile), (error) => error.code === 'SAFETY_REFUSAL' || error.code === 'CAPABILITY_UNSUPPORTED');
  }
});

test('enforces prompt/output bounds, strict JSON, nonzero/cleanup failures, and sanitizes diagnostics', async () => {
  const outcomes = [
    { code: 0, stdout: 'not-json\n', stderr: '', cleanupConfirmed: true },
    { code: 2, stdout: '{}\n', stderr: '', cleanupConfirmed: true },
    { code: 0, stdout: '{}\n', stderr: 'private stderr canary', cleanupConfirmed: true },
    { code: 0, stdout: '{}\n', stderr: '', cleanupConfirmed: false },
    { code: 0, stdout: `${'x'.repeat(1_048_577)}\n`, stderr: '', cleanupConfirmed: true }
  ];
  for (const outcome of outcomes) {
    const runner = makeRunner({ revalidateScope: async () => true, invoke: async () => outcome });
    await assert.rejects(runner.run(request('ask', SNAPSHOT)),
      (error) => error.code === 'CAPABILITY_UNSUPPORTED' && !error.message.includes('canary'));
  }
  const runner = makeRunner({ revalidateScope: async () => true, invoke: async () => ({ code: 0, stdout: '{}\n', stderr: '' }) });
  await assert.rejects(runner.run(request('ask', SNAPSHOT, { prompt: 'x'.repeat(32_769) })),
    (error) => error.code === 'SAFETY_REFUSAL');
});

test('allows at most three simultaneous runs and passes cancellation only to the fixed invocation', async () => {
  const resolvers = [];
  const controller = new AbortController();
  const runner = makeRunner({
    revalidateScope: async () => true,
    invoke: (invocation) => new Promise((resolve) => resolvers.push({ invocation, resolve }))
  });
  const running = [0, 1, 2].map(() => runner.run(request('ask', SNAPSHOT, { signal: controller.signal })));
  await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(runner.run(request('ask', SNAPSHOT)), (error) => error.code === 'CAPABILITY_UNSUPPORTED');
  assert.equal(resolvers.length, 3);
  assert.equal(resolvers.every(({ invocation }) => invocation.signal === controller.signal), true);
  for (const { resolve } of resolvers) resolve({ code: 0, stdout: '{}\n', stderr: '', cleanupConfirmed: true });
  await Promise.all(running);
});

test('scope creation rejects roots, relative/control paths, unknown fields, and unsupported kinds', () => {
  for (const value of [
    { kind: 'snapshot', cwd: 'relative', platform: 'linux' },
    { kind: 'snapshot', cwd: '/', platform: 'linux' },
    { kind: 'other', cwd: '/tmp/safe', platform: 'linux' },
    { kind: 'snapshot', cwd: '/tmp/bad\npath', platform: 'linux' },
    { kind: 'snapshot', cwd: '/tmp/safe', platform: 'linux', extra: true }
  ]) assert.throws(() => createCursorRunScope(value), (error) => error.code === 'SAFETY_REFUSAL');
});

test('binding or scope identity change prevents spawn', async () => {
  for (const [revalidateBinding, revalidateScope] of [[async () => false, async () => true], [async () => true, async () => false]]) {
    let calls = 0;
    const runner = makeRunner({
      revalidateBinding, revalidateScope,
      invoke: async () => { calls += 1; return { code: 0, stdout: '{}\n', stderr: '', cleanupConfirmed: true }; }
    });
    await assert.rejects(runner.run(request('ask', SNAPSHOT)), (error) => error.code === 'SAFETY_REFUSAL');
    assert.equal(calls, 0);
  }
});

test('live-model revalidation failure prevents scope use and spawn', async () => {
  let calls = 0;
  const runner = createCursorRunner({
    revalidateBinding: async () => true,
    revalidateModel: async () => false,
    revalidateScope: async () => { calls += 1; return true; },
    invoke: async () => { calls += 1; return { code: 0, stdout: '{}\n', stderr: '', cleanupConfirmed: true }; }
  });
  await assert.rejects(runner.run(request('ask', SNAPSHOT)), (error) => error.code === 'MODEL_NOT_FOUND');
  assert.equal(calls, 0);
});
