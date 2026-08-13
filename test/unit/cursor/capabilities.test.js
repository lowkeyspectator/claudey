import assert from 'node:assert/strict';
import test from 'node:test';

import { probeCursorCapabilities } from '../../../src/cursor/capabilities.js';
import { resolveCursorAgentExecutable } from '../../../src/cursor/executable.js';

const TARGET = Object.freeze({ name: 'verified-cursor' });
const BINDING = await resolveCursorAgentExecutable({
  candidates: [{ command: 'cursor-agent', source: 'path', target: TARGET }],
  verifyTarget: async ({ target }) => target,
  verifyVersion: async () => true
});

function runner(overrides = {}, calls = []) {
  return async (request) => {
    calls.push(request);
    const key = request.args.join(' ');
    const values = {
      '--version': 'Cursor Agent 1.0.0\n',
      'status --json': '{"authenticated":true}\n',
      'models --json': '{"models":[{"id":"cursor-z"},{"id":"cursor-a"}]}\n',
      'probe json --json': '{"type":"probe","capability":"json","framing":"json-lines"}\n',
      'probe stdin --json': `${JSON.stringify({ type: 'probe', capability: 'stdin', echo: request.stdin })}\n`,
      'probe mode ask --json': '{"type":"probe","capability":"ask","supported":true}\n',
      'probe mode plan --json': '{"type":"probe","capability":"plan","supported":true}\n',
      'probe mode worktree --json': '{"type":"probe","capability":"worktree","supported":true}\n',
      'probe sandbox read-only --json': '{"type":"probe","capability":"sandbox","supported":true}\n'
    };
    const result = Object.hasOwn(overrides, key) ? overrides[key] : values[key];
    return typeof result === 'object' ? result : { code: result === undefined ? 2 : 0, stdout: result ?? '', stderr: '' };
  };
}

test('probes every Cursor capability separately with nonce only on stdin and advertises exact tools', async () => {
  const calls = [];
  let rechecks = 0;
  const result = await probeCursorCapabilities(BINDING, {
    invoke: runner({}, calls), nonceFactory: () => 'nonce-13',
    revalidateBinding: async () => { rechecks += 1; return true; }
  });
  assert.deepEqual(result.tools, {
    models: { available: true, code: 'AVAILABLE' },
    ask: { available: true, code: 'AVAILABLE' },
    plan: { available: true, code: 'AVAILABLE' },
    worktree: { available: true, code: 'AVAILABLE' }
  });
  assert.deepEqual(calls.map(({ args }) => args), [
    ['--version'], ['status', '--json'], ['models', '--json'], ['probe', 'json', '--json'], ['probe', 'stdin', '--json'],
    ['probe', 'mode', 'ask', '--json'], ['probe', 'mode', 'plan', '--json'], ['probe', 'mode', 'worktree', '--json'],
    ['probe', 'sandbox', 'read-only', '--json']
  ]);
  const stdin = calls.find(({ args }) => args[1] === 'stdin');
  assert.equal(stdin.stdin, 'nonce:nonce-13');
  assert.equal(JSON.stringify(stdin.args).includes('nonce-13'), false);
  assert.equal(rechecks, calls.length);
  assert.equal(Object.isFrozen(result), true);
});

test('logged-out status marks every tool AUTH_REQUIRED without confusing it with malformed status', async () => {
  const loggedOut = await probeCursorCapabilities(BINDING, { invoke: runner({
    'status --json': '{"authenticated":false}\n'
  }), nonceFactory: () => 'nonce' });
  assert.deepEqual(Object.values(loggedOut.tools).map(({ code }) => code),
    ['AUTH_REQUIRED', 'AUTH_REQUIRED', 'AUTH_REQUIRED', 'AUTH_REQUIRED']);
  const malformed = await probeCursorCapabilities(BINDING, { invoke: runner({
    'status --json': '{"authenticated":"yes"}\n'
  }), nonceFactory: () => 'nonce' });
  assert.deepEqual(Object.values(malformed.tools).map(({ code }) => code),
    ['CAPABILITY_UNSUPPORTED', 'CAPABILITY_UNSUPPORTED', 'CAPABILITY_UNSUPPORTED', 'CAPABILITY_UNSUPPORTED']);
});

test('missing ask, plan, worktree, or sandbox capability degrades only dependent tools', async () => {
  const cases = [
    ['probe mode ask --json', '{"type":"probe","capability":"ask","supported":false}\n', [true, false, true, true]],
    ['probe mode plan --json', '{"type":"probe","capability":"plan","supported":false}\n', [true, true, false, true]],
    ['probe mode worktree --json', '{"type":"probe","capability":"worktree","supported":false}\n', [true, true, true, false]],
    ['probe sandbox read-only --json', '{"type":"probe","capability":"sandbox","supported":false}\n', [true, false, false, true]]
  ];
  for (const [key, value, expected] of cases) {
    const result = await probeCursorCapabilities(BINDING, { invoke: runner({ [key]: value }), nonceFactory: () => 'nonce' });
    assert.deepEqual(Object.values(result.tools).map(({ available }) => available), expected, key);
  }
});

test('uses the model fallback only after primary failure and rejects empty, duplicate, or malformed model output', async () => {
  const calls = [];
  const fallback = await probeCursorCapabilities(BINDING, { invoke: runner({
    'models --json': { code: 2, stdout: '', stderr: '' },
    '--list-models --json': '{"models":[{"id":"fallback"}]}\n'
  }, calls), nonceFactory: () => 'nonce' });
  assert.equal(fallback.models.available, true);
  assert.deepEqual(calls.filter(({ args }) => args.includes('models') || args.includes('--list-models')).map(({ args }) => args),
    [['models', '--json'], ['--list-models', '--json']]);
  const malformedCalls = [];
  const malformedPrimary = await probeCursorCapabilities(BINDING, { invoke: runner({
    'models --json': '{"models":"malformed"}\n',
    '--list-models --json': '{"models":[{"id":"must-not-mask"}]}\n'
  }, malformedCalls), nonceFactory: () => 'nonce' });
  assert.equal(malformedPrimary.models.available, false);
  assert.deepEqual(malformedCalls.filter(({ args }) => args.includes('models') || args.includes('--list-models')).map(({ args }) => args),
    [['models', '--json']]);
  for (const output of ['{"models":[]}\n', '{"models":[{"id":"x"},{"id":"x"}]}\n', '{"models":"x"}\n']) {
    const result = await probeCursorCapabilities(BINDING, { invoke: runner({
      'models --json': output, '--list-models --json': output
    }), nonceFactory: () => 'nonce' });
    assert.equal(result.tools.models.available, false);
  }
});

test('forged bindings, invalid nonces, warning output, output overflow, and invocation failures fail closed', async () => {
  await assert.rejects(probeCursorCapabilities({ ...BINDING }, { invoke: runner(), nonceFactory: () => 'nonce' }),
    (error) => error.code === 'CAPABILITY_UNSUPPORTED');
  for (const nonceFactory of [() => '', () => 'x\nprivate']) {
    await assert.rejects(probeCursorCapabilities(BINDING, { invoke: runner(), nonceFactory }),
      (error) => error.code === 'CAPABILITY_UNSUPPORTED');
  }
  const warned = await probeCursorCapabilities(BINDING, { invoke: runner({
    '--version': { code: 0, stdout: 'Cursor Agent 1.0.0\n', stderr: 'warning\n' }
  }), nonceFactory: () => 'nonce' });
  assert.equal(warned.tools.models.available, false);
  const overflow = await probeCursorCapabilities(BINDING, { invoke: runner({
    '--version': { code: 0, stdout: `Cursor Agent ${'9'.repeat(16_385)}\n`, stderr: '' }
  }), nonceFactory: () => 'nonce' });
  assert.equal(overflow.tools.models.available, false);
  let calls = 0;
  const swapped = await probeCursorCapabilities(BINDING, {
    invoke: async () => { calls += 1; return { code: 0, stdout: 'Cursor Agent 1.0.0\n', stderr: '' }; },
    revalidateBinding: async () => false,
    nonceFactory: () => 'nonce'
  });
  assert.equal(calls, 0);
  assert.equal(swapped.tools.models.available, false);
});
