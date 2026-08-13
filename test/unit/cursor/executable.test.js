import assert from 'node:assert/strict';
import test from 'node:test';

import { revalidateCursorExecutableBinding, resolveCursorAgentExecutable } from '../../../src/cursor/executable.js';

const A = Object.freeze({ name: 'cursor-agent-target' });
const B = Object.freeze({ name: 'agent-target' });

test('prefers the verified cursor-agent alias over agent and every fallback location', async () => {
  const calls = [];
  const result = await resolveCursorAgentExecutable({
    candidates: [
      { command: 'agent', source: 'path', target: B },
      { command: 'cursor-agent', source: 'fallback', target: A },
      { command: 'cursor-agent', source: 'path', target: A }
    ],
    verifyTarget: async (candidate) => { calls.push(candidate); return candidate.target === A ? candidate.target : null; },
    verifyVersion: async (target) => target === A
  });
  assert.deepEqual(result, { command: 'cursor-agent', source: 'path', target: A });
  assert.deepEqual(calls.map(({ command, source }) => [command, source]), [['cursor-agent', 'path']]);
  assert.equal(Object.isFrozen(result), true);
});

test('uses documented fallback locations before considering the ambiguous agent alias', async () => {
  const calls = [];
  const result = await resolveCursorAgentExecutable({
    candidates: [
      { command: 'agent', source: 'path', target: B },
      { command: 'cursor-agent', source: 'fallback', target: A }
    ],
    verifyTarget: async (candidate) => { calls.push(candidate); return candidate.target; },
    verifyVersion: async (target) => target === A
  });
  assert.equal(result.target, A);
  assert.deepEqual(calls.map(({ command, source }) => [command, source]), [['cursor-agent', 'fallback']]);
});

test('skips unrelated agent aliases and accepts agent only after positive Cursor version identification', async () => {
  const calls = [];
  await assert.rejects(resolveCursorAgentExecutable({
    candidates: [{ command: 'agent', source: 'path', target: B }],
    verifyTarget: async ({ target }) => target,
    verifyVersion: async (target) => { calls.push(target); return false; }
  }), (error) => error.code === 'CAPABILITY_UNSUPPORTED');
  assert.deepEqual(calls, [B]);
});

test('refuses duplicate candidate identities, hostile fields, arbitrary commands, and unverified targets', async () => {
  const cases = [
    [{ command: 'cursor-agent', source: 'path', target: A }, { command: 'cursor-agent', source: 'path', target: A }],
    [{ command: 'other', source: 'path', target: A }],
    [{ command: 'cursor-agent', source: 'hostile', target: A }],
    [{ command: 'cursor-agent', source: 'path', target: A, extra: true }]
  ];
  for (const candidates of cases) {
    await assert.rejects(resolveCursorAgentExecutable({ candidates, verifyTarget: async () => null, verifyVersion: async () => true }),
      (error) => error.code === 'CAPABILITY_UNSUPPORTED');
  }
  await assert.rejects(resolveCursorAgentExecutable({
    candidates: [{ command: 'cursor-agent', source: 'path', target: A }],
    verifyTarget: async () => null,
    verifyVersion: async () => true
  }), (error) => error.code === 'CAPABILITY_UNSUPPORTED');
});

test('sanitizes hostile candidate and verifier diagnostics', async () => {
  const hostile = new Proxy({}, { ownKeys: () => { throw new Error('private cursor canary'); } });
  await assert.rejects(resolveCursorAgentExecutable({ candidates: [hostile], verifyTarget: async () => A, verifyVersion: async () => true }),
    (error) => error.code === 'CAPABILITY_UNSUPPORTED' && !error.message.includes('canary'));
  await assert.rejects(resolveCursorAgentExecutable({
    candidates: [{ command: 'cursor-agent', source: 'path', target: A }],
    verifyTarget: async () => { throw new Error('private verifier canary'); }, verifyVersion: async () => true
  }), (error) => error.code === 'CAPABILITY_UNSUPPORTED' && !error.message.includes('canary'));
});

test('binding revalidation uses the captured target and version verifiers and detects a later swap', async () => {
  let current = A;
  const binding = await resolveCursorAgentExecutable({
    candidates: [{ command: 'cursor-agent', source: 'path', target: A }],
    verifyTarget: async () => current,
    verifyVersion: async (target) => target === A
  });
  assert.equal(await revalidateCursorExecutableBinding(binding), true);
  current = B;
  assert.equal(await revalidateCursorExecutableBinding(binding), false);
});
