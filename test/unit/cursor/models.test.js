import assert from 'node:assert/strict';
import test from 'node:test';

import { probeCursorCapabilities } from '../../../src/cursor/capabilities.js';
import { resolveCursorAgentExecutable } from '../../../src/cursor/executable.js';
import { listCursorModels, requireCursorModel } from '../../../src/cursor/models.js';

const TARGET = Object.freeze({ name: 'cursor' });
const BINDING = await resolveCursorAgentExecutable({
  candidates: [{ command: 'cursor-agent', source: 'path', target: TARGET }],
  verifyTarget: async ({ target }) => target, verifyVersion: async () => true
});
const CAPS = await probeCursorCapabilities(BINDING, {
  nonceFactory: () => 'models',
  invoke: async ({ args, stdin }) => {
    const values = {
      '--version': 'Cursor Agent 1.0.0\n', 'status --json': '{"authenticated":true}\n',
      'models --json': '{"models":[{"id":"z"}]}\n',
      'probe json --json': '{"type":"probe","capability":"json","framing":"json-lines"}\n',
      'probe mode ask --json': '{"type":"probe","capability":"ask","supported":true}\n',
      'probe mode plan --json': '{"type":"probe","capability":"plan","supported":true}\n',
      'probe mode worktree --json': '{"type":"probe","capability":"worktree","supported":true}\n',
      'probe sandbox read-only --json': '{"type":"probe","capability":"sandbox","supported":true}\n'
    };
    const key = args.join(' ');
    const stdout = key === 'probe stdin --json'
      ? `${JSON.stringify({ type: 'probe', capability: 'stdin', echo: stdin })}\n` : values[key];
    return { code: stdout ? 0 : 2, stdout: stdout ?? '', stderr: '' };
  }
});

test('loads a current live Cursor catalog, validates exact shape, and sorts deterministically', async () => {
  const calls = [];
  let rechecks = 0;
  const catalog = await listCursorModels(BINDING, CAPS, { invoke: async (request) => {
    calls.push(request);
    return { code: 0, stdout: '{"models":[{"id":"z-model"},{"id":"a-model"}]}\n', stderr: '' };
  }, revalidateBinding: async () => { rechecks += 1; return true; } });
  assert.deepEqual(catalog.models, ['a-model', 'z-model']);
  assert.deepEqual(calls.map(({ args }) => args), [['models', '--json']]);
  assert.equal(rechecks, 1);
  assert.equal(Object.isFrozen(catalog.models), true);
  assert.equal(requireCursorModel(catalog, 'a-model'), 'a-model');
});

test('uses --list-models only after current command failure', async () => {
  const calls = [];
  const catalog = await listCursorModels(BINDING, CAPS, { invoke: async ({ args }) => {
    calls.push(args);
    return args[0] === 'models' ? { code: 2, stdout: '', stderr: '' }
      : { code: 0, stdout: '{"models":[{"id":"fallback"}]}\n', stderr: '' };
  } });
  assert.deepEqual(catalog.models, ['fallback']);
  assert.deepEqual(calls, [['models', '--json'], ['--list-models', '--json']]);
});

test('a successful malformed current model response fails closed without compatibility fallback', async () => {
  const calls = [];
  await assert.rejects(listCursorModels(BINDING, CAPS, { invoke: async ({ args }) => {
    calls.push(args);
    return { code: 0, stdout: args[0] === 'models' ? '{"models":"bad"}\n' : '{"models":[{"id":"masked"}]}\n', stderr: '' };
  } }), (error) => error.code === 'CAPABILITY_UNSUPPORTED');
  assert.deepEqual(calls, [['models', '--json']]);
});

test('rejects empty, duplicate, malformed, noisy, nonzero, and oversized catalogs', async () => {
  const outputs = [
    '{"models":[]}\n', '{"models":[{"id":"x"},{"id":"x"}]}\n', '{"models":"x"}\n',
    '{"models":[{"id":"x"}]}\nextra\n', `${'x'.repeat(16_385)}\n`
  ];
  for (const stdout of outputs) {
    await assert.rejects(listCursorModels(BINDING, CAPS, { invoke: async () => ({ code: 0, stdout, stderr: '' }) }),
      (error) => error.code === 'CAPABILITY_UNSUPPORTED');
  }
  await assert.rejects(listCursorModels(BINDING, CAPS, { invoke: async () => ({ code: 2, stdout: '', stderr: '' }) }),
    (error) => error.code === 'CAPABILITY_UNSUPPORTED');
});

test('rejects unknown or option-shaped model IDs before downstream execution', async () => {
  const catalog = await listCursorModels(BINDING, CAPS, { invoke: async () => ({
    code: 0, stdout: '{"models":[{"id":"cursor-model"}]}\n', stderr: ''
  }) });
  for (const model of ['missing', '--help', 'x\nprivate']) {
    assert.throws(() => requireCursorModel(catalog, model), (error) => error.code === 'MODEL_NOT_FOUND');
  }
});

test('forged executable, capability, or catalog records are refused', async () => {
  await assert.rejects(listCursorModels({ ...BINDING }, CAPS, { invoke: async () => ({ code: 0, stdout: '{}\n', stderr: '' }) }),
    (error) => error.code === 'CAPABILITY_UNSUPPORTED');
  await assert.rejects(listCursorModels(BINDING, structuredClone(CAPS), { invoke: async () => ({ code: 0, stdout: '{}\n', stderr: '' }) }),
    (error) => error.code === 'CAPABILITY_UNSUPPORTED');
  assert.throws(() => requireCursorModel({ models: ['cursor-model'] }, 'cursor-model'),
    (error) => error.code === 'SAFETY_REFUSAL');
});

test('an executable identity change prevents every live model invocation', async () => {
  let calls = 0;
  await assert.rejects(listCursorModels(BINDING, CAPS, {
    revalidateBinding: async () => false,
    invoke: async () => { calls += 1; return { code: 0, stdout: '{"models":[{"id":"x"}]}\n', stderr: '' }; }
  }), (error) => error.code === 'CAPABILITY_UNSUPPORTED');
  assert.equal(calls, 0);
});
