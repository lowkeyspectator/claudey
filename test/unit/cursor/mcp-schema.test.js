import assert from 'node:assert/strict';
import test from 'node:test';

import { probeCursorCapabilities } from '../../../src/cursor/capabilities.js';
import { resolveCursorAgentExecutable } from '../../../src/cursor/executable.js';
import {
  MCP_PROTOCOL_VERSION, buildCursorToolDescriptors, validateCursorToolArguments
} from '../../../src/cursor/mcp-schema.js';

const TARGET = Object.freeze({ name: 'verified-cursor' });
const BINDING = await resolveCursorAgentExecutable({
  candidates: [{ command: 'cursor-agent', source: 'path', target: TARGET }],
  verifyTarget: async ({ target }) => target,
  verifyVersion: async () => true
});

function runner(overrides = {}) {
  return async (request) => {
    const values = {
      '--version': 'Cursor Agent 1.0.0\n',
      'status --json': '{"authenticated":true}\n',
      'models --json': '{"models":[{"id":"cursor-a"}]}\n',
      'probe json --json': '{"type":"probe","capability":"json","framing":"json-lines"}\n',
      'probe stdin --json': `${JSON.stringify({ type: 'probe', capability: 'stdin', echo: request.stdin })}\n`,
      'probe mode ask --json': '{"type":"probe","capability":"ask","supported":true}\n',
      'probe mode plan --json': '{"type":"probe","capability":"plan","supported":true}\n',
      'probe mode worktree --json': '{"type":"probe","capability":"worktree","supported":true}\n',
      'probe sandbox read-only --json': '{"type":"probe","capability":"sandbox","supported":true}\n'
    };
    const value = Object.hasOwn(overrides, request.args.join(' ')) ? overrides[request.args.join(' ')]
      : values[request.args.join(' ')];
    return { code: value === undefined ? 2 : 0, stdout: value ?? '', stderr: '' };
  };
}

async function capabilities(overrides = {}) {
  return probeCursorCapabilities(BINDING, { invoke: runner(overrides), nonceFactory: () => 'schema-nonce' });
}

test('advertises exact typed descriptors from verified live capabilities and persistent write readiness', async () => {
  const descriptors = buildCursorToolDescriptors({
    capabilities: await capabilities(), writesEnabled: true, worktreeSafetyReady: true
  });
  assert.equal(MCP_PROTOCOL_VERSION, '2025-11-25');
  assert.deepEqual(descriptors.map(({ name }) => name),
    ['cursor_models', 'cursor_ask', 'cursor_plan', 'cursor_worktree_run']);
  assert.deepEqual(descriptors.at(-1), {
    name: 'cursor_worktree_run',
    title: 'Cursor approved worktree run',
    description: 'Run Cursor in a new retained Git worktree after a separate single-use human approval.',
    inputSchema: {
      type: 'object', additionalProperties: false,
      properties: {
        repo: { type: 'string', minLength: 1, maxLength: 4096 },
        prompt: { type: 'string', minLength: 1, maxLength: 32768 },
        model: { type: 'string', minLength: 1, maxLength: 256 },
        baseRef: { type: 'string', minLength: 40, maxLength: 1035 },
        approvalId: { type: 'string', pattern: '^[A-Za-z0-9_-]{43}$' }
      },
      required: ['repo', 'prompt']
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    _meta: {
      'claudex/requiresUserInteraction': true,
      'claudex/requiresOutOfBandApproval': true,
      'anthropic/maxResultSizeChars': 1048576
    }
  });
  assert.equal(Object.isFrozen(descriptors), true);
  assert.equal(Object.isFrozen(descriptors.at(-1).inputSchema.properties), true);
});

test('omits only tools whose independently verified capabilities or persistent safety gates are unavailable', async () => {
  const cases = [
    ['probe mode ask --json', '{"type":"probe","capability":"ask","supported":false}\n',
      ['cursor_models', 'cursor_plan', 'cursor_worktree_run']],
    ['probe mode plan --json', '{"type":"probe","capability":"plan","supported":false}\n',
      ['cursor_models', 'cursor_ask', 'cursor_worktree_run']],
    ['probe mode worktree --json', '{"type":"probe","capability":"worktree","supported":false}\n',
      ['cursor_models', 'cursor_ask', 'cursor_plan']],
    ['probe sandbox read-only --json', '{"type":"probe","capability":"sandbox","supported":false}\n',
      ['cursor_models', 'cursor_worktree_run']],
    ['models --json', '{"models":[]}\n', []]
  ];
  for (const [key, value, expected] of cases) {
    const descriptors = buildCursorToolDescriptors({
      capabilities: await capabilities({ [key]: value }), writesEnabled: true, worktreeSafetyReady: true
    });
    assert.deepEqual(descriptors.map(({ name }) => name), expected, key);
  }
  const verified = await capabilities();
  assert.deepEqual(buildCursorToolDescriptors({ capabilities: verified, writesEnabled: false, worktreeSafetyReady: true })
    .map(({ name }) => name), ['cursor_models', 'cursor_ask', 'cursor_plan']);
  assert.deepEqual(buildCursorToolDescriptors({ capabilities: verified, writesEnabled: true, worktreeSafetyReady: false })
    .map(({ name }) => name), ['cursor_models', 'cursor_ask', 'cursor_plan']);
  assert.throws(() => buildCursorToolDescriptors({ capabilities: structuredClone(verified), writesEnabled: true,
    worktreeSafetyReady: true }), (error) => error.code === 'SAFETY_REFUSAL');
});

test('strictly validates each tool input and rejects unknown fields, prompt fallback surfaces, and unsafe paths or refs', () => {
  assert.deepEqual(validateCursorToolArguments('cursor_models', {}), {});
  assert.deepEqual(validateCursorToolArguments('cursor_ask', {
    prompt: 'private\nprompt', model: 'cursor-a', paths: ['src/a.js', 'space name.txt']
  }), { prompt: 'private\nprompt', model: 'cursor-a', paths: ['src/a.js', 'space name.txt'] });
  assert.deepEqual(validateCursorToolArguments('cursor_plan', { prompt: 'plan it' }), { prompt: 'plan it' });
  assert.deepEqual(validateCursorToolArguments('cursor_worktree_run', {
    repo: '/home/casey/project', prompt: 'change it', model: 'cursor-a', baseRef: 'refs/heads/main',
    approvalId: 'a'.repeat(43)
  }), { repo: '/home/casey/project', prompt: 'change it', model: 'cursor-a', baseRef: 'refs/heads/main',
    approvalId: 'a'.repeat(43) });

  const rejected = [
    ['cursor_models', { extra: true }],
    ['cursor_ask', { prompt: 'x', argv: ['secret'] }],
    ['cursor_ask', { prompt: 'x', paths: ['../secret'] }],
    ['cursor_plan', { prompt: '', model: '--help' }],
    ['cursor_worktree_run', { repo: '/tmp/x', prompt: 'x', baseRef: 'HEAD~1' }],
    ['cursor_worktree_run', { repo: '/tmp/x', prompt: 'x', approvalId: 'short' }],
    ['unknown', {}]
  ];
  for (const [name, value] of rejected) {
    assert.throws(() => validateCursorToolArguments(name, value), (error) => error.code === 'SAFETY_REFUSAL');
  }
});
