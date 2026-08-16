import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { runClaudeAgy } from '../../../src/cli/launchers/claude-agy.js';
import { runClaudeGrok } from '../../../src/cli/launchers/claude-grok.js';
import { runClaudey } from '../../../src/cli/launchers/claudey.js';
import { runClaudeCodex, runClaudex, stageLaunchers } from '../../../src/cli/launchers/claude-codex.js';

test('launcher profiles bind only their fixed provider and parser result', async () => {
  const calls = [];
  const launch = async (request) => { calls.push(request); return { provider: request.provider, model: request.parsed.model }; };
  assert.deepEqual(await runClaudeCodex(['--model', 'gpt-live', '--', '--print', 'x'], {}, { launch }), { provider: 'codex', model: 'gpt-live' });
  assert.deepEqual(await runClaudex(['--model', 'gpt-live', '--', '--print', 'x'], {}, { launch }), { provider: 'codex', model: 'gpt-live' });
  assert.deepEqual(await runClaudeAgy(['--model', 'agy-live'], {}, { launch }), { provider: 'antigravity', model: 'agy-live' });
  assert.deepEqual(await runClaudeGrok(['--model', 'grok-live'], {}, { launch }), { provider: 'grok', model: 'grok-live' });
  assert.deepEqual(await runClaudey(['--yolo'], {}, { launch }), { provider: 'codex', model: undefined });
  assert.deepEqual(calls.map(({ provider, parsed }) => ({ provider, parsed })), [
    { provider: 'codex', parsed: { model: 'gpt-live', select: false, all: false, claudeArgs: ['--print', 'x'], nonInteractive: false } },
    { provider: 'codex', parsed: { model: 'gpt-live', select: false, all: false, claudeArgs: ['--print', 'x'], nonInteractive: false } },
    { provider: 'antigravity', parsed: { model: 'agy-live', select: false, all: false, claudeArgs: [], nonInteractive: false } },
    { provider: 'grok', parsed: { model: 'grok-live', select: false, all: false, claudeArgs: [], nonInteractive: false } },
    { provider: 'codex', parsed: { model: undefined, select: false, all: true, claudeArgs: ['--dangerously-skip-permissions'], nonInteractive: false } }
  ]);
});

test('launcher parser errors and CI noninteractive state reach no provider orchestration', async () => {
  let called = false;
  const launch = async () => { called = true; };
  await assert.rejects(runClaudeCodex(['--model', 'x', '--select'], {}, { launch }), (error) => error.code === 'USAGE_ERROR');
  assert.equal(called, false);
  await runClaudeCodex(['--model', 'x'], { CI: 'true' }, { launch: async ({ parsed }) => { assert.equal(parsed.nonInteractive, true); } });
});

test('stages three exact POSIX launchers with fixed absolute paths, profiles, modes, and argument forwarding', async () => {
  const staged = [];
  const result = await stageLaunchers({
    platform: 'linux',
    nodePath: "/opt/Claudey Runtime/node's bin/node",
    managerPath: '/opt/Claudey Runtime/current/bin/claudeyctl.js',
    stageFile: async (file) => staged.push(file)
  });
  assert.deepEqual(result.map(({ child, mode }) => ({ child, mode })), [
    { child: 'claudeyctl', mode: 0o755 }, { child: 'claudey', mode: 0o755 },
    { child: 'claude-codex', mode: 0o755 }, { child: 'claude-agy', mode: 0o755 },
    { child: 'claude-grok', mode: 0o755 }
  ]);
  assert.deepEqual(staged, result);
  for (const item of result) {
    const text = item.bytes.toString('utf8');
    assert.equal(text.startsWith('#!/bin/sh\nexec '), true);
    assert.equal(text.endsWith(' "$@"\n'), true);
    assert.equal(text.includes('8317'), false);
    assert.equal(text.includes('ANTHROPIC_AUTH_TOKEN'), false);
    assert.equal(text.includes('__CLAUDEX_'), false);
    assert.equal(path.posix.basename(item.child), item.child);
  }
  assert.match(result[0].bytes.toString(), /claudeyctl\.js' "\$@"\n$/);
  assert.match(result[1].bytes.toString(), /claudeyctl\.js' 'launcher' 'claudey' "\$@"\n$/);
  assert.match(result[2].bytes.toString(), /claudeyctl\.js' 'launcher' 'claude-codex' "\$@"\n$/);
  assert.match(result[3].bytes.toString(), /claudeyctl\.js' 'launcher' 'claude-agy' "\$@"\n$/);
  assert.match(result[4].bytes.toString(), /claudeyctl\.js' 'launcher' 'claude-grok' "\$@"\n$/);
});

test('launcher staging rejects Windows, unsafe paths, unknown profiles, and partial writes', async () => {
  for (const options of [
    { platform: 'win32', nodePath: 'C:\\node.exe', managerPath: 'C:\\manager.js' },
    { platform: 'linux', nodePath: 'node', managerPath: '/manager.js' },
    { platform: 'linux', nodePath: '/node\n', managerPath: '/manager.js' },
    { platform: 'linux', nodePath: '/node', managerPath: '/sub/../manager.js' },
    { platform: 'linux', nodePath: '/node', managerPath: '/manager.js', stageFile: undefined }
  ]) {
    await assert.rejects(stageLaunchers({ stageFile: async () => {}, ...options }), (error) => ['PLATFORM_UNSUPPORTED', 'SAFETY_REFUSAL'].includes(error.code));
  }
  let writes = 0;
  await assert.rejects(stageLaunchers({
    platform: 'darwin', nodePath: '/node', managerPath: '/manager.js',
    stageFile: async () => { writes += 1; if (writes === 2) throw new Error('private path secret-canary'); }
  }), (error) => error.code === 'SAFETY_REFUSAL' && !error.message.includes('secret-canary'));

  await assert.rejects(stageLaunchers({
    platform: 'linux', nodePath: '/node', managerPath: '/manager.js',
    stageFile: async (file) => file.bytes.fill(0x78)
  }), (error) => error.code === 'SAFETY_REFUSAL');
});

test('checked-in POSIX templates contain only fixed placeholders, profiles, and exact argument forwarding', async () => {
  const bin = fileURLToPath(new URL('../../../bin/', import.meta.url));
  const expected = {
    claudeyctl: '#!/bin/sh\nexec \'__CLAUDEX_NODE__\' \'__CLAUDEX_MANAGER__\' "$@"\n',
    claudey: '#!/bin/sh\nexec \'__CLAUDEX_NODE__\' \'__CLAUDEX_MANAGER__\' \'launcher\' \'claudey\' "$@"\n',
    'claude-codex': '#!/bin/sh\nexec \'__CLAUDEX_NODE__\' \'__CLAUDEX_MANAGER__\' \'launcher\' \'claude-codex\' "$@"\n',
    'claude-agy': '#!/bin/sh\nexec \'__CLAUDEX_NODE__\' \'__CLAUDEX_MANAGER__\' \'launcher\' \'claude-agy\' "$@"\n',
    'claude-grok': '#!/bin/sh\nexec \'__CLAUDEX_NODE__\' \'__CLAUDEX_MANAGER__\' \'launcher\' \'claude-grok\' "$@"\n'
  };
  for (const [name, contents] of Object.entries(expected)) {
    const actual = await fs.readFile(path.join(bin, name), 'utf8');
    assert.equal(actual.replaceAll('\r\n', '\n'), contents);
    assert.equal(actual.includes('8317'), false);
    assert.equal(actual.includes('TOKEN'), false);
  }
});
