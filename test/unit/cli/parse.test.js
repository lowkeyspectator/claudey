import assert from 'node:assert/strict';
import test from 'node:test';

import { parseLauncherArgs, parseManagementArgs } from '../../../src/cli/parse.js';

const managementCases = [
  { argv: ['onboard', '--yes'], command: ['onboard'], options: { yes: true } },
  { argv: ['setup', '--version', 'v7.2.130', '--port', '8317', '--with-cursor', '--no-start', '--no-path', '--yes'], command: ['setup'], options: { version: '7.2.130', port: 8317, withCursor: true, noStart: true, noPath: true, yes: true } },
  { argv: ['install', '--version', '7.2.130', '--port', '1024', '--yes'], command: ['install'], options: { version: '7.2.130', port: 1024, yes: true } },
  { argv: ['auth', 'codex', '--device-code', '--callback-port', '65535'], command: ['auth', 'codex'], options: { deviceCode: true, callbackPort: 65535 } },
  { argv: ['auth', 'codex', '--no-browser'], command: ['auth', 'codex'], options: { noBrowser: true } },
  { argv: ['auth', 'antigravity', '--no-browser', '--callback-port', '8317'], command: ['auth', 'antigravity'], options: { noBrowser: true, callbackPort: 8317 } },
  { argv: ['auth', 'grok', '--device-code', '--callback-port', '1456'], command: ['auth', 'grok'], options: { deviceCode: true, callbackPort: 1456 } },
  { argv: ['auth', 'all'], command: ['auth', 'all'], options: {} },
  { argv: ['start', '--foreground'], command: ['start'], options: { foreground: true } },
  { argv: ['stop'], command: ['stop'], options: {} },
  { argv: ['restart'], command: ['restart'], options: {} },
  { argv: ['status', '--json'], command: ['status'], options: { json: true } },
  { argv: ['doctor', '--json'], command: ['doctor'], options: { json: true } },
  { argv: ['update', '--check'], command: ['update'], options: { check: true } },
  { argv: ['update', '--version', 'v7.2.130', '--yes'], command: ['update'], options: { version: '7.2.130', yes: true } },
  { argv: ['rollback', '--version', 'v7.2.130', '--yes'], command: ['rollback'], options: { version: '7.2.130', yes: true } },
  { argv: ['models', 'codex'], command: ['models', 'codex'], options: {} },
  { argv: ['models', 'antigravity'], command: ['models', 'antigravity'], options: {} },
  { argv: ['models', 'grok'], command: ['models', 'grok'], options: {} },
  { argv: ['models', 'cursor'], command: ['models', 'cursor'], options: {} },
  { argv: ['models', 'all'], command: ['models', 'all'], options: {} },
  { argv: ['models'], command: ['models'], options: {} },
  { argv: ['config', 'set', 'port', '8317', '--yes'], command: ['config', 'set', 'port'], options: { port: 8317, yes: true } },
  { argv: ['cursor', 'enable', '--scope', 'local'], command: ['cursor', 'enable'], options: { scope: 'local' } },
  { argv: ['cursor', 'disable', '--scope', 'user'], command: ['cursor', 'disable'], options: { scope: 'user' } },
  { argv: ['cursor', 'install', '--yes'], command: ['cursor', 'install'], options: { yes: true } },
  { argv: ['cursor', 'login'], command: ['cursor', 'login'], options: {} },
  { argv: ['cursor', 'repo', 'add', 'C:\\work\\repo'], command: ['cursor', 'repo', 'add'], options: { path: 'C:\\work\\repo' } },
  { argv: ['cursor', 'repo', 'add'], command: ['cursor', 'repo', 'add'], options: {} },
  { argv: ['cursor', 'repo', 'list'], command: ['cursor', 'repo', 'list'], options: {} },
  { argv: ['cursor', 'repo', 'remove', 'C:\\work\\repo'], command: ['cursor', 'repo', 'remove'], options: { path: 'C:\\work\\repo' } },
  { argv: ['cursor', 'repo', 'remove'], command: ['cursor', 'repo', 'remove'], options: {} },
  { argv: ['cursor', 'writes', 'enable', '--yes'], command: ['cursor', 'writes', 'enable'], options: { yes: true } },
  { argv: ['cursor', 'writes', 'disable'], command: ['cursor', 'writes', 'disable'], options: {} },
  { argv: ['cursor', 'approve', 'approval-id'], command: ['cursor', 'approve'], options: { approvalId: 'approval-id' } },
  { argv: ['uninstall', '--dry-run', '--purge-auth', '--yes'], command: ['uninstall'], options: { dryRun: true, purgeAuth: true, yes: true } }
];

test('parses every documented management command into typed command options', () => {
  for (const { argv, command, options } of managementCases) {
    assert.deepEqual(parseManagementArgs(argv), { command, options }, argv.join(' '));
  }
});

test('accepts global flags before or after a management command', () => {
  assert.deepEqual(parseManagementArgs(['--verbose', 'status', '--json', '--no-color']), {
    command: ['status'], options: { verbose: true, json: true, noColor: true }
  });
});

test('normalizes CI into noninteractive mode', () => {
  assert.deepEqual(parseManagementArgs(['models', 'all'], { CI: 'true' }), {
    command: ['models', 'all'], options: { nonInteractive: true }
  });
});

test('accepts global noninteractive before and after a management command', () => {
  assert.deepEqual(parseManagementArgs(['--non-interactive', 'doctor']), {
    command: ['doctor'], options: { nonInteractive: true }
  });
  assert.deepEqual(parseManagementArgs(['doctor', '--non-interactive']), {
    command: ['doctor'], options: { nonInteractive: true }
  });
});

test('CI-derived noninteractive is idempotent with one explicit noninteractive flag', () => {
  assert.deepEqual(parseManagementArgs(['doctor', '--non-interactive'], { CI: 'true' }), {
    command: ['doctor'], options: { nonInteractive: true }
  });
  assert.throws(
    () => parseManagementArgs(['doctor', '--non-interactive', '--non-interactive'], { CI: 'true' }),
    (error) => error.code === 'USAGE_ERROR'
  );
});

test('rejects conflicting, duplicate, unknown, and missing management options', () => {
  for (const argv of [
    ['auth', 'codex', '--device-code', '--no-browser'],
    ['update', '--check', '--version', '7.2.130'],
    ['update', '--check', '--yes'],
    ['setup', '--yes', '--yes'],
    ['start', '--unknown'],
    ['setup', '--port'],
    ['config', 'set', 'port', '1023'],
    ['cursor', 'writes', 'enable'],
    ['cursor', 'approve']
  ]) {
    assert.throws(() => parseManagementArgs(argv), (error) => error.code === 'USAGE_ERROR', argv.join(' '));
  }
});

test('rejects a missing operand for every valued command option', () => {
  for (const argv of [
    ['setup', '--version'],
    ['setup', '--port'],
    ['install', '--version'],
    ['install', '--port'],
    ['auth', 'codex', '--callback-port'],
    ['auth', 'antigravity', '--callback-port'],
    ['update', '--version'],
    ['rollback', '--version'],
    ['config', 'set', 'port'],
    ['cursor', 'enable', '--scope'],
    ['cursor', 'approve']
  ]) {
    assert.throws(() => parseManagementArgs(argv), (error) => error.code === 'USAGE_ERROR', argv.join(' '));
  }
  assert.throws(() => parseLauncherArgs(['--model']), (error) => error.code === 'USAGE_ERROR');
});

test('rejects underflow, overflow, and non-digit values for every port operand', () => {
  const commands = [
    ['setup', '--port'],
    ['install', '--port'],
    ['auth', 'codex', '--callback-port'],
    ['auth', 'antigravity', '--callback-port'],
    ['config', 'set', 'port']
  ];
  for (const command of commands) {
    for (const value of ['1023', '65536', 'not-a-port']) {
      const argv = [...command, value];
      assert.throws(() => parseManagementArgs(argv), (error) => error.code === 'USAGE_ERROR', argv.join(' '));
    }
  }
});

test('cursor repo permits at most one non-option path operand', () => {
  for (const argv of [
    ['cursor', 'repo', 'add', '--unsafe'],
    ['cursor', 'repo', 'remove', '--unsafe'],
    ['cursor', 'repo', 'add', 'C:\\work\\repo', 'extra'],
    ['cursor', 'repo', 'remove', 'C:\\work\\repo', 'extra']
  ]) {
    assert.throws(() => parseManagementArgs(argv), (error) => error.code === 'USAGE_ERROR', argv.join(' '));
  }
});

test('rejects --yes where it cannot approve interaction', () => {
  assert.throws(
    () => parseManagementArgs(['auth', 'codex', '--yes']),
    (error) => error.code === 'USAGE_ERROR'
  );
  assert.throws(
    () => parseManagementArgs(['cursor', 'approve', 'id', '--yes']),
    (error) => error.code === 'USAGE_ERROR'
  );
});

test('launcher requires a delimiter before Claude arguments', () => {
  assert.throws(
    () => parseLauncherArgs(['--model', 'gpt-test', '--verbose']),
    (error) => error.code === 'USAGE_ERROR'
  );
  assert.deepEqual(parseLauncherArgs(['--model', 'gpt-test', '--', '--verbose']), {
    model: 'gpt-test', select: false, all: false, claudeArgs: ['--verbose'], nonInteractive: false
  });
});

test('launcher rejects conflicting model controls and forwards post-delimiter Claude flags untouched', () => {
  for (const argv of [
    ['--model', 'gpt-test', '--select'],
    ['--unknown']
  ]) {
    assert.throws(() => parseLauncherArgs(argv), (error) => error.code === 'USAGE_ERROR', argv.join(' '));
  }
  assert.deepEqual(parseLauncherArgs(['--select', '--', '--json']), {
    model: undefined, select: true, all: false, claudeArgs: ['--json'], nonInteractive: false
  });
  assert.deepEqual(parseLauncherArgs(['--all', '--model', 'grok-4.5']), {
    model: 'grok-4.5', select: false, all: true, claudeArgs: [], nonInteractive: false
  });
  assert.deepEqual(parseLauncherArgs(['--yolo', '--', '--print', 'hi']), {
    model: undefined, select: false, all: false,
    claudeArgs: ['--dangerously-skip-permissions', '--print', 'hi'], nonInteractive: false
  });
});
