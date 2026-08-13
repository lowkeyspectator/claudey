import assert from 'node:assert/strict';
import test from 'node:test';

import { parseLauncherArgs, parseManagementArgs } from '../../../src/cli/parse.js';

const managementCases = [
  { argv: ['setup', '--version', 'v7.2.130', '--port', '8317', '--with-cursor', '--no-start', '--no-path', '--yes'], command: ['setup'], options: { version: '7.2.130', port: 8317, withCursor: true, noStart: true, noPath: true, yes: true } },
  { argv: ['install', '--version', '7.2.130', '--port', '1024', '--yes'], command: ['install'], options: { version: '7.2.130', port: 1024, yes: true } },
  { argv: ['auth', 'codex', '--device-code', '--callback-port', '65535'], command: ['auth', 'codex'], options: { deviceCode: true, callbackPort: 65535 } },
  { argv: ['auth', 'antigravity', '--no-browser', '--callback-port', '8317'], command: ['auth', 'antigravity'], options: { noBrowser: true, callbackPort: 8317 } },
  { argv: ['start', '--foreground'], command: ['start'], options: { foreground: true } },
  { argv: ['stop'], command: ['stop'], options: {} },
  { argv: ['restart'], command: ['restart'], options: {} },
  { argv: ['status', '--json'], command: ['status'], options: { json: true } },
  { argv: ['doctor'], command: ['doctor'], options: {} },
  { argv: ['update', '--check'], command: ['update'], options: { check: true } },
  { argv: ['rollback', '--version', 'v7.2.130', '--yes'], command: ['rollback'], options: { version: '7.2.130', yes: true } },
  { argv: ['models', 'codex'], command: ['models', 'codex'], options: {} },
  { argv: ['config', 'set', 'port', '8317', '--yes'], command: ['config', 'set', 'port'], options: { port: 8317, yes: true } },
  { argv: ['cursor', 'enable', '--scope', 'local'], command: ['cursor', 'enable'], options: { scope: 'local' } },
  { argv: ['cursor', 'disable', '--scope', 'user'], command: ['cursor', 'disable'], options: { scope: 'user' } },
  { argv: ['cursor', 'install', '--yes'], command: ['cursor', 'install'], options: { yes: true } },
  { argv: ['cursor', 'login'], command: ['cursor', 'login'], options: {} },
  { argv: ['cursor', 'repo', 'add', 'C:\\work\\repo'], command: ['cursor', 'repo', 'add'], options: { path: 'C:\\work\\repo' } },
  { argv: ['cursor', 'repo', 'list'], command: ['cursor', 'repo', 'list'], options: {} },
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

test('rejects conflicting, duplicate, unknown, and missing management options', () => {
  for (const argv of [
    ['auth', 'codex', '--device-code', '--no-browser'],
    ['update', '--check', '--version', '7.2.130'],
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
    model: 'gpt-test', select: false, claudeArgs: ['--verbose'], nonInteractive: false
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
    model: undefined, select: true, claudeArgs: ['--json'], nonInteractive: false
  });
});
