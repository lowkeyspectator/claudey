import assert from 'node:assert/strict';
import test from 'node:test';

import { ClaudeyError } from '../../../src/core/errors.js';
import { runOnboardCommand } from '../../../src/cli/commands/onboard.js';
import { beginnerLaunchError, beginnerNextSteps, ensureLocalInstall } from '../../../src/cli/first-run.js';

test('first run installs when nothing is installed yet', async () => {
  const calls = [];
  const installed = await ensureLocalInstall({}, {
    loadInstallation: async () => {
      if (!calls.includes('setup')) throw new ClaudeyError('NOT_INSTALLED', 'missing');
      return { version: '7.2.133', port: 8317 };
    },
    runSetup: async () => { calls.push('setup'); },
    announce: (text) => calls.push(text)
  });
  assert.equal(installed.port, 8317);
  assert.equal(calls[0], 'First run: installing the local gateway. This may take a minute.');
  assert.equal(calls[1], 'setup');
});

test('onboard prints beginner next steps after install', async () => {
  const notes = [];
  const result = await runOnboardCommand({}, {
    loadInstallation: async () => ({ version: '7.2.133', port: 8317 }),
    announce: (text) => notes.push(text)
  });
  assert.equal(result.operation, 'onboard');
  assert.deepEqual(result.next, ['claudey auth grok', 'claudey auth antigravity', 'claudey auth codex', 'claudey', 'claudey --yolo']);
  assert.match(notes.join('\n'), /claudey --yolo/);
  assert.match(beginnerNextSteps(), /claudey/);
});

test('beginner launch errors keep public codes and simple next steps', () => {
  const auth = beginnerLaunchError(new ClaudeyError('AUTH_REQUIRED', 'Provider "antigravity" is not authenticated.'));
  assert.equal(auth.code, 'AUTH_REQUIRED');
  assert.match(auth.hint, /claudey auth grok/);
  const missing = beginnerLaunchError(new ClaudeyError('PREREQUISITE_MISSING', 'A verified Claude Code executable is required.'));
  assert.equal(missing.code, 'PREREQUISITE_MISSING');
  assert.match(missing.hint, /claude.com\/download/);
});
