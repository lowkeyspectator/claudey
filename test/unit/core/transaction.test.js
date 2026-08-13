import assert from 'node:assert/strict';
import test from 'node:test';

import { createJournal } from '../../../src/core/journal.js';
import { createTransaction, recoverTransaction } from '../../../src/core/transaction.js';

const HASH = 'a'.repeat(64);
const options = { platform: 'win32', ownedRoots: ['C:\\managed'], now: () => '2026-08-12T12:00:00.000Z' };

function journalAt(phase, priorRunning = true) {
  return createJournal({
    operationId: '33333333-3333-4333-8333-333333333333',
    kind: 'update',
    phase,
    ownedPaths: {
      staging: ['C:\\managed\\staging\\candidate'],
      configTemp: 'C:\\managed\\state\\config.tmp',
      candidateProcess: 'C:\\managed\\releases\\candidate.exe',
      priorPointerBackup: 'C:\\managed\\state\\active.backup',
      priorConfigBackup: 'C:\\managed\\state\\config.backup'
    },
    hashes: { candidate: HASH, priorPointer: HASH, priorConfig: HASH },
    priorActivePointer: 'releases/7.2.129',
    priorRunning
  }, options);
}

function recorder(overrides = {}) {
  const events = [];
  const action = (name, result) => async () => { events.push(name); return result; };
  return {
    events,
    actions: {
      assertLockHeld: action('lock'),
      removeVerifiedConfigTemp: action('remove-config-temp'),
      removeVerifiedStaging: action('remove-staging'),
      candidatePresent: action('candidate-present', true),
      stopVerifiedCandidate: action('stop-candidate'),
      verifyBackups: action('verify-backups', true),
      restorePointer: action('restore-pointer'),
      restoreConfig: action('restore-config'),
      restartPrior: action('restart-prior'),
      authenticatePriorReadiness: action('authenticate-prior'),
      matchesReadyState: action('matches-ready', true),
      writeCheckpoint: action('write-committed'),
      commitRetentionCleanup: action('retention-cleanup'),
      cleanupCommittedOwnedStaging: action('cleanup-staging'),
      clearJournal: action('clear-journal'),
      quarantineEvidence: action('quarantine'),
      ...overrides
    }
  };
}

function withoutLocks(events) {
  return events.filter((event) => event !== 'lock');
}

test('transaction checkpoints atomically and does not advance after an injected write failure', async () => {
  const writes = [];
  let fail = true;
  const transaction = createTransaction(journalAt('prepared'), {
    ...options,
    assertLockHeld: async () => undefined,
    writeCheckpoint: async (journal) => {
      writes.push(journal.phase);
      if (fail) throw Object.assign(new Error('injected rename failure'), { code: 'EIO' });
    },
    cleanupCommittedOwnedStaging: async () => assert.fail('must not clean uncommitted staging')
  });
  await assert.rejects(() => transaction.checkpoint('release-staged'), (error) => error?.code === 'EIO');
  assert.equal(transaction.current.phase, 'prepared');
  fail = false;
  await transaction.checkpoint('release-staged');
  assert.equal(transaction.current.phase, 'release-staged');
  assert.deepEqual(writes, ['release-staged', 'release-staged']);
  await assert.rejects(() => transaction.cleanup(), (error) => error?.code === 'SAFETY_REFUSAL');
});

test('committed transaction cleanup removes only journal-owned staging', async () => {
  const removed = [];
  const transaction = createTransaction(journalAt('committed'), {
    ...options,
    assertLockHeld: async () => undefined,
    writeCheckpoint: async () => undefined,
    cleanupCommittedOwnedStaging: async (paths) => { removed.push(...paths); }
  });
  await transaction.cleanup();
  assert.deepEqual(removed, ['C:\\managed\\staging\\candidate']);
});

test('prepared and staged interruption cleanup runs in reverse order without touching old state', async () => {
  const prepared = recorder();
  await recoverTransaction(journalAt('prepared'), prepared.actions, options);
  assert.deepEqual(withoutLocks(prepared.events), ['remove-staging', 'clear-journal']);

  const releaseStaged = recorder();
  await recoverTransaction(journalAt('release-staged'), releaseStaged.actions, options);
  assert.deepEqual(withoutLocks(releaseStaged.events), [
    'remove-config-temp', 'remove-staging', 'clear-journal'
  ]);

  const staged = recorder();
  await recoverTransaction(journalAt('config-staged'), staged.actions, options);
  assert.deepEqual(withoutLocks(staged.events), ['remove-config-temp', 'remove-staging', 'clear-journal']);
});

test('activated interruption restores pointer then config and preserves prior stopped state', async () => {
  const state = recorder({ candidatePresent: async () => { state.events.push('candidate-present'); return false; } });
  await recoverTransaction(journalAt('activated', false), state.actions, options);
  assert.deepEqual(withoutLocks(state.events), [
    'candidate-present', 'verify-backups', 'restore-pointer', 'restore-config', 'remove-config-temp',
    'remove-staging', 'clear-journal'
  ]);
});

test('failed candidate stops then restores in reverse order and restarts only a prior running gateway', async () => {
  const running = recorder();
  await recoverTransaction(journalAt('candidate-started', true), running.actions, options);
  assert.deepEqual(withoutLocks(running.events), [
    'candidate-present', 'stop-candidate', 'verify-backups', 'restore-pointer', 'restore-config',
    'restart-prior', 'authenticate-prior', 'remove-config-temp', 'remove-staging', 'clear-journal'
  ]);

  const stopped = recorder();
  await recoverTransaction(journalAt('candidate-started', false), stopped.actions, options);
  assert.equal(stopped.events.includes('restart-prior'), false);
  assert.equal(stopped.events.includes('authenticate-prior'), false);
});

test('ready recovery commits consistent state but rolls back inconsistent state', async () => {
  const consistent = recorder();
  await recoverTransaction(journalAt('ready'), consistent.actions, options);
  assert.deepEqual(withoutLocks(consistent.events), [
    'matches-ready', 'write-committed', 'retention-cleanup', 'cleanup-staging', 'clear-journal'
  ]);

  const inconsistent = recorder({ matchesReadyState: async () => { inconsistent.events.push('matches-ready'); return false; } });
  await recoverTransaction(journalAt('ready'), inconsistent.actions, options);
  assert.deepEqual(withoutLocks(inconsistent.events).slice(0, 4), [
    'matches-ready', 'candidate-present', 'stop-candidate', 'verify-backups'
  ]);
  assert.equal(inconsistent.events.includes('restore-pointer'), true);
});

test('corrupt or unavailable backups are quarantined and never restored', async () => {
  const state = recorder({ verifyBackups: async () => { state.events.push('verify-backups'); return false; } });
  const result = await recoverTransaction(journalAt('candidate-started'), state.actions, options);
  assert.deepEqual(result, { status: 'rollback-unavailable' });
  assert.deepEqual(withoutLocks(state.events), [
    'candidate-present', 'stop-candidate', 'verify-backups', 'quarantine'
  ]);
  assert.equal(state.events.includes('restore-pointer'), false);
  assert.equal(state.events.includes('restore-config'), false);
});

test('committed recovery cleans committed owned staging and clears the journal', async () => {
  const state = recorder();
  await recoverTransaction(journalAt('committed'), state.actions, options);
  assert.deepEqual(withoutLocks(state.events), ['cleanup-staging', 'clear-journal']);
});
