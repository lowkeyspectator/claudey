import crypto from 'node:crypto';

import { ClaudexError } from './errors.js';
import { advanceJournal, assertJournal } from './journal.js';

function safety(message) {
  return new ClaudexError('SAFETY_REFUSAL', message);
}

function requireFunction(value, name) {
  if (typeof value !== 'function') throw safety(`Transaction requires ${name}.`);
  return value;
}

export function createTransaction(initialJournal, deps = {}) {
  const options = {
    platform: deps.platform ?? process.platform,
    ownedRoots: deps.ownedRoots,
    now: deps.now
  };
  assertJournal(initialJournal, options);
  const assertLockHeld = requireFunction(deps.assertLockHeld, 'lock verification');
  const writeCheckpoint = requireFunction(deps.writeCheckpoint, 'atomic checkpoint storage');
  const cleanupCommittedOwnedStaging = requireFunction(
    deps.cleanupCommittedOwnedStaging,
    'verified committed-staging cleanup'
  );
  let current = initialJournal;
  return {
    get current() { return current; },
    async checkpoint(nextPhase) {
      const next = advanceJournal(current, nextPhase, options);
      await assertLockHeld();
      await writeCheckpoint(next);
      current = next;
      return current;
    },
    async cleanup() {
      if (current.phase !== 'committed') throw safety('Uncommitted transaction staging cannot be cleaned.');
      await assertLockHeld();
      await cleanupCommittedOwnedStaging([...current.ownedPaths.staging]);
    }
  };
}

function quarantineEvidence(journal, reason) {
  return {
    sha256: crypto.createHash('sha256').update(JSON.stringify(journal)).digest('hex'),
    reason
  };
}

export async function recoverTransaction(journal, actions, options = {}) {
  assertJournal(journal, options);
  const assertLockHeld = requireFunction(actions?.assertLockHeld, 'lock verification');
  const call = async (name, ...args) => {
    await assertLockHeld();
    return requireFunction(actions?.[name], name)(...args);
  };
  const clear = async () => call('clearJournal');
  const removeStaged = async ({ config = true } = {}) => {
    if (config && journal.ownedPaths.configTemp !== null) {
      await call('removeVerifiedConfigTemp', journal.ownedPaths.configTemp);
    }
    await call('removeVerifiedStaging', [...journal.ownedPaths.staging]);
  };
  const rollback = async () => {
    const candidatePresent = await call('candidatePresent', journal.ownedPaths.candidateProcess, journal.hashes.candidate);
    if (candidatePresent) await call('stopVerifiedCandidate', journal.ownedPaths.candidateProcess, journal.hashes.candidate);
    const backupsValid = await call('verifyBackups', {
      pointerPath: journal.ownedPaths.priorPointerBackup,
      pointerHash: journal.hashes.priorPointer,
      configPath: journal.ownedPaths.priorConfigBackup,
      configHash: journal.hashes.priorConfig,
      priorActivePointer: journal.priorActivePointer
    });
    if (!backupsValid || journal.priorActivePointer === null) {
      await call('quarantineEvidence', quarantineEvidence(journal, 'rollback-unavailable'));
      return { status: 'rollback-unavailable' };
    }
    await call('restorePointer', journal.ownedPaths.priorPointerBackup, journal.hashes.priorPointer);
    await call('restoreConfig', journal.ownedPaths.priorConfigBackup, journal.hashes.priorConfig);
    if (journal.priorRunning) {
      await call('restartPrior', journal.priorActivePointer);
      await call('authenticatePriorReadiness', journal.priorActivePointer);
    }
    await removeStaged();
    await clear();
    return { status: 'rolled-back' };
  };

  if (journal.phase === 'prepared') {
    await removeStaged({ config: false });
    await clear();
    return { status: 'cleaned' };
  }
  if (journal.phase === 'release-staged') {
    await removeStaged({ config: false });
    await clear();
    return { status: 'cleaned' };
  }
  if (journal.phase === 'config-staged') {
    await removeStaged();
    await clear();
    return { status: 'cleaned' };
  }
  if (['activated', 'candidate-started'].includes(journal.phase)) return rollback();
  if (journal.phase === 'ready') {
    const consistent = await call('matchesReadyState', journal);
    if (!consistent) return rollback();
    const committed = advanceJournal(journal, 'committed', options);
    await call('writeCheckpoint', committed);
    await call('commitRetentionCleanup', committed);
    await call('cleanupCommittedOwnedStaging', [...journal.ownedPaths.staging]);
    await clear();
    return { status: 'committed' };
  }
  if (journal.phase === 'committed') {
    await call('cleanupCommittedOwnedStaging', [...journal.ownedPaths.staging]);
    await clear();
    return { status: 'committed' };
  }
  throw safety('Journal phase cannot be recovered.');
}
