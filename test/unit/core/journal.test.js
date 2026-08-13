import assert from 'node:assert/strict';
import test from 'node:test';

import {
  JOURNAL_PHASES,
  advanceJournal,
  createJournal,
  loadJournal,
  parseJournal,
  writeJournal
} from '../../../src/core/journal.js';

const ROOTS = ['C:\\managed'];
const HASH = 'a'.repeat(64);

function fields(overrides = {}) {
  return {
    operationId: '22222222-2222-4222-8222-222222222222',
    kind: 'update',
    phase: 'prepared',
    ownedPaths: {
      staging: ['C:\\managed\\staging\\candidate'],
      configTemp: 'C:\\managed\\state\\config.tmp',
      candidateProcess: 'C:\\managed\\releases\\candidate.exe',
      priorPointerBackup: 'C:\\managed\\state\\active.backup',
      priorConfigBackup: 'C:\\managed\\state\\config.backup'
    },
    hashes: { candidate: HASH, priorPointer: HASH, priorConfig: HASH },
    priorActivePointer: 'releases/7.2.129',
    priorRunning: true,
    ...overrides
  };
}

const options = { platform: 'win32', ownedRoots: ROOTS, now: () => '2026-08-12T12:00:00.000Z' };

test('accepts only the exact forward journal phase sequence', () => {
  assert.deepEqual(JOURNAL_PHASES, [
    'prepared', 'release-staged', 'config-staged', 'activated', 'candidate-started', 'ready', 'committed'
  ]);
  let journal = createJournal(fields(), options);
  for (const phase of JOURNAL_PHASES.slice(1)) {
    journal = advanceJournal(journal, phase, { ...options, now: () => '2026-08-12T12:00:01.000Z' });
    assert.equal(journal.phase, phase);
  }
  assert.throws(() => advanceJournal(createJournal(fields(), options), 'config-staged', options),
    (error) => error?.code === 'SAFETY_REFUSAL');
  assert.throws(() => advanceJournal(journal, 'ready', options),
    (error) => error?.code === 'SAFETY_REFUSAL');
  assert.throws(() => advanceJournal(journal, 'foreign', options),
    (error) => error?.code === 'SAFETY_REFUSAL');
});

test('closed journal schema rejects foreign paths, unknown fields, IDs, hashes, and timestamps', () => {
  const valid = createJournal(fields(), options);
  const cases = [
    { ...valid, extra: true },
    { ...valid, operationId: 'bad-id' },
    { ...valid, phase: 'unknown' },
    { ...valid, ownedPaths: { ...valid.ownedPaths, configTemp: 'D:\\foreign\\config.tmp' } },
    { ...valid, hashes: { ...valid.hashes, candidate: 'A'.repeat(64) } },
    { ...valid, updatedAt: 'yesterday' }
  ];
  for (const record of cases) {
    const result = parseJournal(Buffer.from(JSON.stringify(record)), options);
    assert.equal(result.status, 'quarantined');
    assert.deepEqual(Object.keys(result.evidence).sort(), ['reason', 'sha256']);
  }
});

test('corrupt records are quarantined by hand-derived hash and reason only', () => {
  const result = parseJournal(Buffer.from('not-json'), options);
  assert.deepEqual(result, {
    status: 'quarantined',
    evidence: {
      sha256: '0c21a879c732a67910d80988df4919d794f6a070aab610ef865032a28046b021',
      reason: 'corrupt-json'
    }
  });
});

test('loads invalid journals into quarantine without exposing record contents', async () => {
  const canary = 'TASK4_JOURNAL_SECRET_CANARY';
  const quarantines = [];
  const result = await loadJournal({ stateRoot: 'C:\\managed\\state' }, {
    ...options,
    inspectOwned: async () => 'C:\\managed\\state\\transaction.json',
    readFile: async () => Buffer.from(`{"secret":"${canary}"}`),
    quarantineEvidence: async (evidence) => { quarantines.push(evidence); }
  });
  assert.equal(result.status, 'quarantined');
  assert.equal(JSON.stringify(result).includes(canary), false);
  assert.equal(JSON.stringify(quarantines).includes(canary), false);
});

test('checkpoints valid journals with protected atomic replacement and no secret canaries', async () => {
  const journal = createJournal(fields(), options);
  const calls = [];
  await writeJournal(journal, { stateRoot: 'C:\\managed\\state' }, {
    ...options,
    assertLockHeld: async () => undefined,
    atomicReplace: async (request) => { calls.push(request); }
  });
  assert.equal(calls.length, 1);
  assert.deepEqual({ root: calls[0].root, child: calls[0].child, mode: calls[0].mode }, {
    root: 'C:\\managed\\state', child: 'transaction.json', mode: 0o600
  });
  const text = calls[0].bytes.toString('utf8');
  assert.equal(text.endsWith('\n'), true);
  assert.equal(text.includes('TASK4_BEARER_CANARY'), false);
  assert.equal(text.includes('TASK4_MANIFEST_KEY_CANARY'), false);
  assert.equal(text.includes('oauth'), false);
});
