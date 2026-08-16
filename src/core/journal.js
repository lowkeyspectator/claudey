import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import { ClaudeyError } from './errors.js';
import { assertContainedNoLinks, assertRelativeManagedChild } from './fs-safe.js';
import { atomicReplace } from './permissions.js';

export const JOURNAL_CHILD = 'transaction.json';
export const JOURNAL_PHASES = Object.freeze([
  'prepared', 'release-staged', 'config-staged', 'activated', 'candidate-started', 'ready', 'committed'
]);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SHA256 = /^[0-9a-f]{64}$/u;
const KINDS = new Set(['install', 'update', 'rollback', 'config']);
const JOURNAL_KEYS = [
  'schemaVersion', 'operationId', 'kind', 'phase', 'ownedPaths', 'hashes',
  'priorActivePointer', 'priorRunning', 'createdAt', 'updatedAt'
];
const PATH_KEYS = ['staging', 'configTemp', 'candidateProcess', 'priorPointerBackup', 'priorConfigBackup'];
const HASH_KEYS = ['candidate', 'priorPointer', 'priorConfig'];

function safety(message) {
  return new ClaudeyError('SAFETY_REFUSAL', message);
}

function exactKeys(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function pathApiFor(platform) {
  return platform === 'win32' ? path.win32 : path.posix;
}

function containedBy(root, target, platform) {
  const pathApi = pathApiFor(platform);
  const normalizedRoot = pathApi.normalize(root);
  const normalizedTarget = pathApi.normalize(target);
  const relative = pathApi.relative(normalizedRoot, normalizedTarget);
  const contained = relative !== '' && relative !== '..' && !relative.startsWith(`..${pathApi.sep}`) && !pathApi.isAbsolute(relative);
  if (!contained) return false;
  return platform === 'win32'
    ? normalizedTarget.toLowerCase() === target.toLowerCase()
    : normalizedTarget === target;
}

function assertOwnedPath(value, { platform, ownedRoots }) {
  const pathApi = pathApiFor(platform);
  if (typeof value !== 'string' || /[\0\r\n]/u.test(value) || !pathApi.isAbsolute(value)
    || !ownedRoots.some((root) => containedBy(root, value, platform))) {
    throw safety('Journal contains a foreign or noncanonical path.');
  }
}

function assertTimestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || new Date(value).toISOString() !== value) {
    throw safety('Journal timestamp is invalid.');
  }
}

export function assertJournal(journal, { platform = process.platform, ownedRoots } = {}) {
  if (!Array.isArray(ownedRoots) || ownedRoots.length === 0
    || !exactKeys(journal, JOURNAL_KEYS)
    || journal.schemaVersion !== 1 || !UUID.test(journal.operationId)
    || !KINDS.has(journal.kind) || !JOURNAL_PHASES.includes(journal.phase)
    || !exactKeys(journal.ownedPaths, PATH_KEYS)
    || !Array.isArray(journal.ownedPaths.staging) || journal.ownedPaths.staging.length === 0
    || !exactKeys(journal.hashes, HASH_KEYS)
    || typeof journal.priorRunning !== 'boolean') {
    throw safety('Journal schema is invalid.');
  }
  for (const root of ownedRoots) {
    const pathApi = pathApiFor(platform);
    if (typeof root !== 'string' || !pathApi.isAbsolute(root) || /[\0\r\n]/u.test(root)) {
      throw safety('Journal fixed roots are invalid.');
    }
  }
  for (const ownedPath of [
    ...journal.ownedPaths.staging,
    journal.ownedPaths.configTemp,
    journal.ownedPaths.candidateProcess,
    journal.ownedPaths.priorPointerBackup,
    journal.ownedPaths.priorConfigBackup
  ]) {
    if (ownedPath !== null) assertOwnedPath(ownedPath, { platform, ownedRoots });
  }
  for (const hash of Object.values(journal.hashes)) {
    if (hash !== null && (typeof hash !== 'string' || !SHA256.test(hash))) throw safety('Journal hash is invalid.');
  }
  if (journal.priorActivePointer !== null) {
    assertRelativeManagedChild(journal.priorActivePointer, { platform });
  }
  assertTimestamp(journal.createdAt);
  assertTimestamp(journal.updatedAt);
  return journal;
}

function freezeJournal(journal) {
  Object.freeze(journal.ownedPaths.staging);
  Object.freeze(journal.ownedPaths);
  Object.freeze(journal.hashes);
  return Object.freeze(journal);
}

export function createJournal(fields, {
  platform = process.platform,
  ownedRoots,
  now = () => new Date().toISOString()
} = {}) {
  if (!fields?.ownedPaths || !Array.isArray(fields.ownedPaths.staging)) {
    throw safety('Journal schema is invalid.');
  }
  const timestamp = now();
  const journal = {
    schemaVersion: 1,
    operationId: fields?.operationId,
    kind: fields?.kind,
    phase: fields?.phase,
    ownedPaths: fields?.ownedPaths && {
      ...fields.ownedPaths,
      staging: [...fields.ownedPaths.staging]
    },
    hashes: fields?.hashes && { ...fields.hashes },
    priorActivePointer: fields?.priorActivePointer,
    priorRunning: fields?.priorRunning,
    createdAt: fields?.createdAt ?? timestamp,
    updatedAt: fields?.updatedAt ?? timestamp
  };
  assertJournal(journal, { platform, ownedRoots });
  return freezeJournal(journal);
}

export function advanceJournal(journal, nextPhase, {
  platform = process.platform,
  ownedRoots,
  now = () => new Date().toISOString()
} = {}) {
  assertJournal(journal, { platform, ownedRoots });
  const currentIndex = JOURNAL_PHASES.indexOf(journal.phase);
  if (JOURNAL_PHASES[currentIndex + 1] !== nextPhase) throw safety('Journal phase transition is not forward and contiguous.');
  return createJournal({ ...journal, phase: nextPhase, updatedAt: now() }, { platform, ownedRoots, now });
}

function evidence(bytes, reason) {
  return {
    sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
    reason
  };
}

export function parseJournal(bytes, options = {}) {
  const source = Buffer.from(bytes);
  let parsed;
  try {
    parsed = JSON.parse(source.toString('utf8'));
  } catch {
    return { status: 'quarantined', evidence: evidence(source, 'corrupt-json') };
  }
  try {
    assertJournal(parsed, options);
    return { status: 'valid', journal: freezeJournal(parsed) };
  } catch {
    return { status: 'quarantined', evidence: evidence(source, 'invalid-schema') };
  }
}

export async function loadJournal(paths, deps = {}) {
  const platform = deps.platform ?? process.platform;
  const request = { root: paths.stateRoot, child: JOURNAL_CHILD, platform };
  const inspect = deps.inspectOwned ?? (async () => assertContainedNoLinks(request, {
    canonicalize: deps.canonicalize,
    lstat: deps.lstat
  }));
  let target;
  let bytes;
  try {
    target = await inspect(request);
    bytes = await (deps.readFile ?? fs.readFile)(target);
    await inspect(request);
  } catch (error) {
    if (error?.code === 'ENOENT') return { status: 'missing' };
    throw error;
  }
  const result = parseJournal(bytes, { platform, ownedRoots: deps.ownedRoots });
  if (result.status === 'quarantined') await deps.quarantineEvidence?.(result.evidence);
  return result;
}

export async function writeJournal(journal, paths, deps = {}) {
  if (typeof deps.assertLockHeld !== 'function') throw safety('Journal mutation requires the installation lock.');
  await deps.assertLockHeld();
  assertJournal(journal, { platform: deps.platform ?? process.platform, ownedRoots: deps.ownedRoots });
  const bytes = Buffer.from(`${JSON.stringify(journal)}\n`, 'utf8');
  await (deps.atomicReplace ?? atomicReplace)({
    root: paths.stateRoot,
    child: JOURNAL_CHILD,
    bytes,
    mode: 0o600
  }, deps.atomicDeps);
  return journal;
}
