import path from 'node:path';

import { ClaudeyError } from './errors.js';

const RUNTIME_KEYS = Object.freeze([
  'schemaVersion', 'installationId', 'instanceId', 'pid', 'processGroupId', 'processStartTime',
  'executableCanonicalPath', 'configCanonicalPath', 'version', 'host', 'port', 'nonce',
  'readinessIdentity', 'lastSuccessfulReadinessAt'
]);
const ROOT_KEYS = Object.freeze([
  'pid', 'parentPid', 'processGroupId', 'processStartTime', 'executableCanonicalPath',
  'configCanonicalPath', 'installationId', 'instanceId', 'nonce'
]);
const DESCENDANT_KEYS = Object.freeze([
  'pid', 'parentPid', 'processGroupId', 'processStartTime', 'executableCanonicalPath'
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/;
const VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const runtimePlatforms = new WeakMap();
const ownershipState = new WeakMap();

function mismatch() {
  return new ClaudeyError('PROCESS_IDENTITY_MISMATCH', 'Managed process identity could not be verified.');
}

function exactKeys(value, keys) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key)));
}

function unhealthy() {
  return new ClaudeyError('GATEWAY_UNHEALTHY', 'Owned process-tree cleanup could not be confirmed.');
}

function safeInteger(value, minimum = 1) {
  return Number.isSafeInteger(value) && value >= minimum;
}

function isoTime(value) {
  if (typeof value !== 'string' || value.length !== 24) return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.valueOf()) && parsed.toISOString() === value;
}

function opaque32(value) {
  if (typeof value !== 'string' || !BASE64URL_32.test(value)) return false;
  try { return Buffer.from(value, 'base64url').length === 32; } catch { return false; }
}

function pathApiFor(platform) {
  if (platform === 'win32') return path.win32;
  if (platform === 'linux' || platform === 'darwin') return path.posix;
  throw mismatch();
}

function canonicalPath(value, platform) {
  const pathApi = pathApiFor(platform);
  if (typeof value !== 'string' || value.length === 0 || /[\u0000-\u001f\u007f]/.test(value)
    || !pathApi.isAbsolute(value) || pathApi.normalize(value) !== value) return false;
  if (platform === 'win32') {
    if (!/^[A-Za-z]:\\/.test(value) || value.slice(2).includes(':')) return false;
    if (value.split('\\').some((segment, index) => index > 0 && (segment === '' || segment === '.' || segment === '..' || /[ .]$/.test(segment)))) return false;
  } else if (value !== '/' && value.split('/').some((segment, index) => index > 0 && (segment === '' || segment === '.' || segment === '..'))) return false;
  return true;
}

function samePath(left, right, platform) {
  return platform === 'win32' ? left.toLowerCase() === right.toLowerCase() : left === right;
}

function freeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freeze(child);
  return Object.freeze(value);
}

function validateRuntime(input, platform) {
  if (!exactKeys(input, RUNTIME_KEYS)
    || input.schemaVersion !== 1
    || !UUID.test(input.installationId)
    || !UUID.test(input.instanceId)
    || !safeInteger(input.pid)
    || !safeInteger(input.processGroupId)
    || !isoTime(input.processStartTime)
    || !canonicalPath(input.executableCanonicalPath, platform)
    || !canonicalPath(input.configCanonicalPath, platform)
    || !VERSION.test(input.version)
    || input.host !== '127.0.0.1'
    || !safeInteger(input.port, 1024) || input.port > 65535
    || !opaque32(input.nonce)
    || !opaque32(input.readinessIdentity)
    || !isoTime(input.lastSuccessfulReadinessAt)) throw mismatch();
}

export function createRuntimeRecord(input, { platform = process.platform } = {}) {
  validateRuntime(input, platform);
  const record = freeze(structuredClone(input));
  runtimePlatforms.set(record, platform);
  return record;
}

export async function parseRuntimeRecord(bytes, { platform = process.platform, assertProtected, canonicalize } = {}) {
  if ((!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) || bytes.byteLength < 2 || bytes.byteLength > 16_384
    || typeof assertProtected !== 'function' || typeof canonicalize !== 'function') throw mismatch();
  let protectedRecord = false;
  try { protectedRecord = await assertProtected() === true; } catch { protectedRecord = false; }
  if (!protectedRecord) throw mismatch();
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw mismatch(); }
  const record = createRuntimeRecord(value, { platform });
  let executable;
  let config;
  try {
    executable = await canonicalize(record.executableCanonicalPath);
    config = await canonicalize(record.configCanonicalPath);
  } catch { throw mismatch(); }
  if (!samePath(executable, record.executableCanonicalPath, platform)
    || !samePath(config, record.configCanonicalPath, platform)) throw mismatch();
  return record;
}

function validateRoot(root, runtime, platform) {
  if (!exactKeys(root, ROOT_KEYS)
    || !safeInteger(root.pid) || !safeInteger(root.parentPid, 0) || root.parentPid === root.pid
    || !safeInteger(root.processGroupId) || !isoTime(root.processStartTime)
    || !canonicalPath(root.executableCanonicalPath, platform)
    || !canonicalPath(root.configCanonicalPath, platform)
    || !UUID.test(root.installationId) || !UUID.test(root.instanceId) || !opaque32(root.nonce)
    || root.pid !== runtime.pid || root.processGroupId !== runtime.processGroupId
    || root.processStartTime !== runtime.processStartTime
    || !samePath(root.executableCanonicalPath, runtime.executableCanonicalPath, platform)
    || !samePath(root.configCanonicalPath, runtime.configCanonicalPath, platform)
    || root.installationId !== runtime.installationId || root.instanceId !== runtime.instanceId
    || root.nonce !== runtime.nonce) throw mismatch();
}

function validateTree(tree, runtime, platform) {
  if (!exactKeys(tree, ['complete', 'root', 'descendants']) || tree.complete !== true || !Array.isArray(tree.descendants)) throw mismatch();
  validateRoot(tree.root, runtime, platform);
  const all = new Map([[tree.root.pid, tree.root]]);
  for (const entry of tree.descendants) {
    if (!exactKeys(entry, DESCENDANT_KEYS)
      || !safeInteger(entry.pid) || !safeInteger(entry.parentPid)
      || entry.pid === entry.parentPid || all.has(entry.pid)
      || entry.processGroupId !== runtime.processGroupId
      || !isoTime(entry.processStartTime)
      || !canonicalPath(entry.executableCanonicalPath, platform)) throw mismatch();
    all.set(entry.pid, entry);
  }
  for (const entry of tree.descendants) {
    const visited = new Set([entry.pid]);
    let parent = entry.parentPid;
    while (parent !== runtime.pid) {
      if (visited.has(parent) || !all.has(parent)) throw mismatch();
      visited.add(parent);
      parent = all.get(parent).parentPid;
    }
  }
  return freeze(structuredClone(tree));
}

function captureAdapter(adapter) {
  if (!adapter || typeof adapter.captureProcessTree !== 'function') throw mismatch();
  const captured = { captureProcessTree: adapter.captureProcessTree.bind(adapter) };
  if (typeof adapter.captureProcessSet === 'function') captured.captureProcessSet = adapter.captureProcessSet.bind(adapter);
  if (typeof adapter.signalTree === 'function') captured.signalTree = adapter.signalTree.bind(adapter);
  if (typeof adapter.waitForTreeExit === 'function') captured.waitForTreeExit = adapter.waitForTreeExit.bind(adapter);
  return Object.freeze(captured);
}

async function captureVerified(runtimeRecord, platform, adapter) {
  let tree;
  try { tree = await adapter.captureProcessTree(runtimeRecord.pid); } catch { throw mismatch(); }
  return validateTree(tree, runtimeRecord, platform);
}

export async function verifyProcessIdentity(runtimeRecord, adapter) {
  const platform = runtimePlatforms.get(runtimeRecord);
  if (!platform) throw mismatch();
  const capturedAdapter = captureAdapter(adapter);
  const tree = await captureVerified(runtimeRecord, platform, capturedAdapter);
  const ownership = freeze({ pid: runtimeRecord.pid, processGroupId: runtimeRecord.processGroupId, pids: [tree.root.pid, ...tree.descendants.map(({ pid }) => pid)].sort((a, b) => a - b) });
  ownershipState.set(ownership, { runtimeRecord, platform, adapter: capturedAdapter, tree });
  return ownership;
}

export function isOwnedProcess(value) {
  return ownershipState.has(value);
}

export function sameOwnedProcessIdentity(left, right) {
  const leftState = ownershipState.get(left);
  const rightState = ownershipState.get(right);
  return Boolean(leftState && rightState
    && leftState.platform === rightState.platform
    && JSON.stringify(leftState.runtimeRecord) === JSON.stringify(rightState.runtimeRecord)
    && JSON.stringify(leftState.tree) === JSON.stringify(rightState.tree));
}

function unchangedTreeSubset(previous, current) {
  if (JSON.stringify(previous.root) !== JSON.stringify(current.root)) return false;
  const prior = new Map(previous.descendants.map((entry) => [entry.pid, JSON.stringify(entry)]));
  return current.descendants.length <= previous.descendants.length
    && current.descendants.every((entry) => prior.get(entry.pid) === JSON.stringify(entry));
}

async function revalidateTree(state, { allowExitedDescendants = false } = {}) {
  try {
    const current = await captureVerified(state.runtimeRecord, state.platform, state.adapter);
    const unchanged = JSON.stringify(current) === JSON.stringify(state.tree);
    if (!unchanged && (!allowExitedDescendants || !unchangedTreeSubset(state.tree, current))) throw mismatch();
    return { tree: current, pids: [current.root.pid, ...current.descendants.map(({ pid }) => pid)].sort((a, b) => a - b) };
  } catch (error) {
    if (!allowExitedDescendants || typeof state.adapter.captureProcessSet !== 'function') throw error;
    const requestedPids = [state.tree.root.pid, ...state.tree.descendants.map(({ pid }) => pid)].sort((a, b) => a - b);
    let observed;
    try { observed = await state.adapter.captureProcessSet(requestedPids); } catch { throw mismatch(); }
    if (!exactKeys(observed, ['complete', 'requestedPids', 'processes']) || observed.complete !== true
      || !Array.isArray(observed.requestedPids) || JSON.stringify(observed.requestedPids) !== JSON.stringify(requestedPids)
      || !Array.isArray(observed.processes)) throw mismatch();
    const expected = new Map([
      [state.tree.root.pid, {
        pid: state.tree.root.pid, parentPid: state.tree.root.parentPid,
        processGroupId: state.tree.root.processGroupId, processStartTime: state.tree.root.processStartTime,
        executableCanonicalPath: state.tree.root.executableCanonicalPath
      }],
      ...state.tree.descendants.map((entry) => [entry.pid, entry])
    ]);
    const survivors = new Set();
    for (const entry of observed.processes) {
      if (!exactKeys(entry, DESCENDANT_KEYS) || survivors.has(entry.pid) || !expected.has(entry.pid)) throw mismatch();
      const prior = expected.get(entry.pid);
      if (entry.pid !== prior.pid || entry.processGroupId !== prior.processGroupId
        || entry.processStartTime !== prior.processStartTime
        || !samePath(entry.executableCanonicalPath, prior.executableCanonicalPath, state.platform)
        || !safeInteger(entry.parentPid, 0) || entry.parentPid === entry.pid) throw mismatch();
      survivors.add(entry.pid);
    }
    return { tree: state.tree, pids: [...survivors].sort((a, b) => a - b) };
  }
}

export async function revalidateOwnedProcess(ownership) {
  const state = ownershipState.get(ownership);
  if (!state) throw mismatch();
  await revalidateTree(state);
  return true;
}

export async function signalOwnedProcess(ownership, { force = false } = {}) {
  const state = ownershipState.get(ownership);
  if (!state || typeof force !== 'boolean') throw mismatch();
  const current = await revalidateTree(state, { allowExitedDescendants: force });
  if (current.pids.length === 0) return true;
  if (typeof state.adapter.signalTree !== 'function') throw mismatch();
  const request = freeze({
    pid: ownership.pid,
    processGroupId: ownership.processGroupId,
    pids: current.pids,
    force
  });
  let result;
  try { result = await state.adapter.signalTree(request); } catch { throw unhealthy(); }
  if (!result || result.acknowledged !== true) throw unhealthy();
  state.tree = current.tree;
  return true;
}

export async function waitForOwnedProcessExit(ownership, { timeoutMs } = {}) {
  const state = ownershipState.get(ownership);
  if (!state || typeof state.adapter.waitForTreeExit !== 'function'
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw mismatch();
  try {
    return await state.adapter.waitForTreeExit({ pids: [...ownership.pids], timeoutMs }) === true;
  } catch { return false; }
}

export function buildProcessHelperRequest(input) {
  const common = ['requestId', 'operation', 'pid'];
  if (!input || typeof input !== 'object' || Array.isArray(input) || !UUID.test(input.requestId)
    || !['inspectProcess', 'listDescendants', 'signalProcess'].includes(input.operation) || !safeInteger(input.pid)) throw mismatch();
  const keys = input.operation === 'signalProcess' ? [...common, 'force'] : common;
  if (!exactKeys(input, keys) || (input.operation === 'signalProcess' && typeof input.force !== 'boolean')) throw mismatch();
  return { schemaVersion: 1, ...input };
}

export function parseProcessHelperResponse(stdout, { requestId, operation, pid, force } = {}) {
  if (typeof stdout !== 'string' || stdout.length < 2 || stdout.length > 64 * 1024 || /[\r\n]/.test(stdout)
    || !UUID.test(requestId) || !['inspectProcess', 'listDescendants', 'signalProcess'].includes(operation) || !safeInteger(pid)) throw mismatch();
  let envelope;
  try { envelope = JSON.parse(stdout); } catch { throw mismatch(); }
  if (!exactKeys(envelope, ['schemaVersion', 'requestId', 'ok', 'result']) || envelope.schemaVersion !== 1
    || envelope.requestId !== requestId || envelope.ok !== true) throw mismatch();
  const result = envelope.result;
  if (operation === 'inspectProcess') {
    if (!exactKeys(result, ['pid', 'parentPid', 'processStartTime', 'executableCanonicalPath'])
      || result.pid !== pid || !safeInteger(result.parentPid, 0) || !isoTime(result.processStartTime)
      || !canonicalPath(result.executableCanonicalPath, 'win32')) throw mismatch();
  } else if (operation === 'listDescendants') {
    if (!exactKeys(result, ['rootPid', 'complete', 'processes']) || result.rootPid !== pid || result.complete !== true || !Array.isArray(result.processes)) throw mismatch();
    const seen = new Set();
    for (const entry of result.processes) {
      if (!exactKeys(entry, ['pid', 'parentPid', 'processStartTime', 'executableCanonicalPath'])
        || !safeInteger(entry.pid) || !safeInteger(entry.parentPid, 0) || entry.pid === entry.parentPid
        || entry.pid === pid || seen.has(entry.pid) || !isoTime(entry.processStartTime)
        || !canonicalPath(entry.executableCanonicalPath, 'win32')) throw mismatch();
      seen.add(entry.pid);
    }
  } else if (!exactKeys(result, ['pid', 'force', 'acknowledged', 'exitCode']) || result.pid !== pid
    || typeof force !== 'boolean' || result.force !== force
    || typeof result.acknowledged !== 'boolean' || !Number.isSafeInteger(result.exitCode)
    || result.acknowledged !== (result.exitCode === 0)) throw mismatch();
  return freeze(result);
}
