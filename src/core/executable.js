import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { TextDecoder } from 'node:util';

import { ClaudexError } from './errors.js';

const MAX_SHIM_BYTES = 4_096;
const KNOWN_NPM_ENTRIES = Object.freeze({
  claude: ['@anthropic-ai', 'claude-code', 'cli.js'],
  cliproxyapi: ['cliproxyapi', 'cli.js'],
  'cursor-agent': ['@cursor', 'agent', 'cli.js'],
  agent: ['@cursor', 'agent', 'cli.js']
});
const KNOWN_NATIVE_COMMANDS = new Set(['claude', 'cursor-agent', 'agent', 'CLIProxyAPI', 'cliproxyapi', 'node', 'git', 'tar', 'powershell', 'taskkill']);
const REQUIRED_ADAPTER_METHODS = Object.freeze(['realpath', 'lstat', 'stat', 'openNoFollow']);
const STABLE_FIELDS = Object.freeze(['dev', 'ino', 'birthtimeMs']);
const EXACT_LEAF_FIELDS = Object.freeze(['mode', 'size', 'mtimeMs', 'ctimeMs']);
const PRIVATE_EXECUTABLES = new WeakMap();

function refusal(message, cause) {
  throw new ClaudexError('PREREQUISITE_MISSING', message, { cause });
}

function deeplyFreeze(value, seen = new Set()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deeplyFreeze(child, seen);
  return Object.freeze(value);
}

function pathApiFor(platform) {
  if (platform === 'win32') return path.win32;
  if (platform === 'darwin' || platform === 'linux') return path.posix;
  refusal('Executable platform is unsupported');
}

function samePath(left, right, platform) {
  return platform === 'win32' ? left.toLowerCase() === right.toLowerCase() : left === right;
}

function assertSafeAbsolutePath(value, platform) {
  const pathApi = pathApiFor(platform);
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || /[\u0000-\u001f\u007f]/.test(value) || !pathApi.isAbsolute(value)) {
    refusal('Executable path is not a safe absolute path');
  }
  if (platform === 'win32') {
    if (!/^[A-Za-z]:\\/.test(value) || value.slice(2).includes(':')) refusal('Executable path contains an alternate stream or ambiguous prefix');
    if (/^[A-Za-z]:\\$/.test(value)) return;
    if (value.split('\\').some((segment, index) => index > 0 && (segment === '' || segment === '.' || segment === '..' || /[ .]$/.test(segment)))) {
      refusal('Executable path contains an ambiguous Windows segment');
    }
  } else if (value.split('/').some((segment, index) => index > 0 && (segment === '' || segment === '.' || segment === '..'))) {
    if (value === '/') return;
    refusal('Executable path contains an ambiguous POSIX segment');
  }
  if (pathApi.normalize(value) !== value) refusal('Executable path is not normalized');
}

function captureAdapter(adapter) {
  assertAdapter(adapter);
  return Object.freeze(Object.fromEntries(REQUIRED_ADAPTER_METHODS.map((name) => [name, adapter[name].bind(adapter)])));
}
function assertAdapter(adapter) {
  if (!adapter || typeof adapter !== 'object' || REQUIRED_ADAPTER_METHODS.some((name) => typeof adapter[name] !== 'function')) {
    refusal('Executable filesystem adapter is incomplete');
  }
}

function numericIdentity(value, field) {
  if ((typeof value !== 'number' || !Number.isFinite(value)) && typeof value !== 'bigint') refusal(`Executable filesystem ${field} is invalid`);
  return String(value);
}

function assertStats(stats, platform) {
  if (!stats || typeof stats !== 'object' || typeof stats.isFile !== 'function' || typeof stats.isDirectory !== 'function' || typeof stats.isSymbolicLink !== 'function') {
    refusal('Executable filesystem metadata is invalid');
  }
  for (const field of [...STABLE_FIELDS, ...EXACT_LEAF_FIELDS]) numericIdentity(stats[field], field);
  if (platform === 'win32' && (!Number.isSafeInteger(stats.reparseTag) || stats.reparseTag !== 0)) refusal('Windows executable reparse tag is missing or unsafe');
  if (stats.isSymbolicLink() || stats.reparse === true || stats.isReparsePoint === true) refusal('Executable path traverses a link or reparse point');
  const file = stats.isFile();
  const directory = stats.isDirectory();
  if (typeof file !== 'boolean' || typeof directory !== 'boolean' || file === directory) refusal('Executable filesystem type is ambiguous');
  return file ? 'file' : 'directory';
}

function stableRecord(stats, includeExact) {
  const record = {};
  for (const field of STABLE_FIELDS) record[field] = numericIdentity(stats[field], field);
  if (includeExact) for (const field of EXACT_LEAF_FIELDS) record[field] = numericIdentity(stats[field], field);
  return record;
}

function recordsEqual(left, right, includeExact) {
  const fields = includeExact ? [...STABLE_FIELDS, ...EXACT_LEAF_FIELDS] : STABLE_FIELDS;
  return fields.every((field) => numericIdentity(left[field], field) === numericIdentity(right[field], field));
}

function componentPaths(target, platform) {
  const pathApi = pathApiFor(platform);
  const root = pathApi.parse(target).root;
  const relative = target.slice(root.length).split(pathApi.sep).filter(Boolean);
  const result = [root];
  for (const segment of relative) result.push(pathApi.join(result.at(-1), segment));
  return result;
}

function assertLeafShape(stats, expected, platform, target) {
  if (!stats.isFile()) refusal('Executable leaf is not a regular file');
  const extension = pathApiFor(platform).extname(target).toLowerCase();
  if (expected === 'native' || expected === 'node') {
    if (platform === 'win32' ? extension !== '.exe' : (Number(stats.mode) & 0o111) === 0) refusal('Executable leaf has an invalid extension or mode');
  } else if (expected === 'shim' && extension !== '.cmd') refusal('Executable npm shim must be a .cmd file');
  else if (expected === 'entry' && extension !== '.js') refusal('Executable npm entry must be a JavaScript file');
}

async function inspectLeafHandle(adapter, target, leafType, readBytes, platform) {
  let handle;
  try {
    handle = await adapter.openNoFollow(target);
    if (!handle || handle.noFollow !== true || typeof handle.stat !== 'function' || typeof handle.close !== 'function' || (readBytes && typeof handle.read !== 'function')) {
      refusal('Executable no-follow handle is invalid');
    }
    const handleStats = await handle.stat();
    const handleType = assertStats(handleStats, platform);
    assertLeafShape(handleStats, leafType, platform, target);
    const [canonicalAfterOpen, lstatAfterOpen, statAfterOpen] = await Promise.all([
      adapter.realpath(target), adapter.lstat(target), adapter.stat(target)
    ]);
    assertSafeAbsolutePath(canonicalAfterOpen, platform);
    if (!samePath(target, canonicalAfterOpen, platform)) refusal('Executable leaf canonical identity changed after open');
    const lstatType = assertStats(lstatAfterOpen, platform);
    const statType = assertStats(statAfterOpen, platform);
    if (handleType !== lstatType || handleType !== statType) refusal('Executable leaf path type changed after no-follow open');
    if (!recordsEqual(handleStats, lstatAfterOpen, true) || !recordsEqual(handleStats, statAfterOpen, true)) {
      refusal('Executable leaf path identity changed after no-follow open');
    }
    let bytes = null;
    if (readBytes) {
      const buffer = Buffer.alloc(MAX_SHIM_BYTES + 1);
      const read = await handle.read(buffer, 0, buffer.length, 0);
      if (!read || !Number.isSafeInteger(read.bytesRead) || read.bytesRead < 0 || read.bytesRead > buffer.length) refusal('Executable shim read result is invalid');
      if (read.bytesRead > MAX_SHIM_BYTES) refusal('Executable npm shim exceeds its size limit');
      bytes = buffer.subarray(0, read.bytesRead);
    }
    return { canonical: canonicalAfterOpen, stats: handleStats, bytes };
  } catch (error) {
    if (error instanceof ClaudexError) throw error;
    refusal('Executable no-follow inspection failed', error);
  } finally {
    if (handle && typeof handle.close === 'function') {
      try { await handle.close(); } catch { /* a failed close still leaves the identity check failed by its caller */ }
    }
  }
}

async function inspectPath(target, { platform, adapter, leafType, readBytes = false }) {
  assertSafeAbsolutePath(target, platform);
  const paths = componentPaths(target, platform);
  const components = [];
  let bytes = null;
  let canonical = target;
  for (let index = 0; index < paths.length; index += 1) {
    const current = paths[index];
    const leaf = index === paths.length - 1;
    if (leaf) {
      const inspected = await inspectLeafHandle(adapter, current, leafType, readBytes, platform);
      canonical = inspected.canonical;
      bytes = inspected.bytes;
      components.push({ path: canonical, type: 'file', ...stableRecord(inspected.stats, true) });
      continue;
    }
    let canonicalCurrent;
    let lstat;
    let stat;
    try {
      [canonicalCurrent, lstat, stat] = await Promise.all([adapter.realpath(current), adapter.lstat(current), adapter.stat(current)]);
    } catch (error) { refusal('Executable path component cannot be inspected', error); }
    assertSafeAbsolutePath(canonicalCurrent, platform);
    if (!samePath(current, canonicalCurrent, platform)) refusal('Executable path component changed canonical identity');
    const lstatType = assertStats(lstat, platform);
    const statType = assertStats(stat, platform);
    if (lstatType !== statType || !recordsEqual(lstat, stat, false)) refusal('Executable path component identity is inconsistent');
    if (!lstat.isDirectory()) refusal('Executable ancestor is not a directory');
    components.push({ path: canonicalCurrent, type: lstatType, ...stableRecord(lstat, false) });
  }
  return { canonical, components, bytes };
}

function mergeComponents(groups, platform) {
  const merged = new Map();
  for (const component of groups.flat()) {
    const key = platform === 'win32' ? component.path.toLowerCase() : component.path;
    const prior = merged.get(key);
    if (prior && JSON.stringify(prior) !== JSON.stringify(component)) refusal('Executable component identity changed during resolution');
    merged.set(key, component);
  }
  return [...merged.values()];
}

function candidatePath(candidate) {
  return typeof candidate === 'string' ? candidate : candidate?.path;
}

function identityMatches(actual, expected) {
  if (!expected || typeof expected !== 'object') return false;
  try { return JSON.stringify(actual) === JSON.stringify(expected); } catch { return false; }
}

export async function resolveVerifiedExecutable({ command, platform, candidates, expectedIdentity, adapter } = {}) {
  const trustedAdapter = captureAdapter(adapter);
  if (typeof command !== 'string' || !KNOWN_NATIVE_COMMANDS.has(command) || !Array.isArray(candidates) || candidates.length === 0) {
    refusal('Executable candidate is required');
  }
  const paths = candidates.map(candidatePath);
  for (const target of paths) assertSafeAbsolutePath(target, platform);
  const pathApi = pathApiFor(platform);
  const nativePaths = paths.filter((target) => platform === 'win32' ? pathApi.extname(target).toLowerCase() === '.exe' : pathApi.extname(target).toLowerCase() !== '.cmd');
  if (nativePaths.length > 1) refusal('Executable native identity is ambiguous');

  let result;
  if (nativePaths.length === 1) {
    const native = await inspectPath(nativePaths[0], { platform, adapter: trustedAdapter, leafType: 'native' });
    const identity = {
      schemaVersion: 1, command, platform, kind: 'native', candidatePaths: [...paths], components: native.components
    };
    result = { kind: 'native', executablePath: native.canonical, argsPrefix: [], identity };
  } else {
    if (platform !== 'win32' || paths.length !== 1 || pathApi.extname(paths[0]).toLowerCase() !== '.cmd') refusal('Executable shim is not supported');
    const entrySegments = KNOWN_NPM_ENTRIES[command];
    if (!entrySegments) refusal('Executable npm shim command is unknown');
    const shim = await inspectPath(paths[0], { platform, adapter: trustedAdapter, leafType: 'shim', readBytes: true });
    const shimDirectory = pathApi.dirname(shim.canonical);
    const nodePath = pathApi.join(shimDirectory, 'node.exe');
    const entryPath = pathApi.join(shimDirectory, 'node_modules', ...entrySegments);
    const node = await inspectPath(nodePath, { platform, adapter: trustedAdapter, leafType: 'node' });
    const entry = await inspectPath(entryPath, { platform, adapter: trustedAdapter, leafType: 'entry' });
    const expectedScript = `@ECHO off\r\n"%~dp0\\node.exe" "%~dp0\\node_modules\\${entrySegments.join('\\')}" %*\r\n`;
    let script;
    try { script = new TextDecoder('utf-8', { fatal: true }).decode(shim.bytes); } catch (error) { refusal('Executable npm shim is not valid UTF-8', error); }
    if (script !== expectedScript) refusal('Executable npm shim has an unsafe structure');
    const entryRoot = pathApi.join(shimDirectory, 'node_modules') + pathApi.sep;
    if (!entry.canonical.toLowerCase().startsWith(entryRoot.toLowerCase())) refusal('Executable npm entry escapes its installation');
    const identity = {
      schemaVersion: 1,
      command,
      platform,
      kind: 'node-entry',
      candidatePaths: [...paths],
      components: mergeComponents([shim.components, node.components, entry.components], platform),
      shimSha256: createHash('sha256').update(shim.bytes).digest('hex')
    };
    result = { kind: 'node-entry', executablePath: node.canonical, argsPrefix: [entry.canonical], identity };
  }
  const frozen = deeplyFreeze(result);
  PRIVATE_EXECUTABLES.set(frozen, deeplyFreeze({
    adapter: trustedAdapter,
    command: frozen.identity.command,
    platform: frozen.identity.platform,
    candidatePaths: [...frozen.identity.candidatePaths],
    identity: frozen.identity,
    executablePath: frozen.executablePath,
    argsPrefix: [...frozen.argsPrefix]
  }));
  if (expectedIdentity !== undefined && !identityMatches(frozen.identity, expectedIdentity)) {
    throw new ClaudexError('PROCESS_IDENTITY_MISMATCH', 'Executable identity changed');
  }
  return frozen;
}

export function createDefaultExecutableAdapter() {
  const tagged = (stats) => {
    if (stats.reparseTag === undefined) Object.defineProperty(stats, 'reparseTag', { value: 0, writable: true, configurable: true });
    return stats;
  };
  return {
    realpath: async (value) => {
      try { return await fs.realpath(value); }
      catch (error) { if (error?.code === 'EPERM') return value; throw error; }
    },
    lstat: async (value) => tagged(await fs.lstat(value)),
    stat: async (value) => tagged(await fs.stat(value)),
    openNoFollow: async (value) => {
      const before = tagged(await fs.lstat(value));
      if (before.isSymbolicLink()) throw Object.assign(new Error('link'), { code: 'ELOOP' });
      const handle = await fs.open(value, 'r');
      return {
        ...handle,
        noFollow: true,
        read: handle.read.bind(handle),
        close: handle.close.bind(handle),
        stat: async () => tagged(await handle.stat())
      };
    }
  };
}

export function isVerifiedExecutable(resolved) {
  return Boolean(resolved && typeof resolved === 'object' && PRIVATE_EXECUTABLES.has(resolved));
}

export function isVerifiedExecutableForCommand(resolved, command) {
  const facts = PRIVATE_EXECUTABLES.get(resolved);
  return Boolean(facts && typeof command === 'string' && facts.command === command);
}

export function getVerifiedInvocation(resolved) {
  const facts = PRIVATE_EXECUTABLES.get(resolved);
  if (!facts) return null;
  return { executablePath: facts.executablePath, argsPrefix: [...facts.argsPrefix] };
}

export async function revalidateExecutable(resolved) {
  const facts = PRIVATE_EXECUTABLES.get(resolved);
  if (!facts) return false;
  try {
    const current = await resolveVerifiedExecutable({
      command: facts.command,
      platform: facts.platform,
      candidates: facts.candidatePaths.map((target) => ({ path: target })),
      expectedIdentity: facts.identity,
      adapter: facts.adapter
    });
    return current.executablePath === facts.executablePath && JSON.stringify(current.argsPrefix) === JSON.stringify(facts.argsPrefix);
  } catch { return false; }
}
