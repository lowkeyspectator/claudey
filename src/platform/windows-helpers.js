import { spawn as spawnChild } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ClaudexError } from '../core/errors.js';

const systemSid = 'S-1-5-18';
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fixedPowerShellPath = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const fixedIcaclsPath = 'C:\\Windows\\System32\\icacls.exe';
const bundledHelperPath = fileURLToPath(new URL('../../scripts/windows/security-helper.ps1', import.meta.url));
const defaultTimeoutMs = 120_000;
const defaultOutputLimitBytes = 64 * 1024;
const defaultTerminationGraceMs = 250;

function fail(code, message, cause) {
  return new ClaudexError(code, message, cause ? { cause } : undefined);
}

function safetyRefusal(message, cause) {
  return fail('SAFETY_REFUSAL', message, cause);
}

function capabilityUnsupported(message, cause) {
  return fail('CAPABILITY_UNSUPPORTED', message, cause);
}

function prerequisiteMissing(message, cause) {
  return fail('PREREQUISITE_MISSING', message, cause);
}

function assertExactKeys(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw safetyRefusal('Windows helper protocol requires an object.');
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw safetyRefusal('Windows helper protocol contains unknown or missing fields.');
  }
}

function assertRequest(request) {
  assertExactKeys(request, ['schemaVersion', 'requestId', 'operation', 'path', 'expectedType', 'currentUserSid']);
  if (request.schemaVersion !== 1 || !uuidPattern.test(request.requestId)
    || !['inspect', 'protect'].includes(request.operation)
    || !['file', 'directory'].includes(request.expectedType)
    || typeof request.currentUserSid !== 'string' || !/^S-1-\d+(?:-\d+)+$/i.test(request.currentUserSid)
    || typeof request.path !== 'string' || /[\0\r\n]/.test(request.path) || !path.win32.isAbsolute(request.path)) {
    throw safetyRefusal('Windows helper request is invalid.');
  }
  return request;
}

export function buildSecurityHelperRequest(request) {
  return JSON.stringify(assertRequest({ schemaVersion: 1, ...request }));
}

function assertAce(ace) {
  assertExactKeys(ace, ['type', 'sid', 'rights', 'inherited']);
  if (!['allow', 'deny'].includes(ace.type) || typeof ace.sid !== 'string'
    || !['full-control', 'other'].includes(ace.rights) || typeof ace.inherited !== 'boolean') {
    throw safetyRefusal('Windows helper returned an invalid ACL entry.');
  }
}

function assertResult(result) {
  assertExactKeys(result, ['canonicalPath', 'type', 'isReparsePoint', 'ownerSid', 'daclProtected', 'aces']);
  if (typeof result.canonicalPath !== 'string' || !path.win32.isAbsolute(result.canonicalPath)
    || !['file', 'directory'].includes(result.type) || typeof result.isReparsePoint !== 'boolean'
    || typeof result.ownerSid !== 'string' || typeof result.daclProtected !== 'boolean' || !Array.isArray(result.aces)) {
    throw safetyRefusal('Windows helper returned an invalid inspection result.');
  }
  for (const ace of result.aces) assertAce(ace);
}

export function parseSecurityHelperResponse(stdout, { requestId } = {}) {
  if (typeof stdout !== 'string' || stdout.trim() === '' || stdout.trim().split(/\r?\n/).length !== 1) {
    throw capabilityUnsupported('Windows helper must write exactly one JSON response.');
  }
  let response;
  try {
    response = JSON.parse(stdout.trim());
  } catch (error) {
    throw capabilityUnsupported('Windows helper response is not valid JSON.', error);
  }
  if (response?.ok === true) {
    assertExactKeys(response, ['ok', 'schemaVersion', 'requestId', 'result']);
    if (response.schemaVersion !== 1 || !uuidPattern.test(response.requestId) || response.requestId !== requestId) {
      throw capabilityUnsupported('Windows helper response identity is invalid.');
    }
    assertResult(response.result);
    return response;
  }
  if (response?.ok === false) {
    assertExactKeys(response, ['ok', 'schemaVersion', 'requestId', 'code', 'message']);
    if (response.schemaVersion !== 1 || response.requestId !== requestId || typeof response.code !== 'string' || typeof response.message !== 'string') {
      throw capabilityUnsupported('Windows helper error response is invalid.');
    }
    return response;
  }
  throw capabilityUnsupported('Windows helper response has an invalid envelope.');
}

function assertBoundedText(value, name, maxOutputBytes) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > maxOutputBytes) {
    throw capabilityUnsupported(`Windows helper ${name} exceeded its permitted output.`);
  }
  return value;
}

function sameWindowsPath(left, right) {
  return path.win32.normalize(left).toLowerCase() === path.win32.normalize(right).toLowerCase();
}

function isReparseStat(stats) {
  return stats.isSymbolicLink?.() === true;
}

async function walkNoReparse(absolutePath, fsApi) {
  const normalized = path.win32.normalize(absolutePath);
  const root = path.win32.parse(normalized).root;
  let current = root;
  for (const segment of normalized.slice(root.length).split('\\').filter(Boolean)) {
    current = path.win32.join(current, segment);
    const stats = await fsApi.lstat(current);
    if (isReparseStat(stats)) throw capabilityUnsupported('A trusted Windows path contains a reparse point.');
  }
}

async function verifyTrustedPath(exactPath, { type, fsApi }) {
  if (!path.win32.isAbsolute(exactPath) || /[\0\r\n]/.test(exactPath)) {
    throw capabilityUnsupported('A trusted Windows path is invalid.');
  }
  try {
    await walkNoReparse(exactPath, fsApi);
    const canonical = await fsApi.realpath(exactPath);
    if (!sameWindowsPath(canonical, exactPath)) throw capabilityUnsupported('A trusted Windows path changed identity.');
    const stats = await fsApi.lstat(exactPath);
    if ((type === 'file' && !stats.isFile()) || (type === 'directory' && !stats.isDirectory())) {
      throw capabilityUnsupported('A trusted Windows path has the wrong type.');
    }
    return path.win32.normalize(exactPath);
  } catch (error) {
    if (error instanceof ClaudexError) throw error;
    if (error?.code === 'ENOENT') throw prerequisiteMissing('A required fixed Windows helper executable is missing.', error);
    throw capabilityUnsupported('A trusted Windows path could not be verified.', error);
  }
}

function identityOf(stats) {
  return { dev: stats.dev, ino: stats.ino, birthtimeMs: stats.birthtimeMs };
}

function sameIdentity(stats, identity) {
  return stats.dev === identity.dev && stats.ino === identity.ino && stats.birthtimeMs === identity.birthtimeMs;
}

async function verifyGeneratedIdentity(target, identity, { type, fsApi, parent }) {
  await walkNoReparse(target, fsApi);
  const canonical = await fsApi.realpath(target);
  if (!sameWindowsPath(canonical, target)) throw safetyRefusal('Windows helper request storage changed identity.');
  if (parent && !sameWindowsPath(path.win32.dirname(canonical), parent)) throw safetyRefusal('Windows helper request escaped its directory.');
  const stats = await fsApi.lstat(target);
  if (!sameIdentity(stats, identity) || (type === 'file' ? !stats.isFile() : !stats.isDirectory())) {
    throw safetyRefusal('Windows helper request storage changed identity.');
  }
  return canonical;
}

function defaultSpawn(command, args, {
  shell, windowsHide, timeoutMs, maxOutputBytes,
  terminationGraceMs = defaultTerminationGraceMs,
  spawnChildApi = spawnChild
}) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawnChildApi(command, args, { shell, stdio: ['ignore', 'pipe', 'pipe'], windowsHide });
    } catch (error) {
      reject(prerequisiteMissing('A required Windows helper could not be started.', error));
      return;
    }
    let stdout = '';
    let stderr = '';
    let terminationReason;
    let timeout;
    let escalation;
    let settled = false;
    const clearTimers = () => {
      clearTimeout(timeout);
      clearTimeout(escalation);
    };
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimers();
      callback(value);
    };
    const terminate = (message) => {
      if (terminationReason) return;
      terminationReason = message;
      child.kill();
      escalation = setTimeout(() => child.kill('SIGKILL'), terminationGraceMs);
    };
    timeout = setTimeout(() => terminate('Windows helper timed out.'), timeoutMs);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      if (terminationReason) return;
      stdout += chunk;
      if (Buffer.byteLength(stdout, 'utf8') > maxOutputBytes) terminate('Windows helper stdout exceeded its permitted output.');
    });
    child.stderr.on('data', (chunk) => {
      if (terminationReason) return;
      stderr += chunk;
      if (Buffer.byteLength(stderr, 'utf8') > maxOutputBytes) terminate('Windows helper stderr exceeded its permitted output.');
    });
    child.once('error', (error) => {
      if (!terminationReason) finish(reject, prerequisiteMissing('A required Windows helper failed to start.', error));
    });
    child.once('close', (code) => {
      if (terminationReason) finish(reject, capabilityUnsupported(terminationReason));
      else finish(resolve, { code, stdout, stderr });
    });
  });
}

async function runProcess(command, args, options, deps) {
  const runner = deps.spawn ?? ((cmd, argv, opts) => defaultSpawn(cmd, argv, { ...opts, spawnChildApi: deps.spawnChild }));
  const result = await runner(command, args, options);
  assertBoundedText(result?.stdout, 'stdout', options.maxOutputBytes);
  assertBoundedText(result?.stderr, 'stderr', options.maxOutputBytes);
  return result;
}

async function protectRequestPath(target, { directory, currentUserSid, icaclsPath, limits, deps }) {
  const inheritance = directory ? '(OI)(CI)' : '';
  const args = [
    target,
    '/inheritance:r',
    '/grant:r',
    `*${currentUserSid}:${inheritance}F`,
    `*${systemSid}:${inheritance}F`,
    '/q'
  ];
  const result = await runProcess(icaclsPath, args, limits, deps);
  if (result.code !== 0) throw capabilityUnsupported('Windows request DACL protection failed.');
}

async function confirmAbsent(target, fsApi) {
  try {
    await fsApi.lstat(target);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  throw safetyRefusal('Windows helper request cleanup left residue.');
}

async function cleanupRequestStorage(storage, fsApi) {
  if (!storage.directoryIdentity) return;
  if (storage.fileIdentity) {
    await verifyGeneratedIdentity(storage.requestPath, storage.fileIdentity, {
      type: 'file', fsApi, parent: storage.directoryPath
    });
    await fsApi.rm(storage.requestPath);
    await confirmAbsent(storage.requestPath, fsApi);
  }
  await verifyGeneratedIdentity(storage.directoryPath, storage.directoryIdentity, { type: 'directory', fsApi });
  await fsApi.rmdir(storage.directoryPath);
  await confirmAbsent(storage.directoryPath, fsApi);
}

async function createProtectedRequest(input, { currentUserSid, icaclsPath, limits, deps }) {
  const fsApi = deps.fsApi ?? fs;
  const storage = {};
  let handle;
  try {
    storage.directoryPath = await fsApi.mkdtemp(path.join(os.tmpdir(), 'claudexctl-security-'));
    storage.directoryIdentity = identityOf(await fsApi.lstat(storage.directoryPath));
    await walkNoReparse(storage.directoryPath, fsApi);
    const canonicalDirectory = await fsApi.realpath(storage.directoryPath);
    if (!sameWindowsPath(canonicalDirectory, storage.directoryPath)) {
      throw safetyRefusal('Windows helper request directory changed identity.');
    }
    storage.directoryPath = canonicalDirectory;
    await protectRequestPath(storage.directoryPath, { directory: true, currentUserSid, icaclsPath, limits, deps });
    await verifyGeneratedIdentity(storage.directoryPath, storage.directoryIdentity, { type: 'directory', fsApi });
    storage.requestPath = path.join(storage.directoryPath, 'request.json');
    handle = await fsApi.open(storage.requestPath, 'wx');
    await handle.writeFile(input, 'utf8');
    await handle.sync();
    await handle.close();
    handle = undefined;
    storage.fileIdentity = identityOf(await fsApi.lstat(storage.requestPath));
    await protectRequestPath(storage.requestPath, { directory: false, currentUserSid, icaclsPath, limits, deps });
    await verifyGeneratedIdentity(storage.requestPath, storage.fileIdentity, {
      type: 'file', fsApi, parent: storage.directoryPath
    });
    return storage;
  } catch (error) {
    await handle?.close().catch(() => {});
    error.requestStorage = storage;
    throw error;
  }
}
export async function runWindowsSecurityHelper({
  request,
  timeoutMs = defaultTimeoutMs,
  maxOutputBytes = defaultOutputLimitBytes
}, deps = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || !Number.isInteger(maxOutputBytes) || maxOutputBytes <= 0) {
    throw safetyRefusal('Windows helper execution limits are invalid.');
  }
  const fsApi = deps.fsApi ?? fs;
  const input = buildSecurityHelperRequest(request);
  const limits = { shell: false, windowsHide: true, timeoutMs, maxOutputBytes };
  const powershellPath = await verifyTrustedPath(fixedPowerShellPath, { type: 'file', fsApi });
  const icaclsPath = await verifyTrustedPath(fixedIcaclsPath, { type: 'file', fsApi });
  const helperPath = await verifyTrustedPath(bundledHelperPath, { type: 'file', fsApi });
  let storage;
  let operationError;
  let response;
  try {
    storage = await createProtectedRequest(input, {
      currentUserSid: request.currentUserSid, icaclsPath, limits, deps: { ...deps, fsApi }
    });
    const result = await runProcess(powershellPath, [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', helperPath, '-RequestPath', storage.requestPath
    ], limits, deps);
    response = parseSecurityHelperResponse(result.stdout, { requestId: request.requestId });
    if (result.code !== 0 || response.ok === false) {
      throw new ClaudexError(response.code ?? 'SAFETY_REFUSAL', response.message ?? 'Windows helper refused the operation.');
    }
  } catch (error) {
    operationError = error;
    storage ??= error.requestStorage;
  }
  try {
    await deps.beforeCleanup?.({ ...storage });
    await cleanupRequestStorage(storage ?? {}, fsApi);
  } catch (cleanupError) {
    throw safetyRefusal('Windows helper request cleanup failed closed.', cleanupError);
  }
  if (operationError) throw operationError;
  return response;
}

export function assertWindowsDacl(result, { expectedType, currentUserSid }) {
  if (result.isReparsePoint || result.type !== expectedType || !result.daclProtected || result.ownerSid !== currentUserSid) {
    throw safetyRefusal('Windows managed path protection is invalid.');
  }
  const allowed = new Set([currentUserSid, systemSid]);
  if (result.aces.length !== 2 || result.aces.some((ace) => ace.inherited || ace.type !== 'allow' || ace.rights !== 'full-control' || !allowed.delete(ace.sid))) {
    throw safetyRefusal('Windows managed path DACL is broader than allowed.');
  }
  return result;
}
