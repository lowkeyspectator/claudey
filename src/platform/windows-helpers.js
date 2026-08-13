import { spawn as spawnChild } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { ClaudexError } from '../core/errors.js';

const systemSid = 'S-1-5-18';
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function safetyRefusal(message) {
  return new ClaudexError('SAFETY_REFUSAL', message);
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
    throw safetyRefusal('Windows helper must write exactly one JSON response.');
  }
  let response;
  try {
    response = JSON.parse(stdout.trim());
  } catch {
    throw safetyRefusal('Windows helper response is not valid JSON.');
  }
  if (response?.ok === true) {
    assertExactKeys(response, ['ok', 'schemaVersion', 'requestId', 'result']);
    if (response.schemaVersion !== 1 || !uuidPattern.test(response.requestId) || response.requestId !== requestId) {
      throw safetyRefusal('Windows helper response identity is invalid.');
    }
    assertResult(response.result);
    return response;
  }
  if (response?.ok === false) {
    assertExactKeys(response, ['ok', 'schemaVersion', 'requestId', 'code', 'message']);
    if (response.schemaVersion !== 1 || response.requestId !== requestId || typeof response.code !== 'string' || typeof response.message !== 'string') {
      throw safetyRefusal('Windows helper error response is invalid.');
    }
    return response;
  }
  throw safetyRefusal('Windows helper response has an invalid envelope.');
}

const defaultTimeoutMs = 10_000;
const defaultOutputLimitBytes = 64 * 1024;

function assertBoundedText(value, name, maxOutputBytes) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > maxOutputBytes) {
    throw safetyRefusal(`Windows helper ${name} exceeded its permitted output.`);
  }
  return value;
}

function resolvePowerShellPath(powershellPath) {
  const defaultPath = path.win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const candidate = powershellPath ?? defaultPath;
  const normalized = typeof candidate === 'string' ? path.win32.normalize(candidate) : '';
  const fixedTail = normalized.toLowerCase().endsWith('\\system32\\windowspowershell\\v1.0\\powershell.exe');
  if (typeof candidate !== 'string' || !path.win32.isAbsolute(candidate) || /[\0\r\n]/.test(candidate) || !fixedTail) {
    throw safetyRefusal('Windows helper PowerShell executable is invalid.');
  }
  return normalized;
}

async function writePrivateRequestFile(input, { fsApi = fs, requestDirectory } = {}) {
  const directory = requestDirectory ?? os.tmpdir();
  if (typeof directory !== 'string' || directory.length === 0 || /[\0\r\n]/.test(directory)) {
    throw safetyRefusal('Windows helper request directory is invalid.');
  }
  const requestPath = path.join(directory, `.claudexctl-security-${crypto.randomUUID()}.json`);
  let handle;
  try {
    handle = await fsApi.open(requestPath, 'wx', 0o600);
    await handle.writeFile(input, 'utf8');
    await handle.sync();
    await handle.close();
    handle = undefined;
    await fsApi.chmod(requestPath, 0o600);
    return requestPath;
  } catch (error) {
    await handle?.close().catch(() => {});
    await fsApi.rm(requestPath, { force: true }).catch(() => {});
    throw error;
  }
}

function defaultSpawn(command, args, { shell, windowsHide, timeoutMs, maxOutputBytes }) {
  return new Promise((resolve, reject) => {
    const child = spawnChild(command, args, { shell, stdio: ['ignore', 'pipe', 'pipe'], windowsHide });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback(value);
    };
    const terminate = (message) => {
      child.kill();
      finish(reject, safetyRefusal(message));
    };
    const timer = setTimeout(() => terminate('Windows helper timed out.'), timeoutMs);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      if (Buffer.byteLength(stdout, 'utf8') > maxOutputBytes) terminate('Windows helper stdout exceeded its permitted output.');
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
      if (Buffer.byteLength(stderr, 'utf8') > maxOutputBytes) terminate('Windows helper stderr exceeded its permitted output.');
    });
    child.once('error', (error) => finish(reject, error));
    child.once('close', (code) => finish(resolve, { code, stdout, stderr }));
  });
}

export async function runWindowsSecurityHelper({
  helperPath,
  request,
  powershellPath,
  requestDirectory,
  timeoutMs = defaultTimeoutMs,
  maxOutputBytes = defaultOutputLimitBytes,
  spawn = defaultSpawn,
  fsApi = fs
}) {
  if (typeof helperPath !== 'string' || !path.win32.isAbsolute(helperPath) || /[\0\r\n]/.test(helperPath)) {
    throw safetyRefusal('Windows helper path is invalid.');
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || !Number.isInteger(maxOutputBytes) || maxOutputBytes <= 0) {
    throw safetyRefusal('Windows helper execution limits are invalid.');
  }
  const input = buildSecurityHelperRequest(request);
  const requestPath = await writePrivateRequestFile(input, { fsApi, requestDirectory });
  try {
    const result = await spawn(resolvePowerShellPath(powershellPath), [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', helperPath, '-RequestPath', requestPath
    ], { shell: false, windowsHide: true, timeoutMs, maxOutputBytes });
    assertBoundedText(result?.stdout, 'stdout', maxOutputBytes);
    assertBoundedText(result?.stderr, 'stderr', maxOutputBytes);
    const response = parseSecurityHelperResponse(result.stdout, { requestId: request.requestId });
    if (result?.code !== 0 || response.ok === false) {
      throw new ClaudexError(response.code ?? 'SAFETY_REFUSAL', response.message ?? 'Windows helper refused the operation.');
    }
    return response;
  } finally {
    await fsApi.rm(requestPath, { force: true }).catch(() => {});
  }
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
