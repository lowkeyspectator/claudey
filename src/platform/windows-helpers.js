import { spawn as spawnChild } from 'node:child_process';
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

function defaultSpawn(command, args, { input, shell }) {
  return new Promise((resolve, reject) => {
    const child = spawnChild(command, args, { shell, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(input);
  });
}

export async function runWindowsSecurityHelper({ helperPath, request, spawn = defaultSpawn }) {
  if (typeof helperPath !== 'string' || !path.win32.isAbsolute(helperPath) || /[\0\r\n]/.test(helperPath)) {
    throw safetyRefusal('Windows helper path is invalid.');
  }
  const input = buildSecurityHelperRequest(request);
  const result = await spawn('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helperPath
  ], { input, shell: false });
  const response = parseSecurityHelperResponse(result?.stdout, { requestId: request.requestId });
  if (result?.code !== 0 || response.ok === false) {
    throw new ClaudexError(response.code ?? 'SAFETY_REFUSAL', response.message ?? 'Windows helper refused the operation.');
  }
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
