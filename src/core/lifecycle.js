import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import { ClaudeyError } from './errors.js';
import { assertContainedNoLinks, resolveManagedChild } from './fs-safe.js';
import { getVerifiedInvocation, revalidateExecutable } from './executable.js';
import { requestGatewayModels } from './gateway-client.js';
import { atomicReplace } from './permissions.js';
import {
  createRuntimeRecord,
  parseRuntimeRecord,
  sameOwnedProcessIdentity,
  signalOwnedProcess,
  verifyProcessIdentity,
  waitForOwnedProcessExit
} from './process.js';
import { inspectPortOwnership } from './port.js';
import { isSecret } from './secrets.js';
import { validateAuthenticatedModelCatalog } from '../providers/capabilities.js';

const DEFAULTS = Object.freeze({
  startupTimeoutMs: 10_000,
  pollIntervalMs: 50,
  gracefulTimeoutMs: 2_000,
  forceTimeoutMs: 2_000,
  maxLogBytes: 64 * 1024
});
const ENV_ALLOWLIST = Object.freeze([
  'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'TMPDIR', 'HOME', 'USERPROFILE', 'LANG', 'LC_ALL'
]);
const READINESS_DOMAIN = 'claudeyctl-gateway-readiness-v1\0';
const READINESS_BINDING_KEYS = Object.freeze([
  'schemaVersion', 'installationId', 'instanceId', 'pid', 'processGroupId', 'processStartTime',
  'executableCanonicalPath', 'configCanonicalPath', 'version', 'host', 'port', 'nonce'
]);

function unhealthy(message = 'The managed gateway lifecycle operation could not be completed safely.') {
  return new ClaudeyError('GATEWAY_UNHEALTHY', message);
}

function mismatch() {
  return new ClaudeyError('PROCESS_IDENTITY_MISMATCH', 'Managed process identity could not be verified.');
}

function checkedDuration(value, fallback) {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > 120_000) throw unhealthy();
  return result;
}

function pathApiFor(platform) {
  if (platform === 'win32') return path.win32;
  if (platform === 'linux' || platform === 'darwin') return path.posix;
  throw unhealthy();
}

function safeCanonicalPath(value, platform) {
  const pathApi = pathApiFor(platform);
  return typeof value === 'string' && value.length > 0 && !/[\u0000-\u001f\u007f]/.test(value)
    && pathApi.isAbsolute(value) && pathApi.normalize(value) === value;
}

function publicError(error) {
  if (error?.code === 'PROCESS_IDENTITY_MISMATCH') return mismatch();
  if (error?.code === 'PORT_IN_USE') {
    return new ClaudeyError('PORT_IN_USE', 'The configured loopback port is occupied by an unrelated listener.');
  }
  return unhealthy();
}

function captureEnvironment(source = process.env) {
  const env = {};
  for (const name of ENV_ALLOWLIST) {
    if (typeof source?.[name] === 'string' && source[name].length > 0) env[name] = source[name];
  }
  return Object.freeze(env);
}

function normalizeRuntime(record, platform) {
  try { return createRuntimeRecord(record, { platform }); } catch { throw mismatch(); }
}

function runtimeFileIdentity(stats) {
  if (!stats?.isFile?.() || stats.isSymbolicLink?.() || stats.isReparsePoint === true
    || !/^(0|[1-9]\d*)$/.test(String(stats.dev)) || !/^(0|[1-9]\d*)$/.test(String(stats.ino))) throw mismatch();
  return Object.freeze({ dev: String(stats.dev), ino: String(stats.ino) });
}

function sameRuntimeFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function assertContext(ctx) {
  if (!ctx || typeof ctx !== 'object' || ctx.host !== '127.0.0.1'
    || !Number.isSafeInteger(ctx.port) || ctx.port < 1024 || ctx.port > 65535
    || !isSecret(ctx.token) || typeof ctx.installationId !== 'string'
    || typeof ctx.version !== 'string' || !safeCanonicalPath(ctx.configCanonicalPath, ctx.platform)
    || !ctx.runtimeStore || typeof ctx.runtimeStore.load !== 'function' || typeof ctx.runtimeStore.write !== 'function'
    || typeof ctx.runtimeStore.remove !== 'function' || !ctx.processAdapter
    || typeof ctx.inspectListeners !== 'function' || typeof ctx.cleanupSpawnedChild !== 'function') throw unhealthy();
}

async function fixedInvocation(ctx, foreground) {
  const revalidate = ctx.revalidateExecutable ?? revalidateExecutable;
  const invocationFor = ctx.getInvocation ?? getVerifiedInvocation;
  let verified = false;
  try { verified = await revalidate(ctx.executable) === true; } catch { verified = false; }
  const trusted = verified ? invocationFor(ctx.executable) : null;
  if (!trusted || !safeCanonicalPath(trusted.executablePath, ctx.platform)
    || !Array.isArray(trusted.argsPrefix) || !trusted.argsPrefix.every((argument) => typeof argument === 'string' && !/[\0\r\n]/.test(argument))) throw mismatch();
  return Object.freeze({
    executablePath: trusted.executablePath,
    args: Object.freeze([...trusted.argsPrefix, '--config', ctx.configCanonicalPath]),
    shell: false,
    detached: foreground ? false : ctx.platform !== 'win32',
    foreground,
    env: captureEnvironment(ctx.baseEnvironment),
    maxStdoutBytes: DEFAULTS.maxLogBytes,
    maxStderrBytes: DEFAULTS.maxLogBytes
  });
}

function exactTime(ctx) {
  const value = (ctx.now ?? (() => new Date().toISOString()))();
  if (typeof value !== 'string' || new Date(value).toISOString() !== value) throw unhealthy();
  return value;
}

function randomIdentity(ctx) {
  const bytes = (ctx.randomBytes ?? crypto.randomBytes)(32);
  if ((!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) || bytes.byteLength !== 32) throw unhealthy();
  return Buffer.from(bytes).toString('base64url');
}

function readinessIdentity(record, token) {
  const binding = {};
  for (const key of READINESS_BINDING_KEYS) binding[key] = record[key];
  try {
    return token.withValue((bytes) => {
      if (bytes.length !== 32) throw mismatch();
      return crypto.createHmac('sha256', Buffer.from(bytes))
        .update(READINESS_DOMAIN, 'utf8').update(JSON.stringify(binding), 'utf8').digest('base64url');
    });
  } catch {
    throw mismatch();
  }
}

function assertReadinessIdentity(record, token) {
  const actual = Buffer.from(record.readinessIdentity, 'base64url');
  const expected = Buffer.from(readinessIdentity(record, token), 'base64url');
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) throw mismatch();
}

async function assertRuntimeBinding(ctx, record) {
  if (record.installationId !== ctx.installationId || record.version !== ctx.version
    || record.host !== ctx.host || record.port !== ctx.port
    || record.configCanonicalPath !== ctx.configCanonicalPath) throw mismatch();
  const invocation = await fixedInvocation(ctx, false);
  if (record.executableCanonicalPath !== invocation.executablePath) throw mismatch();
}

function makeRuntime(ctx, invocation, child) {
  const nonce = randomIdentity(ctx);
  const record = {
    schemaVersion: 1,
    installationId: ctx.installationId,
    instanceId: (ctx.randomUUID ?? crypto.randomUUID)(),
    pid: child.pid,
    processGroupId: child.processGroupId,
    processStartTime: child.processStartTime,
    executableCanonicalPath: invocation.executablePath,
    configCanonicalPath: ctx.configCanonicalPath,
    version: ctx.version,
    host: '127.0.0.1',
    port: ctx.port,
    nonce,
    readinessIdentity: '',
    lastSuccessfulReadinessAt: exactTime(ctx)
  };
  record.readinessIdentity = readinessIdentity(record, ctx.token);
  return createRuntimeRecord(record, { platform: ctx.platform });
}

async function requestHealthyCatalog(ctx) {
  const request = ctx.requestGatewayModels ?? requestGatewayModels;
  const allowPreAuthEmpty = ctx.allowPreAuthEmpty === true;
  const catalog = await request({
    host: '127.0.0.1', port: ctx.port, token: ctx.token, allowPreAuthEmpty,
    timeoutMs: Math.min(checkedDuration(ctx.pollIntervalMs, DEFAULTS.pollIntervalMs), 3_000),
    signal: ctx.signal
  });
  if (!validateAuthenticatedModelCatalog(catalog, { allowPreAuthEmpty })) throw unhealthy();
  return catalog;
}

async function ensureRecordHealthy(ctx, record) {
  await assertRuntimeBinding(ctx, record);
  assertReadinessIdentity(record, ctx.token);
  const before = await inspectPortOwnership({ host: '127.0.0.1', port: ctx.port, runtimeRecord: record }, {
    inspectListeners: ctx.inspectListeners,
    processAdapter: ctx.processAdapter
  });
  if (before.state !== 'owned') throw unhealthy();
  const models = await requestHealthyCatalog(ctx);
  const after = await inspectPortOwnership({ host: '127.0.0.1', port: ctx.port, runtimeRecord: record }, {
    inspectListeners: ctx.inspectListeners,
    processAdapter: ctx.processAdapter
  });
  if (after.state !== 'owned' || !sameOwnedProcessIdentity(before.ownership, after.ownership)) throw mismatch();
  return { state: 'healthy', runtimeRecord: record, ownership: after.ownership, models };
}

export async function verifyOwnedProcess(runtimeRecord, adapter) {
  const inferredPlatform = /^[A-Za-z]:\\/.test(runtimeRecord?.executableCanonicalPath ?? '')
    ? 'win32' : (adapter?.platform ?? (process.platform === 'win32' ? 'linux' : process.platform));
  return verifyProcessIdentity(normalizeRuntime(runtimeRecord, inferredPlatform), adapter);
}

async function terminateOwnership(ownership, ctx) {
  await signalOwnedProcess(ownership, { force: false });
  if (await waitForOwnedProcessExit(ownership, { timeoutMs: checkedDuration(ctx.gracefulTimeoutMs, DEFAULTS.gracefulTimeoutMs) })) return true;
  await signalOwnedProcess(ownership, { force: true });
  if (await waitForOwnedProcessExit(ownership, { timeoutMs: checkedDuration(ctx.forceTimeoutMs, DEFAULTS.forceTimeoutMs) })) return true;
  throw unhealthy('Owned process-tree cleanup could not be confirmed.');
}

async function terminateRecord(record, ctx) {
  const ownership = await verifyOwnedProcess(record, ctx.processAdapter);
  return terminateOwnership(ownership, ctx);
}

async function removeAfterConfirmedStop(ctx) {
  try { await ctx.runtimeStore.remove(); } catch { throw unhealthy('Runtime cleanup could not be confirmed.'); }
}

async function cleanupFailedStart(record, ctx) {
  await terminateRecord(record, ctx);
  await removeAfterConfirmedStop(ctx);
}

export async function ensureGatewayHealthy(ctx) {
  assertContext(ctx);
  const stored = await ctx.runtimeStore.load();
  if (!stored) throw unhealthy();
  const record = normalizeRuntime(stored, ctx.platform);
  return ensureRecordHealthy(ctx, record);
}

export async function startOwnedGateway(ctx, { foreground = false } = {}) {
  assertContext(ctx);
  if (typeof foreground !== 'boolean') throw unhealthy();
  const existing = await ctx.runtimeStore.load();
  if (existing) {
    const healthy = await ensureRecordHealthy(ctx, normalizeRuntime(existing, ctx.platform));
    return { ...healthy, state: 'already-running' };
  }
  const initialPort = await inspectPortOwnership({ host: '127.0.0.1', port: ctx.port, runtimeRecord: null }, {
    inspectListeners: ctx.inspectListeners,
    processAdapter: ctx.processAdapter
  });
  if (initialPort.state !== 'free') throw unhealthy();
  if (ctx.signal?.aborted) throw unhealthy();
  const invocation = await fixedInvocation(ctx, foreground);
  if (typeof ctx.spawnGateway !== 'function' || typeof ctx.isChildExited !== 'function') throw mismatch();
  let child;
  let record;
  try {
    child = await ctx.spawnGateway(invocation);
    record = makeRuntime(ctx, invocation, child);
    await ctx.runtimeStore.write(record);
    const timeoutMs = checkedDuration(ctx.startupTimeoutMs, DEFAULTS.startupTimeoutMs);
    const intervalMs = checkedDuration(ctx.pollIntervalMs, DEFAULTS.pollIntervalMs);
    const monotonicNow = ctx.monotonicNow ?? Date.now;
    const sleep = ctx.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
    const deadline = monotonicNow() + timeoutMs;
    let lastError = unhealthy();
    while (monotonicNow() < deadline) {
      if (ctx.signal?.aborted || await ctx.isChildExited(child)) throw unhealthy();
      try {
        const healthy = await ensureRecordHealthy(ctx, record);
        const readyRecord = createRuntimeRecord({ ...record, lastSuccessfulReadinessAt: exactTime(ctx) }, { platform: ctx.platform });
        await ctx.runtimeStore.write(readyRecord);
        return { ...healthy, state: foreground ? 'foreground' : 'started', runtimeRecord: readyRecord };
      } catch (error) {
        if (error?.code === 'PORT_IN_USE' || error?.code === 'PROCESS_IDENTITY_MISMATCH') throw error;
        lastError = publicError(error);
      }
      if (ctx.signal?.aborted) throw unhealthy();
      await sleep(Math.min(intervalMs, Math.max(1, deadline - monotonicNow())));
    }
    throw lastError;
  } catch (error) {
    const original = publicError(error);
    try { ctx.onLifecycleDiagnostic?.({ code: original.code }); } catch { /* diagnostics cannot own cleanup */ }
    if (record) {
      try { await cleanupFailedStart(record, ctx); }
      catch (cleanupError) { throw publicError(cleanupError); }
    } else if (child) {
      try {
        if (await ctx.cleanupSpawnedChild(child) !== true) throw unhealthy();
      } catch (cleanupError) {
        throw publicError(cleanupError);
      }
    }
    throw original;
  }
}

export async function stopOwnedGateway(ctx) {
  assertContext(ctx);
  const stored = await ctx.runtimeStore.load();
  if (!stored) return { state: 'already-stopped' };
  const record = normalizeRuntime(stored, ctx.platform);
  await assertRuntimeBinding(ctx, record);
  const port = await inspectPortOwnership({ host: '127.0.0.1', port: ctx.port, runtimeRecord: record }, {
    inspectListeners: ctx.inspectListeners,
    processAdapter: ctx.processAdapter
  });
  const ownership = port.state === 'owned' ? port.ownership : await verifyOwnedProcess(record, ctx.processAdapter);
  await terminateOwnership(ownership, ctx);
  await removeAfterConfirmedStop(ctx);
  return { state: 'stopped' };
}

export async function restartOwnedGateway(ctx, options = {}) {
  await stopOwnedGateway(ctx);
  return startOwnedGateway(ctx, options);
}

export function createRuntimeStore({ root, child = 'gateway-runtime.json', platform = process.platform } = {}, deps = {}) {
  if (typeof root !== 'string' || typeof child !== 'string' || typeof deps.assertProtected !== 'function') throw mismatch();
  resolveManagedChild(root, child, { platform });
  const fsApi = deps.fsApi ?? fs;
  const canonicalize = deps.canonicalize ?? ((value) => fsApi.realpath(value));
  const replace = deps.atomicReplace ?? atomicReplace;
  const load = async () => {
    const safetyDeps = { lstat: fsApi.lstat.bind(fsApi), canonicalize: async (value) => fsApi.realpath(value) };
    const checked = await assertContainedNoLinks({ root, child, platform }, safetyDeps);
    let before;
    try { before = runtimeFileIdentity(await fsApi.lstat(checked, { bigint: true })); }
    catch (error) { if (error?.code === 'ENOENT') return null; throw mismatch(); }
    if (await deps.assertProtected(checked) !== true) throw mismatch();
    let bytes;
    try { bytes = await fsApi.readFile(checked); }
    catch { throw mismatch(); }
    const after = runtimeFileIdentity(await fsApi.lstat(checked, { bigint: true }));
    await assertContainedNoLinks({ root, child, platform }, safetyDeps);
    if (!sameRuntimeFileIdentity(before, after) || await deps.assertProtected(checked) !== true) throw mismatch();
    return parseRuntimeRecord(bytes, {
      platform,
      assertProtected: async () => true,
      canonicalize
    });
  };
  return {
    load,
    async write(record) {
      const checked = normalizeRuntime(record, platform);
      const bytes = Buffer.from(`${JSON.stringify(checked)}\n`, 'utf8');
      await replace({ root, child, bytes, mode: 0o600 }, { platform, fsApi });
      const observed = await load();
      if (!observed || JSON.stringify(observed) !== JSON.stringify(checked)) throw mismatch();
      return true;
    },
    async remove() {
      const safetyDeps = { lstat: fsApi.lstat.bind(fsApi), canonicalize: async (value) => fsApi.realpath(value) };
      const checked = await assertContainedNoLinks({ root, child, platform }, safetyDeps);
      let before;
      try { before = runtimeFileIdentity(await fsApi.lstat(checked, { bigint: true })); }
      catch (error) { if (error?.code === 'ENOENT') return false; throw mismatch(); }
      if (await deps.assertProtected(checked) !== true) throw mismatch();
      await assertContainedNoLinks({ root, child, platform }, safetyDeps);
      const after = runtimeFileIdentity(await fsApi.lstat(checked, { bigint: true }));
      if (!sameRuntimeFileIdentity(before, after) || await deps.assertProtected(checked) !== true) throw mismatch();
      await fsApi.rm(checked, { force: false });
      try { await fsApi.lstat(checked); throw mismatch(); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
      return true;
    }
  };
}
