import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import { ClaudeyError } from './errors.js';
import { assertContainedNoLinks } from './fs-safe.js';

const noncePattern = /^[A-Za-z0-9_-]{43}$/;

function lockBusy(message = 'Another Claudey operation owns the installation lock.') {
  return new ClaudeyError('LOCK_BUSY', message);
}

function safetyRefusal(message) {
  return new ClaudeyError('SAFETY_REFUSAL', message);
}

function pathApiFor(platform) {
  return platform === 'win32' ? path.win32 : path.posix;
}

function validateOwner(owner) {
  if (!owner || !Number.isInteger(owner.pid) || owner.pid <= 0
    || !Number.isFinite(owner.processStartTime) || typeof owner.executableCanonicalPath !== 'string' || owner.executableCanonicalPath.length === 0) {
    throw safetyRefusal('Lock owner identity is invalid.');
  }
  return owner;
}

function validateRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== 'acquiredAt,kind,nonce,owner,schemaVersion'
    || value.schemaVersion !== 1 || value.kind !== 'installation-lock' || !noncePattern.test(value.nonce)
    || typeof value.acquiredAt !== 'string' || Number.isNaN(Date.parse(value.acquiredAt))) {
    return undefined;
  }
  try {
    validateOwner(value.owner);
  } catch {
    return undefined;
  }
  return value;
}

function makeRecord(owner, now) {
  return {
    schemaVersion: 1,
    kind: 'installation-lock',
    nonce: crypto.randomBytes(32).toString('base64url'),
    acquiredAt: now().toISOString(),
    owner: { ...owner }
  };
}

function missing(error) {
  return error?.code === 'ENOENT';
}

function defaultInspector() {
  return { exists: true, unknown: true };
}

async function isStale(record, { now, staleAfterMs, inspectOwner }) {
  const age = now().getTime() - Date.parse(record.acquiredAt);
  if (age < staleAfterMs || age < 0) return false;
  let inspected;
  try {
    inspected = await inspectOwner(record.owner.pid);
  } catch {
    return false;
  }
  if (!inspected || inspected.unknown === true) return false;
  if (inspected.exists === false) return true;
  if (inspected.exists !== true) return false;
  return inspected.startTime !== record.owner.processStartTime
    || inspected.executableCanonicalPath !== record.owner.executableCanonicalPath;
}

async function writeExclusive(lockPath, record, fsApi) {
  let handle;
  try {
    handle = await fsApi.open(lockPath, 'wx', 0o600);
    await handle.writeFile(JSON.stringify(record));
    await handle.sync();
    await handle.close();
    handle = undefined;
    await fsApi.chmod(lockPath, 0o600);
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function readRecord(lockPath, fsApi) {
  let parsed;
  try {
    parsed = JSON.parse(await fsApi.readFile(lockPath, 'utf8'));
  } catch {
    return undefined;
  }
  return validateRecord(parsed);
}

export async function openExclusive({
  root,
  child,
  owner,
  staleAfterMs = 5 * 60_000,
  now = () => new Date(),
  inspectOwner = defaultInspector,
  platform = process.platform
}, { fsApi = fs } = {}) {
  validateOwner(owner);
  if (!Number.isFinite(staleAfterMs) || staleAfterMs < 0) throw safetyRefusal('Lock stale timeout is invalid.');
  const safetyDeps = { lstat: fsApi.lstat, canonicalize: async (value) => fsApi.realpath(value) };
  const lockPath = await assertContainedNoLinks({ root, child, platform }, safetyDeps);
  const pathApi = pathApiFor(platform);
  const parent = pathApi.dirname(lockPath);
  await fsApi.mkdir(parent, { recursive: true, mode: 0o700 });
  await assertContainedNoLinks({ root, child, platform }, safetyDeps);
  const record = makeRecord(owner, now);

  try {
    await writeExclusive(lockPath, record, fsApi);
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
    await assertContainedNoLinks({ root, child, platform }, safetyDeps);
    const existing = await readRecord(lockPath, fsApi);
    if (!existing || !await isStale(existing, { now, staleAfterMs, inspectOwner })) throw lockBusy();

    const quarantineName = `.claudeyctl-stale-lock-${crypto.randomUUID()}`;
    const quarantinePath = pathApi.join(parent, quarantineName);
    const quarantineChild = pathApi.join(pathApi.relative(root, parent), quarantineName);
    await assertContainedNoLinks({ root, child, platform }, safetyDeps);
    await fsApi.rename(lockPath, quarantinePath);
    try {
      await assertContainedNoLinks({ root, child: quarantineChild, platform }, safetyDeps);
      await writeExclusive(lockPath, record, fsApi);
    } catch (recoveryError) {
      try {
        await assertContainedNoLinks({ root, child: quarantineChild, platform }, safetyDeps);
        await fsApi.rm(quarantinePath, { force: true });
      } catch {
        // Preserve any path whose identity cannot be re-established.
      }
      throw recoveryError.code === 'EEXIST' ? lockBusy() : recoveryError;
    }
    await assertContainedNoLinks({ root, child: quarantineChild, platform }, safetyDeps);
    await fsApi.rm(quarantinePath, { force: true });
  }

  let released = false;
  return {
    record,
    async release() {
      if (released) return;
      try {
        await assertContainedNoLinks({ root, child, platform }, safetyDeps);
        const current = await readRecord(lockPath, fsApi);
        if (!current || current.nonce !== record.nonce) throw safetyRefusal('Lock ownership changed before release.');
        await assertContainedNoLinks({ root, child, platform }, safetyDeps);
        const finalRecord = await readRecord(lockPath, fsApi);
        if (!finalRecord || finalRecord.nonce !== record.nonce) throw safetyRefusal('Lock ownership changed before release.');
        await fsApi.unlink(lockPath);
        released = true;
      } catch (error) {
        if (missing(error)) {
          released = true;
          return;
        }
        throw error;
      }
    }
  };
}

export const acquireInstallationLock = openExclusive;
