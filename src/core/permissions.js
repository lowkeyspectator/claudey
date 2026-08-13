import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import { ClaudexError } from './errors.js';
import { assertContainedNoLinks } from './fs-safe.js';
import { assertPosixProtection } from '../platform/posix.js';
import { assertWindowsDacl, runWindowsSecurityHelper } from '../platform/windows-helpers.js';

function safetyRefusal(message) {
  return new ClaudexError('SAFETY_REFUSAL', message);
}

function pathApiFor(platform) {
  return platform === 'win32' ? path.win32 : path.posix;
}

function relativeChild(root, target, platform) {
  return pathApiFor(platform).relative(root, target);
}

export async function assertProtected({ target, type, mode, platform = process.platform, currentUserSid }, deps = {}) {
  if (platform !== 'win32') return assertPosixProtection({ target, type, mode }, { lstat: deps.lstat });
  if (!currentUserSid) throw safetyRefusal('Windows protection verification requires the current user SID.');
  const response = await runWindowsSecurityHelper({
    request: {
      requestId: crypto.randomUUID(), operation: 'inspect', path: target, expectedType: type, currentUserSid
    }
  }, {
    spawn: deps.spawn,
    spawnChild: deps.spawnChild,
    fsApi: deps.fsApi
  });
  return assertWindowsDacl(response.result, { expectedType: type, currentUserSid });
}

export async function atomicReplace({ root, child, bytes, mode }, {
  platform = process.platform,
  fsApi = fs,
  beforeFinalRecheck
} = {}) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) throw safetyRefusal('Atomic replacement requires bytes.');
  if (!Number.isInteger(mode) || mode < 0 || mode > 0o777) throw safetyRefusal('Atomic replacement requires a safe mode.');

  const safetyDeps = { lstat: fsApi.lstat, canonicalize: async (value) => fsApi.realpath(value) };
  const target = await assertContainedNoLinks({ root, child, platform }, safetyDeps);
  const pathApi = pathApiFor(platform);
  const parent = pathApi.dirname(target);
  await fsApi.mkdir(parent, { recursive: true, mode: 0o700 });
  await assertContainedNoLinks({ root, child, platform }, safetyDeps);

  const temporaryName = `.claudexctl-${crypto.randomUUID()}.tmp`;
  const temporaryChild = pathApi.join(relativeChild(root, parent, platform), temporaryName);
  const temporary = pathApi.join(parent, temporaryName);
  let handle;
  let activated = false;
  try {
    handle = await fsApi.open(temporary, 'wx', mode);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await fsApi.chmod(temporary, mode);
    await beforeFinalRecheck?.({ root, child, target, temporary, temporaryChild });
    await assertContainedNoLinks({ root, child, platform }, safetyDeps);
    await assertContainedNoLinks({ root, child: temporaryChild, platform }, safetyDeps);
    await fsApi.rename(temporary, target);
    activated = true;
    return target;
  } finally {
    await handle?.close().catch(() => {});
    if (!activated) {
      try {
        const checkedTemporary = await assertContainedNoLinks({ root, child: temporaryChild, platform }, safetyDeps);
        if (checkedTemporary === temporary) await fsApi.rm(temporary, { force: true });
      } catch {
        // A changed path is intentionally retained rather than deleted through a swapped link.
      }
    }
  }
}
