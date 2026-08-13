import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import { ClaudexError } from './errors.js';
import { assertContainedNoLinks, assertRelativeManagedChild, resolveManagedChild } from './fs-safe.js';
import { atomicReplace } from './permissions.js';
import { Secret, isSecret } from './secrets.js';

export const MANIFEST_CHILD = 'manifest.json';
const SHA256 = /^[0-9a-f]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const VERIFIED = new WeakSet();

function safety(message) {
  return new ClaudexError('SAFETY_REFUSAL', message);
}

function exactKeys(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function pathApiFor(family) {
  return family === 'windows' ? path.win32 : path.posix;
}

function platformName(family) {
  return family === 'windows' ? 'win32' : 'posix';
}

function equivalentPath(left, right, family) {
  const pathApi = pathApiFor(family);
  const normalizedLeft = pathApi.normalize(left);
  const normalizedRight = pathApi.normalize(right);
  return family === 'windows'
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

function sortRecursively(value) {
  if (Array.isArray(value)) return value.map(sortRecursively);
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortRecursively(value[key])]));
}

function withoutHmac(manifest) {
  const { hmac: ignored, ...unsigned } = manifest;
  return unsigned;
}

export function canonicalManifestBytes(manifest) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) throw safety('Manifest must be an object.');
  return Buffer.from(JSON.stringify(sortRecursively(withoutHmac(manifest))), 'utf8');
}

function secretBytes(secret, label, callback) {
  if (!isSecret(secret)) throw safety(`${label} must be an opaque secret.`);
  return secret.withValue((bytes) => {
    if (bytes.length !== 32) throw safety(`${label} must contain 32 bytes.`);
    return callback(bytes);
  });
}

function equalSecretBytes(left, right) {
  return secretBytes(left, 'Bearer token', (leftBytes) => secretBytes(right, 'Manifest key', (rightBytes) => (
    crypto.timingSafeEqual(leftBytes, rightBytes)
  )));
}

export function createInstallationSecrets(randomBytes = crypto.randomBytes) {
  if (typeof randomBytes !== 'function') throw safety('A cryptographic random source is required.');
  const bearerBytes = Buffer.from(randomBytes(32));
  if (bearerBytes.length !== 32) throw safety('Bearer token generation returned an unsafe length.');
  const manifestBytes = Buffer.from(randomBytes(32));
  if (manifestBytes.length !== 32) throw safety('Manifest key generation returned an unsafe length.');
  if (crypto.timingSafeEqual(bearerBytes, manifestBytes)) {
    bearerBytes.fill(0);
    manifestBytes.fill(0);
    throw safety('Independent installation secret generation failed.');
  }
  const result = {
    bearerToken: Secret.fromBytes(bearerBytes),
    manifestKey: Secret.fromBytes(manifestBytes)
  };
  bearerBytes.fill(0);
  manifestBytes.fill(0);
  return result;
}

function assertInstallationSecrets(secrets) {
  if (!secrets || !exactKeys(secrets, ['bearerToken', 'manifestKey'])) {
    throw safety('Protected installation secrets are malformed.');
  }
  secretBytes(secrets.bearerToken, 'Bearer token', () => undefined);
  secretBytes(secrets.manifestKey, 'Manifest key', () => undefined);
  if (equalSecretBytes(secrets.bearerToken, secrets.manifestKey)) {
    throw safety('Protected installation secrets are not independent.');
  }
  return secrets;
}

export async function loadOrCreateInstallationSecrets({ readExisting, persistCreated }, {
  randomBytes = crypto.randomBytes
} = {}) {
  if (typeof readExisting !== 'function' || typeof persistCreated !== 'function') {
    throw safety('Protected secret storage is required.');
  }
  const existing = await readExisting();
  if (existing !== null && existing !== undefined) return assertInstallationSecrets(existing);
  const created = createInstallationSecrets(randomBytes);
  await persistCreated(created);
  return created;
}

export function deriveApprovalKey(manifestKey, { cryptoApi = crypto } = {}) {
  return secretBytes(manifestKey, 'Manifest key', (bytes) => Secret.fromBytes(
    cryptoApi.createHmac('sha256', bytes).update('claudexctl/approval/v1', 'utf8').digest()
  ));
}

function assertManifestShape(manifest) {
  if (!exactKeys(manifest, ['schemaVersion', 'installationId', 'platform', 'managedRoots', 'files', 'hmac'])
    || manifest.schemaVersion !== 1 || !UUID.test(manifest.installationId)
    || !exactKeys(manifest.platform, ['family', 'runtimeArch'])
    || !['windows', 'macos', 'linux'].includes(manifest.platform.family)
    || !['x64', 'arm64'].includes(manifest.platform.runtimeArch)
    || !exactKeys(manifest.managedRoots, ['managerRoot', 'stateRoot', 'userBinRoot', 'ownedPluginRoots'])
    || !Array.isArray(manifest.managedRoots.ownedPluginRoots)
    || manifest.managedRoots.ownedPluginRoots.length === 0
    || !Array.isArray(manifest.files)
    || typeof manifest.hmac !== 'string') {
    throw safety('Manifest schema is invalid.');
  }
  const family = manifest.platform.family;
  const pathApi = pathApiFor(family);
  for (const root of [
    manifest.managedRoots.managerRoot,
    manifest.managedRoots.stateRoot,
    manifest.managedRoots.userBinRoot,
    ...manifest.managedRoots.ownedPluginRoots
  ]) {
    if (typeof root !== 'string' || !pathApi.isAbsolute(root) || /[\0\r\n]/u.test(root)) {
      throw safety('Manifest root schema is invalid.');
    }
  }
  const seen = new Set();
  for (const record of manifest.files) {
    if (!exactKeys(record, ['relativePath', 'type', 'sha256'])
      || record.type !== 'file' || !SHA256.test(record.sha256)) {
      throw safety('Manifest file schema is invalid.');
    }
    assertRelativeManagedChild(record.relativePath, { platform: platformName(family) });
    const normalized = record.relativePath.replaceAll('\\', '/');
    if (/(^|\/)(auth|oauth|config)(\/|$)/iu.test(normalized) || /^config\.ya?ml$/iu.test(normalized)) {
      throw safety('Credential and configuration paths are not removable inventory.');
    }
    const identity = family === 'windows' ? normalized.toLowerCase() : normalized;
    if (seen.has(identity)) throw safety('Manifest contains duplicate file inventory.');
    seen.add(identity);
  }
}

function assertFixedRoots(manifest, fixedPaths) {
  if (!fixedPaths || !Array.isArray(fixedPaths.ownedPluginRoots)) throw safety('Fixed managed roots are required.');
  const roots = manifest.managedRoots;
  const family = manifest.platform.family;
  if (!equivalentPath(roots.managerRoot, fixedPaths.managerRoot, family)
    || !equivalentPath(roots.stateRoot, fixedPaths.stateRoot, family)
    || !equivalentPath(roots.userBinRoot, fixedPaths.userBinRoot, family)
    || roots.ownedPluginRoots.length !== fixedPaths.ownedPluginRoots.length
    || roots.ownedPluginRoots.some((root, index) => !equivalentPath(root, fixedPaths.ownedPluginRoots[index], family))) {
    throw safety('Manifest roots do not match the fixed platform roots.');
  }
}

function computeMac(manifest, manifestKey, cryptoApi) {
  return secretBytes(manifestKey, 'Manifest key', (bytes) => (
    (cryptoApi.createHmac ?? crypto.createHmac)('sha256', bytes).update(canonicalManifestBytes(manifest)).digest()
  ));
}

function decodeMac(value) {
  if (!BASE64URL.test(value)) throw safety('Manifest authentication failed.');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value) throw safety('Manifest authentication failed.');
  return bytes;
}

function freezeRecursively(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freezeRecursively(child);
    Object.freeze(value);
  }
  return value;
}

export function verifyManifest(manifest, manifestKey, { fixedPaths, cryptoApi = crypto } = {}) {
  assertManifestShape(manifest);
  const supplied = decodeMac(manifest.hmac);
  const expected = computeMac(manifest, manifestKey, cryptoApi);
  if (supplied.length !== expected.length || !cryptoApi.timingSafeEqual(supplied, expected)) {
    throw safety('Manifest authentication failed.');
  }
  assertFixedRoots(manifest, fixedPaths);
  freezeRecursively(manifest);
  VERIFIED.add(manifest);
  return manifest;
}

function signManifest(manifest, manifestKey, cryptoApi = crypto) {
  const candidate = { ...manifest, hmac: '' };
  assertManifestShape(candidate);
  const hmac = computeMac(candidate, manifestKey, cryptoApi).toString('base64url');
  return { ...manifest, hmac };
}

export async function writeManifest(manifest, manifestKey, paths, deps = {}) {
  if (typeof deps.assertLockHeld !== 'function') throw safety('Manifest mutation requires the installation lock.');
  await deps.assertLockHeld();
  const signed = signManifest(manifest, manifestKey, deps.cryptoApi ?? crypto);
  assertFixedRoots(signed, paths);
  const bytes = Buffer.from(`${JSON.stringify(sortRecursively(signed))}\n`, 'utf8');
  const replace = deps.atomicReplace ?? atomicReplace;
  await replace({ root: paths.stateRoot, child: MANIFEST_CHILD, bytes, mode: 0o600 }, deps.atomicDeps);
  freezeRecursively(signed);
  VERIFIED.add(signed);
  return signed;
}

export async function loadVerifiedManifest(paths, manifestKey, deps = {}) {
  const safetyDeps = { canonicalize: deps.canonicalize, lstat: deps.lstat };
  const inspect = deps.assertContainedNoLinks ?? assertContainedNoLinks;
  const request = { root: paths.stateRoot, child: MANIFEST_CHILD, platform: deps.platform ?? process.platform };
  const target = await inspect(request, safetyDeps);
  const bytes = await (deps.readFile ?? fs.readFile)(target);
  await inspect(request, safetyDeps);
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(bytes).toString('utf8'));
  } catch {
    throw safety('Manifest schema is invalid.');
  }
  return verifyManifest(parsed, manifestKey, { fixedPaths: paths, cryptoApi: deps.cryptoApi ?? crypto });
}

async function defaultInspectCandidate({ root, relativePath, platform }) {
  try {
    const safetyDeps = { canonicalize: async (value) => fs.realpath(value), lstat: fs.lstat };
    const checked = await assertContainedNoLinks({ root, child: relativePath, platform }, safetyDeps);
    const stats = await fs.lstat(checked);
    if (!stats.isFile()) return { exists: true, canonicalPath: checked, type: 'other' };
    const bytes = await fs.readFile(checked);
    await assertContainedNoLinks({ root, child: relativePath, platform }, safetyDeps);
    return {
      exists: true,
      canonicalPath: checked,
      type: 'file',
      sha256: crypto.createHash('sha256').update(bytes).digest('hex')
    };
  } catch (error) {
    if (error?.code === 'ENOENT') return { exists: false };
    throw error;
  }
}

export async function planOwnedRemoval(manifest, paths, {
  platform = process.platform,
  inspectCandidate = defaultInspectCandidate
} = {}) {
  if (!VERIFIED.has(manifest)) throw safety('Removal requires an authenticated manifest.');
  assertFixedRoots(manifest, paths);
  const family = manifest.platform.family;
  const filesystemPlatform = family === 'windows' ? 'win32' : 'posix';
  const plan = [];
  for (const file of manifest.files) {
    const target = resolveManagedChild(paths.managerRoot, file.relativePath, { platform: filesystemPlatform });
    const state = await inspectCandidate({
      root: paths.managerRoot,
      relativePath: file.relativePath,
      target,
      platform,
      expectedSha256: file.sha256
    });
    if (!state?.exists) {
      plan.push({ path: target, action: 'preserve', reason: 'missing' });
      continue;
    }
    if (state.type !== 'file' || !equivalentPath(state.canonicalPath, target, family)
      || state.sha256 !== file.sha256) {
      plan.push({ path: target, action: 'preserve', reason: 'modified' });
      continue;
    }
    plan.push({ path: target, action: 'remove', reason: 'unchanged' });
  }
  return plan;
}
