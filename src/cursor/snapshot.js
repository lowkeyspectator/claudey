import path from 'node:path';

import { ClaudeyError } from '../core/errors.js';
import { createCursorRunScope } from './runner.js';
import { isRegisteredCursorRepository } from './registry.js';

const DEFAULT_LIMITS = Object.freeze({ maxRequestedPaths: 128, maxFiles: 5_000, maxBytes: 50 * 1024 * 1024, timeoutMs: 30_000 });
const SECRET_NAMES = new Set(['.env', '.npmrc', '.pypirc', '.netrc', 'id_rsa', 'id_ed25519', 'credentials', 'credentials.json', 'secrets.json']);
const SECRET_DIRECTORIES = new Set(['.ssh', '.aws', '.gnupg', '.azure']);

function safety() {
  return new ClaudeyError('SAFETY_REFUSAL', 'The Cursor source snapshot could not be created safely.');
}

function exact(value, keys) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(','));
}

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function checkedLimits(value) {
  const merged = value === undefined ? { ...DEFAULT_LIMITS } : value;
  if (!exact(merged, ['maxRequestedPaths', 'maxFiles', 'maxBytes', 'timeoutMs'])) throw safety();
  for (const [name, limit] of Object.entries(merged)) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > (name === 'maxBytes' ? 1_073_741_824 : name === 'timeoutMs' ? 600_000 : 100_000)) throw safety();
  }
  return freeze({ ...merged });
}

function checkedRelative(value, pathApi) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4_096 || value.includes('\0')
    || value.includes('\r') || value.includes('\n') || pathApi.isAbsolute(value)) throw safety();
  const normalized = pathApi.normalize(value);
  if (normalized !== value || normalized === '..' || normalized.startsWith(`..${pathApi.sep}`)) throw safety();
  const segments = normalized.split(pathApi.sep);
  const name = segments.at(-1).toLowerCase();
  if (segments.some((segment) => segment.toLowerCase() === '.git' || SECRET_DIRECTORIES.has(segment.toLowerCase()))
    || SECRET_NAMES.has(name) || name.startsWith('.env.') || /(?:\.pem|\.key|\.p12|\.pfx|\.kdbx)$/iu.test(name)
    || /(?:^|_)(?:rsa|ed25519)$/iu.test(name) || ['token.json', 'oauth.json'].includes(name)) throw safety();
  return normalized;
}

export function createCursorSnapshotService({
  platform, snapshotParent, limits, now = Date.now, inspectRepositoryRoot, enumerateFiles, inspectSource,
  createRoot, copyFile, revalidateSource, inspectCopied, revalidateRoot, cleanupRoot
} = {}) {
  const normalizedPlatform = platform === 'win32' || platform === 'windows' ? 'win32'
    : platform === 'linux' ? 'linux' : platform === 'darwin' || platform === 'macos' ? 'darwin' : null;
  const pathApi = normalizedPlatform === 'win32' ? path.win32 : path.posix;
  if (!normalizedPlatform || typeof now !== 'function') throw safety();
  const parent = typeof snapshotParent === 'string' ? pathApi.normalize(snapshotParent) : '';
  if (!parent || parent !== snapshotParent || !pathApi.isAbsolute(parent) || parent === pathApi.parse(parent).root) throw safety();
  const policy = checkedLimits(limits);
  const services = { inspectRepositoryRoot, enumerateFiles, inspectSource, createRoot, copyFile, revalidateSource, inspectCopied, revalidateRoot, cleanupRoot };
  if (Object.values(services).some((service) => typeof service !== 'function')) throw safety();

  return freeze({
    async withSnapshot(request, consumer) {
      let descriptor;
      let caught;
      let result;
      try {
        if (!request || typeof request !== 'object' || Array.isArray(request)
          || !['repository', 'paths,repository'].includes(Object.keys(request).sort().join(','))
          || !isRegisteredCursorRepository(request.repository) || typeof consumer !== 'function') throw safety();
        let requestedPaths;
        if (Object.hasOwn(request, 'paths')) {
          if (!Array.isArray(request.paths) || request.paths.length === 0 || request.paths.length > policy.maxRequestedPaths) throw safety();
          requestedPaths = request.paths.map((entry) => checkedRelative(entry, pathApi));
          if (new Set(requestedPaths).size !== requestedPaths.length) throw safety();
        }
        const started = now();
        const assertTime = () => {
          const current = now();
          if (!Number.isFinite(started) || !Number.isFinite(current) || current - started > policy.timeoutMs) throw safety();
        };
        const rootState = await inspectRepositoryRoot(request.repository.root);
        if (!exact(rootState, ['canonicalPath', 'dev', 'type', 'isLink', 'isJunction', 'isReparsePoint'])
          || rootState.canonicalPath !== request.repository.root || rootState.type !== 'directory'
          || rootState.isLink !== false || rootState.isJunction !== false || rootState.isReparsePoint !== false
          || !['string', 'number'].includes(typeof rootState.dev)) throw safety();
        const revalidateRepositoryRoot = async () => {
          const current = await inspectRepositoryRoot(request.repository.root);
          return exact(current, ['canonicalPath', 'dev', 'type', 'isLink', 'isJunction', 'isReparsePoint'])
            && current.canonicalPath === rootState.canonicalPath && `${current.dev}` === `${rootState.dev}`
            && current.type === 'directory' && current.isLink === false && current.isJunction === false
            && current.isReparsePoint === false;
        };
        assertTime();
        const enumerated = await enumerateFiles({
          root: request.repository.root, paths: requestedPaths, trackedOnly: requestedPaths === undefined
        });
        if (!Array.isArray(enumerated) || enumerated.length === 0 || enumerated.length > policy.maxFiles) throw safety();
        const files = enumerated.map((entry) => checkedRelative(entry, pathApi)).sort((left, right) => left.localeCompare(right));
        if (new Set(files).size !== files.length) throw safety();
        if (requestedPaths && files.some((file) => !requestedPaths.some((selected) => file === selected || file.startsWith(`${selected}${pathApi.sep}`)))) throw safety();
        const sourceStates = [];
        let totalBytes = 0;
        for (const relativePath of files) {
          assertTime();
          const state = await inspectSource({ root: request.repository.root, relativePath });
          if (!exact(state, ['exists', 'type', 'canonicalPath', 'size', 'isLink', 'isJunction', 'isReparsePoint', 'isDevice', 'sensitive', 'dev', 'ino', 'mtimeMs'])
            || state.exists !== true || state.type !== 'file' || state.isLink !== false || state.isJunction !== false
            || state.isReparsePoint !== false || state.isDevice !== false || state.sensitive !== false
            || !Number.isSafeInteger(state.size) || state.size < 0
            || `${state.dev}` !== `${rootState.dev}`
            || state.canonicalPath !== pathApi.join(request.repository.root, relativePath)) throw safety();
          totalBytes += state.size;
          if (!Number.isSafeInteger(totalBytes) || totalBytes > policy.maxBytes) throw safety();
          sourceStates.push(freeze({ ...state, relativePath }));
        }
        if (await revalidateRepositoryRoot() !== true) throw safety();
        const candidateRoot = await createRoot({ parent, repositoryRoot: request.repository.root, sourceDev: rootState.dev });
        if (!exact(candidateRoot, ['path', 'canonicalPath', 'dev', 'identity', 'owned', 'empty', 'private', 'isLink', 'isJunction', 'isReparsePoint'])
          || candidateRoot.path !== candidateRoot.canonicalPath || !pathApi.isAbsolute(candidateRoot.path)
          || candidateRoot.owned !== true || candidateRoot.empty !== true || candidateRoot.private !== true
          || candidateRoot.isLink !== false || candidateRoot.isJunction !== false || candidateRoot.isReparsePoint !== false
          || typeof candidateRoot.identity !== 'string' || candidateRoot.identity.length === 0
          || `${candidateRoot.dev}` !== `${rootState.dev}`) throw safety();
        const relativeRoot = pathApi.relative(parent, candidateRoot.path);
        if (!relativeRoot || relativeRoot === '..' || relativeRoot.startsWith(`..${pathApi.sep}`) || pathApi.isAbsolute(relativeRoot)) throw safety();
        descriptor = candidateRoot;
        for (const expected of sourceStates) {
          assertTime();
          if (await revalidateRepositoryRoot() !== true || await revalidateSource({ expected }) !== true
            || await revalidateRoot(descriptor) !== true) throw safety();
          const copied = await copyFile({ source: expected.canonicalPath, targetRoot: descriptor.path, relativePath: expected.relativePath });
          if (!exact(copied, ['size', 'sha256']) || copied.size !== expected.size || !/^[0-9a-f]{64}$/u.test(copied.sha256)) throw safety();
          if (await revalidateSource({ expected }) !== true || await revalidateRoot(descriptor) !== true) throw safety();
          const final = await inspectCopied({ root: descriptor.path, relativePath: expected.relativePath });
          if (!exact(final, ['exists', 'type', 'canonicalPath', 'size', 'sha256', 'isLink', 'isJunction', 'isReparsePoint'])
            || final.exists !== true || final.type !== 'file' || final.size !== copied.size || final.sha256 !== copied.sha256
            || final.canonicalPath !== pathApi.join(descriptor.path, expected.relativePath)
            || final.isLink !== false || final.isJunction !== false || final.isReparsePoint !== false) throw safety();
        }
        const scope = createCursorRunScope({ kind: 'snapshot', cwd: descriptor.path, platform: normalizedPlatform });
        result = await consumer(freeze({ scope, files: freeze([...files]), totalBytes }));
      } catch (error) {
        caught = error?.code === 'SAFETY_REFUSAL' ? error : safety();
      }
      if (descriptor) {
        try {
          if (await revalidateRoot(descriptor) !== true) throw safety();
          await cleanupRoot(descriptor);
        } catch { caught = safety(); }
      }
      if (caught) throw caught;
      return result;
    }
  });
}
