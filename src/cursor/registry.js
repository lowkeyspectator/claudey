import path from 'node:path';

import { ClaudeyError } from '../core/errors.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SCOPES = new Set(['local', 'user']);
const REGISTERED = new WeakSet();

function safety() {
  return new ClaudeyError('SAFETY_REFUSAL', 'The Cursor repository registry could not be used safely.');
}

function interaction() {
  return new ClaudeyError('INTERACTION_REQUIRED', 'Explicit confirmation is required to change this Cursor repository registration.');
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

function safePath(value, pathApi) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || value.includes('\r') || value.includes('\n')
    || !pathApi.isAbsolute(value) || pathApi.normalize(value) !== value) throw safety();
  return value;
}

function identity(value, family) {
  return family === 'windows' ? value.toLowerCase() : value;
}

function errorCode(error) {
  try { return error?.code; } catch { return undefined; }
}

export function createCursorRepositoryRegistry({
  platform, homeRoot, installationId, readRecord, writeRecord, inspectRepository
} = {}) {
  const family = platform === 'win32' || platform === 'windows' ? 'windows'
    : platform === 'linux' || platform === 'darwin' || platform === 'macos' ? 'posix' : null;
  const pathApi = family === 'windows' ? path.win32 : path.posix;
  if (!family || !UUID.test(installationId) || typeof readRecord !== 'function'
    || typeof writeRecord !== 'function' || typeof inspectRepository !== 'function') throw safety();
  const checkedHome = safePath(homeRoot, pathApi);

  const load = async () => {
    let record;
    try { record = await readRecord(); } catch { throw safety(); }
    if (!exact(record, ['schemaVersion', 'installationId', 'repositories']) || record.schemaVersion !== 1
      || record.installationId !== installationId || !Array.isArray(record.repositories) || record.repositories.length > 1_024) throw safety();
    const seen = new Set();
    const repositories = record.repositories.map((entry) => {
      if (!exact(entry, ['root', 'scope']) || !SCOPES.has(entry.scope)) throw safety();
      const root = safePath(entry.root, pathApi);
      if (root === pathApi.parse(root).root || identity(root, family) === identity(checkedHome, family)) throw safety();
      const key = identity(root, family);
      if (seen.has(key)) throw safety();
      seen.add(key);
      const registered = freeze({ root, scope: entry.scope });
      REGISTERED.add(registered);
      return registered;
    });
    return repositories;
  };

  const inspect = async (candidate) => {
    const requested = safePath(candidate, pathApi);
    let state;
    try { state = await inspectRepository(requested); } catch { throw safety(); }
    if (!exact(state, ['exists', 'type', 'canonicalPath', 'gitRoot', 'isLink', 'isJunction', 'isReparsePoint', 'isBare', 'owner'])
      || state.exists !== true || state.type !== 'directory' || state.isLink !== false || state.isJunction !== false
      || state.isReparsePoint !== false || state.isBare !== false || state.owner !== 'current'
      || typeof state.gitRoot !== 'string') throw safety();
    const canonical = safePath(state.canonicalPath, pathApi);
    const root = safePath(state.gitRoot, pathApi);
    const relative = pathApi.relative(root, canonical);
    if (relative === '..' || relative.startsWith(`..${pathApi.sep}`) || pathApi.isAbsolute(relative)
      || root === pathApi.parse(root).root || identity(root, family) === identity(checkedHome, family)) throw safety();
    return root;
  };

  const persist = async (repositories) => {
    try { await writeRecord(freeze({ schemaVersion: 1, installationId, repositories: repositories.map(({ root, scope }) => ({ root, scope })) })); }
    catch { throw safety(); }
  };

  return freeze({
    async list() { return freeze([...(await load())]); },
    async add(input) {
      try {
        if (!exact(input, ['path', 'scope', 'currentProject', 'confirmed']) || !SCOPES.has(input.scope)
          || typeof input.confirmed !== 'boolean') throw safety();
        const currentProject = safePath(input.currentProject, pathApi);
        const root = await inspect(input.path);
        const localExemption = input.scope === 'local' && identity(root, family) === identity(currentProject, family);
        if (!localExemption && !input.confirmed) throw interaction();
        const entries = await load();
        const existing = entries.find((entry) => identity(entry.root, family) === identity(root, family));
        if (existing) return freeze({ action: 'preserved', reason: 'already-registered', root: existing.root, scope: existing.scope });
        const next = [...entries, freeze({ root, scope: input.scope })].sort((left, right) => identity(left.root, family).localeCompare(identity(right.root, family)));
        await persist(next);
        return freeze({ action: 'added', root, scope: input.scope });
      } catch (error) {
        if (errorCode(error) === 'INTERACTION_REQUIRED') throw error;
        throw safety();
      }
    },
    async remove(input) {
      try {
        if (!exact(input, ['path', 'confirmed']) || typeof input.confirmed !== 'boolean') throw safety();
        const entries = await load();
        const requested = safePath(input.path, pathApi);
        const direct = entries.find((entry) => identity(entry.root, family) === identity(requested, family));
        let root = direct?.root;
        if (!root) {
          try { root = await inspect(requested); }
          catch { return freeze({ action: 'preserved', reason: 'not-registered', root: requested }); }
        }
        const index = entries.findIndex((entry) => identity(entry.root, family) === identity(root, family));
        if (index < 0) return freeze({ action: 'preserved', reason: 'not-registered', root });
        if (!input.confirmed) throw interaction();
        await persist(entries.filter((_, candidate) => candidate !== index));
        return freeze({ action: 'removed', root: entries[index].root });
      } catch (error) {
        if (errorCode(error) === 'INTERACTION_REQUIRED') throw error;
        throw safety();
      }
    }
  });
}

export function isRegisteredCursorRepository(value) {
  return Boolean(value && typeof value === 'object' && REGISTERED.has(value));
}
