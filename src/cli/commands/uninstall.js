import path from 'node:path';

import { ClaudexError } from '../../core/errors.js';
import { planOwnedRemoval } from '../../core/manifest.js';

const OPTION_KEYS = new Set(['dryRun', 'purgeAuth', 'yes', 'nonInteractive']);
const ACTIONS = new Set(['remove', 'restore', 'preserve']);
const CATEGORIES = new Set(['managed-file', 'runtime', 'launcher', 'plugin', 'path', 'auth', 'unlisted', 'worktree']);
const MESSAGES = new Map([
  ['LOCK_BUSY', 'Another Claudex operation owns the installation lock.'],
  ['INTERACTION_REQUIRED', 'Explicit confirmation is required to remove authentication data.'],
  ['PROCESS_IDENTITY_MISMATCH', 'The managed gateway process identity could not be verified.'],
  ['SAFETY_REFUSAL', 'Uninstall could not be completed safely.']
]);

function error(code = 'SAFETY_REFUSAL') {
  return new ClaudexError(code, MESSAGES.get(code) ?? MESSAGES.get('SAFETY_REFUSAL'));
}

function publicFailure(value) {
  let code;
  try { code = value && typeof value === 'object' ? value.code : undefined; } catch { return error(); }
  return MESSAGES.has(code) ? error(code) : error();
}

function parseOptions(value) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw error();
    const keys = Object.keys(value);
    if (keys.some((key) => !OPTION_KEYS.has(key))) throw error();
    const parsed = {};
    for (const key of OPTION_KEYS) {
      const field = Object.hasOwn(value, key) ? value[key] : false;
      if (typeof field !== 'boolean') throw error();
      parsed[key] = field;
    }
    return Object.freeze(parsed);
  } catch (caught) {
    if (caught?.code === 'SAFETY_REFUSAL') throw caught;
    throw error();
  }
}

function service(context, name) {
  try {
    const candidate = context?.[name];
    if (typeof candidate !== 'function') throw error();
    return candidate;
  } catch { throw error(); }
}

function field(context, name) {
  try { return context?.[name]; } catch { throw error(); }
}

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function safePath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')
    || value.includes('\r') || value.includes('\n')) throw error();
  return value;
}

function platformFamily(manifest) {
  let family;
  try { family = manifest?.platform?.family; } catch { throw error(); }
  if (family === 'windows') return { family, pathApi: path.win32 };
  if (family === 'linux' || family === 'macos') return { family, pathApi: path.posix };
  throw error();
}

function fixedRoots(manifest, paths, pathApi, family) {
  let roots;
  try {
    const managed = manifest.managedRoots;
    roots = [managed.managerRoot, managed.stateRoot, managed.userBinRoot, ...managed.ownedPluginRoots];
    const expected = [paths.managerRoot, paths.stateRoot, paths.userBinRoot, ...paths.ownedPluginRoots];
    if (roots.length !== expected.length) throw error();
    for (let index = 0; index < roots.length; index += 1) {
      const left = pathApi.normalize(safePath(roots[index]));
      const right = pathApi.normalize(safePath(expected[index]));
      if ((family === 'windows' ? left.toLowerCase() : left) !== (family === 'windows' ? right.toLowerCase() : right)) throw error();
    }
  } catch (caught) {
    if (caught?.code === 'SAFETY_REFUSAL') throw caught;
    throw error();
  }
  return roots.map((root) => pathApi.normalize(root));
}

function withinOneRoot(target, roots, pathApi, family) {
  for (const root of roots) {
    const relative = pathApi.relative(root, target);
    const compare = family === 'windows' ? relative.toLowerCase() : relative;
    if (compare !== '' && compare !== '..' && !compare.startsWith(`..${pathApi.sep}`) && !pathApi.isAbsolute(relative)) return true;
  }
  return false;
}

function withinCategoryRoot(target, category, roots, pathApi, family) {
  const selected = category === 'plugin' ? roots.slice(3)
    : category === 'runtime' ? [roots[1]]
      : category === 'launcher' ? [roots[0], roots[2]]
        : [roots[0]];
  return withinOneRoot(target, selected, pathApi, family);
}

function normalizedPlan(raw, manifest, paths) {
  if (!Array.isArray(raw)) throw error();
  const { family, pathApi } = platformFamily(manifest);
  const roots = fixedRoots(manifest, paths, pathApi, family);
  const seenMutations = new Set();
  return raw.map((candidate) => {
    try {
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)
        || Object.keys(candidate).sort().join(',') !== 'action,category,path,reason') throw error();
      const target = safePath(candidate.path);
      if (!ACTIONS.has(candidate.action) || !CATEGORIES.has(candidate.category)
        || typeof candidate.reason !== 'string' || candidate.reason.length === 0 || candidate.reason.length > 80) throw error();
      if (!pathApi.isAbsolute(target) || pathApi.normalize(target) !== target) throw error();
      if (candidate.action === 'restore') {
        if (candidate.category !== 'path' || candidate.reason !== 'owned') throw error();
        const binRoot = pathApi.normalize(paths.userBinRoot);
        if ((family === 'windows' ? target.toLowerCase() : target) !== (family === 'windows' ? binRoot.toLowerCase() : binRoot)) throw error();
      } else if (candidate.action === 'remove') {
        const eligible = candidate.reason === 'unchanged' && ['managed-file', 'runtime', 'launcher'].includes(candidate.category)
          || candidate.reason === 'owned' && candidate.category === 'plugin';
        if (!eligible || !withinCategoryRoot(target, candidate.category, roots, pathApi, family)) throw error();
      }
      if (candidate.action !== 'preserve') {
        const identity = family === 'windows' ? target.toLowerCase() : target;
        if (seenMutations.has(identity)) throw error();
        seenMutations.add(identity);
      }
      return freeze({ path: target, action: candidate.action, reason: candidate.reason, category: candidate.category });
    } catch (caught) {
      if (caught?.code === 'SAFETY_REFUSAL') throw caught;
      throw error();
    }
  });
}

function samePath(left, right, pathApi, family) {
  const a = pathApi.normalize(safePath(left));
  const b = pathApi.normalize(safePath(right));
  return family === 'windows' ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function validateAuthInspection(inspection, paths, manifest) {
  const { family, pathApi } = platformFamily(manifest);
  const expected = pathApi.normalize(safePath(paths.authRoot));
  if (!pathApi.isAbsolute(expected) || expected === pathApi.parse(expected).root
    || samePath(expected, paths.homeRoot, pathApi, family)
    || samePath(expected, paths.repositoryRoot, pathApi, family)) throw error();
  if (!inspection || typeof inspection !== 'object') throw error();
  if (inspection.exists === false) return freeze({ exists: false, canonicalPath: expected });
  if (inspection.exists !== true || inspection.type !== 'directory'
    || inspection.isLink !== false || inspection.isJunction !== false || inspection.isReparsePoint !== false
    || !samePath(inspection.canonicalPath, expected, pathApi, family)) throw error();
  return freeze({ exists: true, canonicalPath: expected });
}

function noOp(dryRun) {
  return freeze({
    operation: 'uninstall', changed: false, dryRun, alreadyUninstalled: true,
    targets: [], preserved: [], auth: { action: 'preserved', reason: 'not-requested' }
  });
}

function integrationOutcome(value, expectedAction, allowedReasons) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== 'action,reason'
      || ![expectedAction, 'preserved'].includes(value.action)
      || typeof value.reason !== 'string' || !allowedReasons.has(value.reason)) throw error();
    return freeze({ action: value.action, reason: value.reason });
  } catch { throw error(); }
}

export async function runUninstallCommand(options = {}, context = {}) {
  const parsed = parseOptions(options);
  let lock;
  let result;
  let caught;
  try {
    lock = await service(context, 'acquireLock')({ kind: 'uninstall' });
    if (!lock || typeof lock.assertHeld !== 'function' || typeof lock.release !== 'function') throw error();
    await lock.assertHeld();
    if (!parsed.dryRun) await service(context, 'recoverInterrupted')({ lock, kind: 'uninstall' });
    const manifest = await service(context, 'loadAuthenticatedManifest')();
    if (manifest === null) {
      if (parsed.purgeAuth) throw error();
      result = noOp(parsed.dryRun);
    } else {
      const paths = field(context, 'paths');
      if (!paths || typeof paths !== 'object') throw error();
      const platform = platformFamily(manifest).family === 'windows' ? 'win32' : 'posix';
      const ownedTargets = await planOwnedRemoval(manifest, paths, {
        platform,
        inspectCandidate: service(context, 'inspectCandidate')
      });
      const supplementalTargets = await service(context, 'planRemoval')(manifest);
      const targets = normalizedPlan([
        ...ownedTargets.map((item) => ({ ...item, category: 'managed-file' })),
        ...supplementalTargets
      ], manifest, paths);
      const preserved = targets.filter((item) => item.action === 'preserve');
      let authInspection;
      if (parsed.purgeAuth) {
        if (!parsed.dryRun) {
          if (parsed.nonInteractive && !parsed.yes) throw error('INTERACTION_REQUIRED');
          if (!parsed.yes && await service(context, 'confirmPurgeAuth')({ path: paths.authRoot }) !== true) {
            throw error('INTERACTION_REQUIRED');
          }
        }
        authInspection = validateAuthInspection(await service(context, 'inspectAuthRoot')({ path: paths.authRoot }), paths, manifest);
      }
      if (parsed.dryRun) {
        result = freeze({
          operation: 'uninstall', changed: false, dryRun: true, alreadyUninstalled: false,
          targets, preserved,
          auth: parsed.purgeAuth
            ? { action: authInspection.exists ? 'remove' : 'preserve', reason: authInspection.exists ? 'requested' : 'missing' }
            : { action: 'preserved', reason: 'not-requested' }
        });
      } else {
        const transaction = await service(context, 'beginJournal')({ kind: 'uninstall', lock });
        if (!transaction || typeof transaction.checkpoint !== 'function'
          || typeof transaction.cleanup !== 'function' || typeof transaction.clear !== 'function') throw error();
        const gateway = await service(context, 'inspectOwnedGateway')();
        let stopped = false;
        if (gateway?.state === 'owned') {
          if ((typeof gateway.identity !== 'string' && (typeof gateway.identity !== 'object' || gateway.identity === null))
            || await service(context, 'recheckOwnedGateway')(gateway.identity) !== true) {
            throw error('PROCESS_IDENTITY_MISMATCH');
          }
          await service(context, 'stopOwnedGateway')({ identity: gateway.identity });
          stopped = true;
        } else if (gateway?.state !== 'stopped' && gateway?.state !== 'absent') throw error('PROCESS_IDENTITY_MISMATCH');
        await transaction.checkpoint('gateway-stopped');

        const removed = [];
        const executionPreserved = [...preserved];
        for (const item of targets) {
          if (item.action === 'preserve') continue;
          if (await service(context, 'revalidateRemovalTarget')(item) !== true) throw error();
          if (item.category === 'plugin') {
            const outcome = integrationOutcome(await service(context, 'removeOwnedPlugin')(item), 'removed',
              new Set(['owned', 'modified', 'missing', 'unknown-plugin', 'ownership-collision']));
            if (outcome.action === 'preserved') executionPreserved.push(freeze({ ...item, action: 'preserve', reason: outcome.reason }));
            else removed.push(item);
          } else if (item.category === 'path') {
            const outcome = integrationOutcome(await service(context, 'restoreOwnedPath')(item), 'restored',
              new Set(['owned-change', 'modified', 'missing', 'not-owned']));
            if (outcome.action === 'preserved') executionPreserved.push(freeze({ ...item, action: 'preserve', reason: outcome.reason }));
            else removed.push(item);
          } else {
            await service(context, 'removeOwnedTarget')(item);
            removed.push(item);
          }
        }
        await transaction.checkpoint('owned-files-removed');
        await transaction.checkpoint('integrations-restored');
        let auth = { action: 'preserved', reason: 'not-requested' };
        if (parsed.purgeAuth) {
          if (authInspection.exists) {
            if (await service(context, 'recheckAuthRoot')(authInspection) !== true) throw error();
            await service(context, 'purgeAuthRoot')({ path: authInspection.canonicalPath });
            auth = { action: 'removed', reason: 'requested' };
          } else auth = { action: 'preserved', reason: 'missing' };
        }
        await transaction.checkpoint('committed');
        await transaction.cleanup();
        await transaction.clear();
        result = freeze({
          operation: 'uninstall',
          changed: stopped || removed.length > 0 || auth.action === 'removed',
          dryRun: false, alreadyUninstalled: false, targets, preserved: executionPreserved, auth
        });
      }
    }
  } catch (failure) { caught = publicFailure(failure); }
  if (lock) {
    try { await lock.release(); } catch { caught = error(); }
  }
  if (caught) throw caught;
  return result;
}
