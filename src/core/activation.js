import { ClaudeyError } from './errors.js';
import { assertRelativeManagedChild } from './fs-safe.js';
import { isSecret } from './secrets.js';

const SHA256 = /^[0-9a-f]{64}$/u;
const VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const MAX_RETAINED_RELEASES = 64;
const OPTION_KEYS = new Set([
  'version', 'port', 'yes', 'withCursor', 'noStart', 'noPath', 'check',
  'json', 'noColor', 'verbose', 'nonInteractive'
]);
const PUBLIC_MESSAGES = new Map([
  ['USAGE_ERROR', 'The requested gateway operation is invalid.'],
  ['PLATFORM_UNSUPPORTED', 'This platform is not supported.'],
  ['PREREQUISITE_MISSING', 'A required verified prerequisite is unavailable.'],
  ['CAPABILITY_UNSUPPORTED', 'The installed upstream version lacks a required capability.'],
  ['NOT_INSTALLED', 'Claudey is not installed.'],
  ['NETWORK_FAILURE', 'The verified release could not be downloaded.'],
  ['CHECKSUM_MISMATCH', 'The downloaded release failed checksum verification.'],
  ['ARCHIVE_UNSAFE', 'The downloaded release archive is unsafe.'],
  ['LOCK_BUSY', 'Another Claudey operation owns the installation lock.'],
  ['PORT_IN_USE', 'The configured loopback port is occupied by an unrelated listener.'],
  ['GATEWAY_UNHEALTHY', 'The managed gateway did not become healthy.'],
  ['PROCESS_IDENTITY_MISMATCH', 'The managed gateway process identity could not be verified.'],
  ['CONFIG_MODIFIED', 'The managed configuration was modified outside Claudey.'],
  ['SAFETY_REFUSAL', 'The gateway transaction could not be completed safely.'],
  ['ROLLBACK_UNAVAILABLE', 'No verified rollback release is available.']
]);

function failure(code, message, options) {
  return new ClaudeyError(code, message, options);
}

function safety() {
  return failure('SAFETY_REFUSAL', PUBLIC_MESSAGES.get('SAFETY_REFUSAL'));
}

function publicFailure(error) {
  let code;
  try { code = error && typeof error === 'object' ? error.code : undefined; }
  catch { return safety(); }
  return PUBLIC_MESSAGES.has(code) ? failure(code, PUBLIC_MESSAGES.get(code)) : safety();
}

function requireFunction(context, name) {
  let value;
  try { value = context?.[name]; } catch { throw safety(); }
  if (typeof value !== 'function') throw safety();
  return value;
}

function closedRecord(value, variants) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) throw safety();
    const keys = Object.keys(value).sort();
    const allowed = variants.find((candidate) => candidate.length === keys.length
      && [...candidate].sort().every((key, index) => key === keys[index]));
    if (!allowed) throw safety();
    return Object.fromEntries(keys.map((key) => [key, value[key]]));
  } catch { throw safety(); }
}

function activationPlatform(options) {
  if (options === undefined) return process.platform;
  const value = closedRecord(options, [['platform']]);
  if (!['win32', 'linux', 'darwin'].includes(value.platform)) throw safety();
  return value.platform;
}

function pathPlatform(platform) {
  return platform === 'win32' ? 'win32' : 'posix';
}

function releaseIdentity(release, platform) {
  const value = closedRecord(release, [['version', 'relativePath', 'sha256']]);
  if (!VERSION.test(value.version) || !SHA256.test(value.sha256)) throw safety();
  try { assertRelativeManagedChild(value.relativePath, { platform: pathPlatform(platform) }); }
  catch { throw safety(); }
  const expectedPath = `releases/${value.version}/${platform === 'win32' ? 'CLIProxyAPI.exe' : 'CLIProxyAPI'}`;
  if (value.relativePath !== expectedPath) throw safety();
  return Object.freeze({ version: value.version, relativePath: value.relativePath, sha256: value.sha256 });
}

function sameRelease(left, right, platform) {
  if (!left || !right) return left === right;
  const pathEqual = platform === 'win32'
    ? left.relativePath.toLowerCase() === right.relativePath.toLowerCase()
    : left.relativePath === right.relativePath;
  return left.version === right.version && left.sha256 === right.sha256 && pathEqual;
}

export function createActivationState(value = {}, options) {
  const platform = activationPlatform(options);
  const record = closedRecord(value, [
    ['active', 'rollback', 'retained'],
    ['schemaVersion', 'active', 'rollback', 'retained']
  ]);
  let retainedValues;
  try {
    if (record.schemaVersion !== undefined && record.schemaVersion !== 1
      || !Array.isArray(record.retained) || Object.getPrototypeOf(record.retained) !== Array.prototype
      || record.retained.length > MAX_RETAINED_RELEASES) throw safety();
    retainedValues = Array.from(record.retained);
  } catch { throw safety(); }
  const active = record.active === null ? null : releaseIdentity(record.active, platform);
  const rollback = record.rollback === null ? null : releaseIdentity(record.rollback, platform);
  const retained = retainedValues.map((item) => releaseIdentity(item, platform));
  const identities = new Set();
  const versions = new Set();
  for (const release of retained) {
    const key = platform === 'win32' ? release.relativePath.toLowerCase() : release.relativePath;
    if (identities.has(key) || versions.has(release.version)) throw safety();
    identities.add(key);
    versions.add(release.version);
  }
  if (active && !retained.some((item) => sameRelease(item, active, platform))) throw safety();
  if (rollback && !retained.some((item) => sameRelease(item, rollback, platform))) throw safety();
  return Object.freeze({ schemaVersion: 1, active, rollback, retained: Object.freeze(retained) });
}

export function planActivation(current, candidate, options) {
  const platform = activationPlatform(options);
  const state = createActivationState(current, { platform });
  const next = releaseIdentity(candidate, platform);
  if (sameRelease(state.active, next, platform)) return Object.freeze({ changed: false, state });
  const retained = [...state.retained];
  if (!retained.some((item) => sameRelease(item, next, platform))) retained.push(next);
  const planned = createActivationState({ active: next, rollback: state.active, retained }, { platform });
  return Object.freeze({ changed: true, state: planned });
}

export function planRollback(current, requestedVersion, options) {
  const platform = activationPlatform(options);
  const state = createActivationState(current, { platform });
  if (requestedVersion !== undefined && (typeof requestedVersion !== 'string' || !VERSION.test(requestedVersion))) {
    throw failure('USAGE_ERROR', PUBLIC_MESSAGES.get('USAGE_ERROR'));
  }
  const target = requestedVersion === undefined
    ? state.rollback
    : state.retained.find((item) => item.version === requestedVersion);
  if (!target) throw failure('ROLLBACK_UNAVAILABLE', PUBLIC_MESSAGES.get('ROLLBACK_UNAVAILABLE'));
  if (sameRelease(state.active, target, platform)) return Object.freeze({ changed: false, target, state });
  const planned = createActivationState({ active: target, rollback: null, retained: [...state.retained] }, { platform });
  return Object.freeze({ changed: true, target, state: planned });
}

function checkedPreflight(value) {
  const record = closedRecord(value, [['platform', 'priorRunning', 'port', 'activation']]);
  if (!['win32', 'linux', 'darwin'].includes(record.platform)
    || typeof record.priorRunning !== 'boolean' || !Number.isSafeInteger(record.port)
    || record.port < 1024 || record.port > 65535) throw safety();
  return Object.freeze({ ...record, activation: createActivationState(record.activation, { platform: record.platform }) });
}

function checkedTransaction(value) {
  if (!value || typeof value !== 'object' || typeof value.checkpoint !== 'function'
    || typeof value.cleanup !== 'function' || typeof value.clear !== 'function') throw safety();
  return value;
}

function checkedInstallation(value) {
  const record = closedRecord(value, [['installationId', 'bearerToken', 'manifestKey']]);
  if (!UUID.test(record.installationId) || !isSecret(record.bearerToken) || !isSecret(record.manifestKey)) throw safety();
  return Object.freeze(record);
}

function checkedOptions(options) {
  if (options === undefined || options === null) return Object.freeze({});
  let keys;
  let record;
  try {
    if (typeof options !== 'object' || Array.isArray(options) || Object.getPrototypeOf(options) !== Object.prototype) throw safety();
    keys = Object.keys(options);
    if (keys.some((key) => !OPTION_KEYS.has(key))) throw safety();
    record = Object.fromEntries(keys.map((key) => [key, options[key]]));
  } catch { throw safety(); }
  const port = record.port;
  if (port !== undefined && (!Number.isSafeInteger(port) || port < 1024 || port > 65535)) throw publicFailure({ code: 'USAGE_ERROR' });
  if (record.version !== undefined && (typeof record.version !== 'string' || !VERSION.test(record.version))) throw publicFailure({ code: 'USAGE_ERROR' });
  for (const key of keys) {
    if (key !== 'port' && key !== 'version' && typeof record[key] !== 'boolean') throw safety();
  }
  return Object.freeze(record);
}

async function checkpoint(transaction, phase) {
  await transaction.checkpoint(phase);
  return phase;
}

export async function runGatewayInstallation({ kind, options, setup = false, update = false } = {}, context = {}) {
  if (!['install', 'setup', 'update'].includes(kind) || typeof setup !== 'boolean' || typeof update !== 'boolean') throw safety();
  const input = checkedOptions(options);
  const acquireLock = requireFunction(context, 'acquireLock');
  let lock;
  let preflight;
  let transaction;
  let transactionKind = kind;
  let stage = 'lock';
  let committed = false;
  let result;
  let caught;
  try {
    lock = await acquireLock({ kind });
    if (!lock || typeof lock.assertHeld !== 'function' || typeof lock.release !== 'function') throw safety();
    await lock.assertHeld();
    await requireFunction(context, 'recoverInterrupted')({ lock, kind });
    preflight = checkedPreflight(await requireFunction(context, 'preflight')({ kind, options: input, lock }));
    transactionKind = kind === 'setup' ? (preflight.activation.active ? 'update' : 'install') : kind;
    transaction = checkedTransaction(await requireFunction(context, 'beginJournal')({ kind: transactionKind, operation: kind, preflight, lock }));
    const release = await requireFunction(context, 'resolveRelease')({ requestedVersion: input.version, platform: preflight.platform });
    stage = 'download';
    const download = await requireFunction(context, 'downloadVerifiedRelease')({ release, preflight });
    stage = 'extraction';
    const extracted = await requireFunction(context, 'extractVerifiedRelease')({ download, release, preflight });
    let candidate;
    let installation;
    let config;
    let launchers;
    let activation;
    let materialChange;
    const port = input.port ?? preflight.port;
    await requireFunction(context, 'withCandidate')(extracted, async (scope) => {
      if (!scope || typeof scope !== 'object' || !Object.isFrozen(scope) || typeof scope.read !== 'function') throw safety();
      stage = 'candidate-probe';
      candidate = releaseIdentity(await requireFunction(context, 'probeCandidate')({ scope, extracted, release, preflight }), preflight.platform);
      let resolvedVersion;
      try { resolvedVersion = release?.version; } catch { throw safety(); }
      if (!VERSION.test(resolvedVersion) || candidate.version !== resolvedVersion
        || input.version !== undefined && candidate.version !== input.version) throw safety();
      await checkpoint(transaction, 'release-staged');
      installation = checkedInstallation(await requireFunction(context, 'loadOrCreateInstallation')({ preflight, candidate }));
      stage = 'config-stage';
      config = await requireFunction(context, 'stageConfig')({ port, candidate, installation, preflight });
      if (!config || typeof config !== 'object') throw safety();
      stage = 'launcher-stage';
      launchers = await requireFunction(context, 'stageLaunchers')({ candidate, installation, preflight });
      if (!launchers || typeof launchers !== 'object') throw safety();
      await checkpoint(transaction, 'config-staged');
      activation = planActivation(preflight.activation, candidate, { platform: preflight.platform });
      materialChange = activation.changed || config.changed === true || launchers.changed === true;
      if (materialChange) {
        stage = 'candidate-revalidation';
        if (await requireFunction(context, 'revalidateCandidate')({ scope, candidate, extracted, preflight }) !== true) throw safety();
      }
      if (materialChange && preflight.priorRunning) await requireFunction(context, 'stopPrior')({ preflight, candidate });
      stage = 'activation';
      if (activation.changed) await requireFunction(context, 'writeActivation')(activation.state, { scope, preflight, candidate });
      await checkpoint(transaction, 'activated');
    });
    let setupChanged = false;
    if (setup && input.noPath !== true) {
      const intent = await requireFunction(context, 'stagePathIntent')({ preflight, candidate });
      if (!intent || typeof intent !== 'object' || typeof intent.changed !== 'boolean') throw safety();
      setupChanged ||= intent.changed;
    }
    if (setup && input.withCursor === true) {
      const intent = await requireFunction(context, 'stagePluginIntent')({ preflight, candidate });
      if (!intent || typeof intent !== 'object' || typeof intent.changed !== 'boolean') throw safety();
      setupChanged ||= intent.changed;
    }
    const shouldStart = setup
      ? input.noStart !== true && (!preflight.priorRunning || materialChange)
      : preflight.priorRunning && materialChange;
    stage = 'spawn';
    if (shouldStart) await requireFunction(context, 'startCandidate')({ preflight, candidate, port, installation });
    await checkpoint(transaction, 'candidate-started');
    stage = 'readiness';
    if (shouldStart) await requireFunction(context, 'authenticateReadiness')({ preflight, candidate, port, installation });
    stage = 'ready-checkpoint';
    await checkpoint(transaction, 'ready');
    stage = 'manifest';
    await requireFunction(context, 'commitManifest')({ kind: transactionKind, operation: kind, preflight, candidate, activation: activation.state, config, launchers, installation });
    await checkpoint(transaction, 'committed');
    committed = true;
    await transaction.cleanup();
    await transaction.clear();
    const running = shouldStart || (!materialChange && preflight.priorRunning);
    result = Object.freeze({ operation: kind, version: candidate.version, port, running, changed: materialChange || setupChanged });
  } catch (error) {
    if (preflight && !committed) {
      try {
        await requireFunction(context, 'rollbackTransaction')({ kind: transactionKind, operation: kind, preflight, transaction, stage });
      } catch { caught = safety(); }
    }
    if (!caught) {
      caught = (update || transactionKind === 'update') && stage === 'readiness'
        ? failure('UPDATE_ROLLED_BACK', 'The candidate gateway failed readiness and the prior installation was restored.')
        : publicFailure(error);
    }
  }
  if (lock) {
    try { await lock.release(); }
    catch { caught = safety(); }
  }
  if (caught) throw caught;
  return result;
}

export async function runGatewayRollback(options = {}, context = {}) {
  const input = checkedOptions(options);
  const acquireLock = requireFunction(context, 'acquireLock');
  let lock;
  let preflight;
  let transaction;
  let committed = false;
  let result;
  let caught;
  try {
    lock = await acquireLock({ kind: 'rollback' });
    if (!lock || typeof lock.assertHeld !== 'function' || typeof lock.release !== 'function') throw safety();
    await lock.assertHeld();
    await requireFunction(context, 'recoverInterrupted')({ lock, kind: 'rollback' });
    preflight = checkedPreflight(await requireFunction(context, 'preflight')({ kind: 'rollback', options: input, lock }));
    const plan = planRollback(preflight.activation, input.version, { platform: preflight.platform });
    if (!plan.changed) {
      result = Object.freeze({ operation: 'rollback', version: plan.target.version, port: preflight.port, running: preflight.priorRunning, changed: false });
    } else {
      transaction = checkedTransaction(await requireFunction(context, 'beginJournal')({ kind: 'rollback', preflight, lock, candidate: plan.target }));
      const candidate = releaseIdentity(await requireFunction(context, 'revalidateRetainedRelease')({ target: plan.target, preflight }), preflight.platform);
      if (!sameRelease(candidate, plan.target, preflight.platform)) throw safety();
      await checkpoint(transaction, 'release-staged');
      await checkpoint(transaction, 'config-staged');
      if (preflight.priorRunning) await requireFunction(context, 'stopPrior')({ preflight, candidate });
      await requireFunction(context, 'writeActivation')(plan.state, { preflight, candidate });
      await checkpoint(transaction, 'activated');
      if (preflight.priorRunning) await requireFunction(context, 'startCandidate')({ preflight, candidate, port: preflight.port });
      await checkpoint(transaction, 'candidate-started');
      if (preflight.priorRunning) await requireFunction(context, 'authenticateReadiness')({ preflight, candidate, port: preflight.port });
      await checkpoint(transaction, 'ready');
      await requireFunction(context, 'commitManifest')({ kind: 'rollback', preflight, candidate, activation: plan.state });
      await checkpoint(transaction, 'committed');
      committed = true;
      await transaction.cleanup();
      await transaction.clear();
      result = Object.freeze({ operation: 'rollback', version: candidate.version, port: preflight.port, running: preflight.priorRunning, changed: true });
    }
  } catch (error) {
    if (preflight && transaction && !committed) {
      try { await requireFunction(context, 'rollbackTransaction')({ kind: 'rollback', preflight, transaction }); }
      catch { caught = safety(); }
    }
    if (!caught) caught = publicFailure(error);
  }
  if (lock) {
    try { await lock.release(); }
    catch { caught = safety(); }
  }
  if (caught) throw caught;
  return result;
}

export async function checkGatewayUpdate(options = {}, context = {}) {
  const input = checkedOptions(options);
  let value;
  try { value = await requireFunction(context, 'checkForUpdate')({ requestedVersion: input.version }); }
  catch (error) { throw publicFailure(error); }
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== 'availableVersion,currentVersion,updateAvailable'
      || !VERSION.test(value.currentVersion) || !VERSION.test(value.availableVersion)
      || typeof value.updateAvailable !== 'boolean') throw safety();
    return Object.freeze({ operation: 'update-check', currentVersion: value.currentVersion, availableVersion: value.availableVersion, updateAvailable: value.updateAvailable });
  } catch (error) { throw publicFailure(error); }
}

export async function runGatewayPortChange(options = {}, context = {}) {
  const input = checkedOptions(options);
  if (input.port === undefined) throw failure('USAGE_ERROR', PUBLIC_MESSAGES.get('USAGE_ERROR'));
  const acquireLock = requireFunction(context, 'acquireLock');
  let lock;
  let preflight;
  let transaction;
  let committed = false;
  let result;
  let caught;
  try {
    lock = await acquireLock({ kind: 'config' });
    if (!lock || typeof lock.assertHeld !== 'function' || typeof lock.release !== 'function') throw safety();
    await lock.assertHeld();
    await requireFunction(context, 'recoverInterrupted')({ lock, kind: 'config' });
    preflight = checkedPreflight(await requireFunction(context, 'preflight')({ kind: 'config', options: input, lock }));
    if (preflight.port === input.port) {
      result = Object.freeze({ operation: 'config-port', port: input.port, running: preflight.priorRunning, changed: false });
    } else {
      const inspected = await requireFunction(context, 'inspectPort')({ host: '127.0.0.1', port: input.port });
      if (!inspected || typeof inspected !== 'object' || Object.keys(inspected).length !== 1 || inspected.state !== 'free') {
        throw failure('PORT_IN_USE', PUBLIC_MESSAGES.get('PORT_IN_USE'));
      }
      transaction = checkedTransaction(await requireFunction(context, 'beginJournal')({ kind: 'config', preflight, lock }));
      await checkpoint(transaction, 'release-staged');
      const config = await requireFunction(context, 'stageConfig')({ port: input.port, preflight });
      await checkpoint(transaction, 'config-staged');
      if (preflight.priorRunning) await requireFunction(context, 'stopPrior')({ preflight });
      await requireFunction(context, 'activateConfig')({ port: input.port, config, preflight });
      await checkpoint(transaction, 'activated');
      if (preflight.priorRunning) await requireFunction(context, 'startCandidate')({ preflight, port: input.port });
      await checkpoint(transaction, 'candidate-started');
      if (preflight.priorRunning) await requireFunction(context, 'authenticateReadiness')({ preflight, port: input.port });
      await checkpoint(transaction, 'ready');
      await requireFunction(context, 'commitManifest')({ kind: 'config', preflight, port: input.port, config });
      await checkpoint(transaction, 'committed');
      committed = true;
      await transaction.cleanup();
      await transaction.clear();
      result = Object.freeze({ operation: 'config-port', port: input.port, running: preflight.priorRunning, changed: true });
    }
  } catch (error) {
    if (preflight && transaction && !committed) {
      try { await requireFunction(context, 'rollbackTransaction')({ kind: 'config', preflight, transaction }); }
      catch { caught = safety(); }
    }
    if (!caught) caught = publicFailure(error);
  }
  if (lock) {
    try { await lock.release(); }
    catch { caught = safety(); }
  }
  if (caught) throw caught;
  return result;
}
