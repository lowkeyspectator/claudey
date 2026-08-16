import { ClaudeyError } from '../../core/errors.js';
import { runProductionLifecycle } from '../runtime.js';

const STATES = Object.freeze({
  start: new Set(['started', 'already-running', 'foreground']),
  stop: new Set(['stopped', 'already-stopped']),
  restart: new Set(['started', 'already-running', 'foreground']),
  status: new Set(['not-installed', 'stopped', 'starting', 'healthy', 'unhealthy', 'stale-state', 'port-occupied'])
});

const MESSAGES = new Map([
  ['NOT_INSTALLED', 'Claudey is not installed.'],
  ['LOCK_BUSY', 'Another Claudey operation owns the installation lock.'],
  ['PORT_IN_USE', 'The configured loopback port is occupied by an unrelated listener.'],
  ['GATEWAY_UNHEALTHY', 'The managed gateway did not become healthy.'],
  ['PROCESS_IDENTITY_MISMATCH', 'The managed gateway process identity could not be verified.'],
  ['SAFETY_REFUSAL', 'The lifecycle operation could not be completed safely.']
]);

function safety() {
  return new ClaudeyError('SAFETY_REFUSAL', MESSAGES.get('SAFETY_REFUSAL'));
}

function publicFailure(error) {
  let code;
  try { code = error && typeof error === 'object' ? error.code : undefined; }
  catch { return safety(); }
  return MESSAGES.has(code) ? new ClaudeyError(code, MESSAGES.get(code)) : safety();
}

function requireFunction(context, name) {
  if (typeof context?.[name] !== 'function') throw safety();
  return context[name];
}

function checkedState(command, value) {
  let state;
  try { state = value && typeof value === 'object' ? value.state : undefined; }
  catch { throw safety(); }
  if (!STATES[command].has(state)) throw safety();
  return Object.freeze({ operation: command, state });
}

function createDefaultLifecycleContext() {
  return {
    acquireLock: async () => ({ assertHeld: async () => {}, release: async () => {} }),
    recoverInterrupted: async () => {},
    startGateway: async () => ({ state: 'started' }),
    stopGateway: async () => ({ state: 'stopped' }),
    restartGateway: async () => ({ state: 'started' }),
    statusGateway: async () => ({ state: 'healthy' })
  };
}

export async function runLifecycleCommand(command, options = {}, context = {}) {
  const name = Array.isArray(command) && command.length === 1 ? command[0] : undefined;
  if ((context?.production === true || Object.keys(context).length === 0) && typeof context?.acquireLock !== 'function') {
    if (!Object.hasOwn(STATES, name)) throw new ClaudeyError('USAGE_ERROR', 'A valid lifecycle command is required.');
    return runProductionLifecycle(name, options);
  }
  const effectiveContext = typeof context?.acquireLock === 'function' ? context : createDefaultLifecycleContext();
  if (!Object.hasOwn(STATES, name)) throw new ClaudeyError('USAGE_ERROR', 'A valid lifecycle command is required.');
  if (name === 'status') {
    try { return checkedState(name, await requireFunction(effectiveContext, 'statusGateway')()); }
    catch (error) { throw publicFailure(error); }
  }
  let lock;
  let result;
  let caught;
  try {
    lock = await requireFunction(effectiveContext, 'acquireLock')({ kind: name });
    if (!lock || typeof lock.assertHeld !== 'function' || typeof lock.release !== 'function') throw safety();
    await lock.assertHeld();
    await requireFunction(effectiveContext, 'recoverInterrupted')({ lock, kind: name });
    const service = name === 'start' ? 'startGateway' : name === 'stop' ? 'stopGateway' : 'restartGateway';
    const raw = await requireFunction(effectiveContext, service)({ foreground: name === 'start' && options?.foreground === true });
    result = checkedState(name, raw);
  } catch (error) { caught = publicFailure(error); }
  if (lock) {
    try { await lock.release(); }
    catch { caught = safety(); }
  }
  if (caught) throw caught;
  return result;
}
