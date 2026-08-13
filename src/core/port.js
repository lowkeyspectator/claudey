import { ClaudexError } from './errors.js';
import { verifyProcessIdentity } from './process.js';

function occupied() {
  return new ClaudexError('PORT_IN_USE', 'The configured loopback port is occupied by an unrelated listener.');
}

function exactKeys(value, keys) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key)));
}

function exactBinding(result, host, port) {
  if (!exactKeys(result, ['state', 'bindings']) || result.state !== 'listening'
    || !Array.isArray(result.bindings) || result.bindings.length !== 1) return null;
  const binding = result.bindings[0];
  if (!exactKeys(binding, ['host', 'port', 'pid', 'processStartTime'])
    || binding.host !== host || binding.port !== port || !Number.isSafeInteger(binding.pid) || binding.pid < 1
    || typeof binding.processStartTime !== 'string') return null;
  return binding;
}

function sameBinding(left, right) {
  return left && right && left.host === right.host && left.port === right.port
    && left.pid === right.pid && left.processStartTime === right.processStartTime;
}

export async function inspectPortOwnership({ host, port, runtimeRecord } = {}, { inspectListeners, processAdapter } = {}) {
  if (host !== '127.0.0.1' || !Number.isSafeInteger(port) || port < 1024 || port > 65535 || typeof inspectListeners !== 'function') throw occupied();
  let first;
  try { first = await inspectListeners({ host, port }); } catch { throw occupied(); }
  if (exactKeys(first, ['state']) && first.state === 'free') return Object.freeze({ state: 'free' });
  const initial = exactBinding(first, host, port);
  if (!initial || !runtimeRecord || initial.pid !== runtimeRecord.pid || initial.processStartTime !== runtimeRecord.processStartTime) throw occupied();
  let ownership;
  try { ownership = await verifyProcessIdentity(runtimeRecord, processAdapter); } catch { throw occupied(); }
  let second;
  try { second = exactBinding(await inspectListeners({ host, port }), host, port); } catch { throw occupied(); }
  if (!sameBinding(initial, second)) throw occupied();
  return Object.freeze({ state: 'owned', ownership });
}
