import { ClaudeyError } from '../core/errors.js';
import { isCursorExecutableBinding, revalidateCursorExecutableBinding } from './executable.js';

const MAX_OUTPUT_BYTES = 16_384;
const CALL_FAILED = Symbol('CALL_FAILED');
const CAPABILITIES = new WeakSet();
const CAPABILITY_BINDINGS = new WeakMap();

function unsupported(code = 'CAPABILITY_UNSUPPORTED') {
  return Object.freeze({ available: false, code });
}

function available(details = {}) {
  return Object.freeze({ available: true, code: 'AVAILABLE', ...details });
}

function failure() {
  return new ClaudeyError('CAPABILITY_UNSUPPORTED', 'Cursor Agent capabilities could not be verified.');
}

function exact(value, keys) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(','));
}

function jsonLine(value) {
  if (typeof value !== 'string' || !value.endsWith('\n') || value.indexOf('\n') !== value.length - 1) return null;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch { return null; }
}

function modelShape(value) {
  if (!exact(value, ['models']) || !Array.isArray(value.models) || value.models.length === 0) return false;
  const seen = new Set();
  return value.models.every((model) => exact(model, ['id']) && typeof model.id === 'string'
    && model.id.length > 0 && model.id.length <= 256 && !/[\u0000-\u001f\u007f]/u.test(model.id)
    && !seen.has(model.id) && (seen.add(model.id), true));
}

async function call(invoke, revalidateBinding, binding, args, stdin = null) {
  try {
    if (await revalidateCursorExecutableBinding(binding) !== true || await revalidateBinding(binding) !== true) return CALL_FAILED;
    const result = await invoke(Object.freeze({ binding, args: Object.freeze([...args]), stdin }));
    if (!result || result.code !== 0 || typeof result.stdout !== 'string' || typeof result.stderr !== 'string'
      || result.stderr !== '' || Buffer.byteLength(result.stdout, 'utf8') > MAX_OUTPUT_BYTES
      || Buffer.byteLength(result.stderr, 'utf8') > MAX_OUTPUT_BYTES) return CALL_FAILED;
    return result.stdout;
  } catch { return CALL_FAILED; }
}

function modeShape(name, value) {
  return exact(value, ['type', 'capability', 'supported']) && value.type === 'probe'
    && value.capability === name && value.supported === true;
}

function tool(capabilities, names) {
  for (const name of names) {
    if (!capabilities[name].available) {
      return unsupported(capabilities[name].code === 'AUTH_REQUIRED' ? 'AUTH_REQUIRED' : 'CAPABILITY_UNSUPPORTED');
    }
  }
  return available();
}

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

export async function probeCursorCapabilities(binding, { invoke, nonceFactory, revalidateBinding = async () => true } = {}) {
  if (!isCursorExecutableBinding(binding) || typeof invoke !== 'function' || typeof nonceFactory !== 'function'
    || typeof revalidateBinding !== 'function') throw failure();
  let nonce;
  try { nonce = nonceFactory(); } catch { throw failure(); }
  if (typeof nonce !== 'string' || nonce.length < 1 || nonce.length > 256 || /[\u0000-\u001f\u007f]/u.test(nonce)) throw failure();

  const versionOutput = await call(invoke, revalidateBinding, binding, ['--version']);
  const versionMatch = /^Cursor Agent ((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))\n$/u.exec(
    typeof versionOutput === 'string' ? versionOutput : ''
  );
  const identity = available();
  const version = versionMatch ? available({ version: versionMatch[1] }) : unsupported();
  const statusValue = jsonLine(await call(invoke, revalidateBinding, binding, ['status', '--json']));
  const status = exact(statusValue, ['authenticated']) && typeof statusValue.authenticated === 'boolean'
    ? statusValue.authenticated ? available() : unsupported('AUTH_REQUIRED')
    : unsupported();
  const primaryModels = await call(invoke, revalidateBinding, binding, ['models', '--json']);
  let modelsValue = jsonLine(primaryModels);
  if (primaryModels === CALL_FAILED) modelsValue = jsonLine(await call(invoke, revalidateBinding, binding, ['--list-models', '--json']));
  const models = modelShape(modelsValue) ? available() : unsupported();
  const jsonValue = jsonLine(await call(invoke, revalidateBinding, binding, ['probe', 'json', '--json']));
  const json = exact(jsonValue, ['type', 'capability', 'framing']) && jsonValue.type === 'probe'
    && jsonValue.capability === 'json' && jsonValue.framing === 'json-lines' ? available() : unsupported();
  const prompt = `nonce:${nonce}`;
  const stdinValue = jsonLine(await call(invoke, revalidateBinding, binding, ['probe', 'stdin', '--json'], prompt));
  const stdin = exact(stdinValue, ['type', 'capability', 'echo']) && stdinValue.type === 'probe'
    && stdinValue.capability === 'stdin' && stdinValue.echo === prompt ? available() : unsupported();
  const askValue = jsonLine(await call(invoke, revalidateBinding, binding, ['probe', 'mode', 'ask', '--json']));
  const planValue = jsonLine(await call(invoke, revalidateBinding, binding, ['probe', 'mode', 'plan', '--json']));
  const worktreeValue = jsonLine(await call(invoke, revalidateBinding, binding, ['probe', 'mode', 'worktree', '--json']));
  const sandboxValue = jsonLine(await call(invoke, revalidateBinding, binding, ['probe', 'sandbox', 'read-only', '--json']));
  const capabilities = {
    identity, version, status, models, json, stdin,
    ask: modeShape('ask', askValue) ? available() : unsupported(),
    plan: modeShape('plan', planValue) ? available() : unsupported(),
    worktree: modeShape('worktree', worktreeValue) ? available() : unsupported(),
    sandbox: modeShape('sandbox', sandboxValue) ? available() : unsupported()
  };
  const result = freeze({
    ...capabilities,
    tools: {
      models: tool(capabilities, ['identity', 'version', 'status', 'models']),
      ask: tool(capabilities, ['identity', 'version', 'status', 'models', 'json', 'stdin', 'ask', 'sandbox']),
      plan: tool(capabilities, ['identity', 'version', 'status', 'models', 'json', 'stdin', 'plan', 'sandbox']),
      worktree: tool(capabilities, ['identity', 'version', 'status', 'models', 'json', 'stdin', 'worktree'])
    }
  });
  CAPABILITIES.add(result);
  CAPABILITY_BINDINGS.set(result, binding);
  return result;
}

export function isCursorCapabilitySet(value) {
  return Boolean(value && typeof value === 'object' && CAPABILITIES.has(value));
}

export function cursorCapabilitiesMatchBinding(value, binding) {
  return isCursorCapabilitySet(value) && isCursorExecutableBinding(binding) && CAPABILITY_BINDINGS.get(value) === binding;
}
