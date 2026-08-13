import { ClaudexError } from '../core/errors.js';
import { isRegisteredCursorRepository } from './registry.js';

const FINGERPRINT_KEYS = ['branch', 'files', 'head', 'index', 'refs', 'untracked'];
const PUBLIC_CODES = new Set(['SAFETY_REFUSAL', 'CAPABILITY_UNSUPPORTED', 'AUTH_REQUIRED', 'MODEL_NOT_FOUND']);

function safety() {
  return new ClaudexError('SAFETY_REFUSAL', 'The Cursor read-only delegation could not be completed safely.');
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

function fingerprint(value) {
  if (!exact(value, FINGERPRINT_KEYS) || FINGERPRINT_KEYS.some((key) => typeof value[key] !== 'string'
    || value[key].length === 0 || value[key].length > 16_384 || value[key].includes('\0'))) throw safety();
  return freeze(Object.fromEntries(FINGERPRINT_KEYS.map((key) => [key, value[key]])));
}

function sameFingerprint(left, right) {
  return FINGERPRINT_KEYS.every((key) => left[key] === right[key]);
}

function checkedInput(value) {
  try {
    const keySet = value && typeof value === 'object' && !Array.isArray(value) ? Object.keys(value).sort().join(',') : '';
    if (!['model,paths,prompt,repository', 'model,prompt,repository'].includes(keySet)
      || !isRegisteredCursorRepository(value.repository)
      || typeof value.prompt !== 'string' || value.prompt.length === 0 || Buffer.byteLength(value.prompt, 'utf8') > 32_768
      || value.prompt.includes('\0') || typeof value.model !== 'string' || value.model.length === 0 || value.model.length > 256
      || /[\u0000-\u001f\u007f]/u.test(value.model)) throw safety();
    if (Object.hasOwn(value, 'paths')) {
      if (!Array.isArray(value.paths) || value.paths.length === 0 || value.paths.length > 128) throw safety();
      for (const selected of value.paths) {
        if (typeof selected !== 'string' || selected.length === 0 || selected.length > 4_096
          || /[\u0000-\u001f\u007f]/u.test(selected) || /^(?:[A-Za-z]:[\\/]|[\\/])/u.test(selected)
          || selected.split(/[\\/]/u).includes('..')) throw safety();
      }
    }
    return value;
  } catch { throw safety(); }
}

function publicFailure(error) {
  let code;
  try { code = error?.code; } catch { return safety(); }
  if (!PUBLIC_CODES.has(code)) return safety();
  return new ClaudexError(code, code === 'MODEL_NOT_FOUND' ? 'The requested Cursor model is unavailable.'
    : code === 'AUTH_REQUIRED' ? 'Cursor Agent authentication is required.'
      : code === 'CAPABILITY_UNSUPPORTED' ? 'Cursor Agent cannot perform this delegated operation.'
        : 'The Cursor read-only delegation could not be completed safely.');
}

export function createCursorReadonlyService({ snapshotService, runner, captureSourceFingerprint, runContext = {} } = {}) {
  if (!snapshotService || typeof snapshotService.withSnapshot !== 'function' || !runner || typeof runner.run !== 'function'
    || typeof captureSourceFingerprint !== 'function' || !runContext || typeof runContext !== 'object' || Array.isArray(runContext)) throw safety();
  const context = freeze({ ...runContext });

  const execute = async (mode, rawInput, { signal } = {}) => {
    if (signal !== undefined && (!signal || typeof signal.addEventListener !== 'function')) throw safety();
    const input = checkedInput(rawInput);
    let before;
    try { before = fingerprint(await captureSourceFingerprint(input.repository.root)); } catch { throw safety(); }
    let result;
    let caught;
    try {
      result = await snapshotService.withSnapshot({
        repository: input.repository,
        ...(Object.hasOwn(input, 'paths') ? { paths: [...input.paths] } : {})
      }, async (snapshot) => runner.run({
        ...context, mode, prompt: input.prompt, model: input.model, scope: snapshot.scope,
        ...(signal === undefined ? {} : { signal })
      }));
    } catch (error) { caught = publicFailure(error); }
    let after;
    try { after = fingerprint(await captureSourceFingerprint(input.repository.root)); }
    catch { caught = safety(); }
    if (after && !sameFingerprint(before, after)) caught = safety();
    if (caught) throw caught;
    return freeze({ mode, result });
  };

  return freeze({
    ask: (input, options) => execute('ask', input, options),
    plan: (input, options) => execute('plan', input, options)
  });
}
