import { ClaudeyError } from '../core/errors.js';
import { isCursorCapabilitySet } from './capabilities.js';

export const MCP_PROTOCOL_VERSION = '2025-11-25';

const MODEL = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const REF_OR_OID = /^(?:refs\/(?:heads|tags)\/[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}|[0-9a-f]{40}|[0-9a-f]{64})$/u;
const APPROVAL = /^[A-Za-z0-9_-]{43}$/u;

function safety() {
  return new ClaudeyError('SAFETY_REFUSAL', 'The Cursor MCP schema or input is unsafe.');
}

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function record(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exact(value, allowed, required = allowed) {
  if (!record(value)) return false;
  const keys = Object.keys(value);
  return keys.every((key) => allowed.includes(key)) && required.every((key) => Object.hasOwn(value, key));
}

function safeText(value, maxBytes, { controls = false } = {}) {
  return typeof value === 'string' && value.length > 0 && Buffer.byteLength(value, 'utf8') <= maxBytes
    && !value.includes('\0') && (controls || !/[\u0000-\u001f\u007f]/u.test(value));
}

function schema(properties, required) {
  return freeze({ type: 'object', additionalProperties: false, properties, ...(required.length ? { required } : {}) });
}

const EMPTY_SCHEMA = schema({}, []);
const READ_ANNOTATIONS = freeze({ readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: true });
const MODELS_ANNOTATIONS = freeze({ ...READ_ANNOTATIONS, idempotentHint: true });
const WORKTREE_ANNOTATIONS = freeze({ readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true });

const MODELS = freeze({
  name: 'cursor_models', title: 'Cursor models',
  description: 'List the current models from the verified authenticated Cursor Agent.',
  inputSchema: EMPTY_SCHEMA, annotations: MODELS_ANNOTATIONS
});

function readonly(name, title, description) {
  return freeze({
    name, title, description,
    inputSchema: schema({
      prompt: { type: 'string', minLength: 1, maxLength: 32_768 },
      model: { type: 'string', minLength: 1, maxLength: 256 },
      paths: { type: 'array', minItems: 1, maxItems: 128, uniqueItems: true,
        items: { type: 'string', minLength: 1, maxLength: 4_096 } }
    }, ['prompt']),
    annotations: READ_ANNOTATIONS
  });
}

const ASK = readonly('cursor_ask', 'Ask Cursor about a snapshot',
  'Ask Cursor using a private disposable read-only project snapshot.');
const PLAN = readonly('cursor_plan', 'Plan with Cursor in a snapshot',
  'Request a genuine Cursor plan using a private disposable read-only project snapshot.');

const WORKTREE = freeze({
  name: 'cursor_worktree_run',
  title: 'Cursor approved worktree run',
  description: 'Run Cursor in a new retained Git worktree after a separate single-use human approval.',
  inputSchema: schema({
    repo: { type: 'string', minLength: 1, maxLength: 4_096 },
    prompt: { type: 'string', minLength: 1, maxLength: 32_768 },
    model: { type: 'string', minLength: 1, maxLength: 256 },
    baseRef: { type: 'string', minLength: 40, maxLength: 1_035 },
    approvalId: { type: 'string', pattern: '^[A-Za-z0-9_-]{43}$' }
  }, ['repo', 'prompt']),
  annotations: WORKTREE_ANNOTATIONS,
  _meta: {
    'claudey/requiresUserInteraction': true,
    'claudey/requiresOutOfBandApproval': true,
    'anthropic/maxResultSizeChars': 1_048_576
  }
});

export function buildCursorToolDescriptors({ capabilities, writesEnabled, worktreeSafetyReady } = {}) {
  if (!isCursorCapabilitySet(capabilities) || typeof writesEnabled !== 'boolean'
    || typeof worktreeSafetyReady !== 'boolean') throw safety();
  const tools = [];
  if (capabilities.tools.models.available) tools.push(MODELS);
  if (capabilities.tools.ask.available) tools.push(ASK);
  if (capabilities.tools.plan.available) tools.push(PLAN);
  if (capabilities.tools.worktree.available && writesEnabled && worktreeSafetyReady) tools.push(WORKTREE);
  return freeze([...tools]);
}

function checkedPaths(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 128) throw safety();
  const seen = new Set();
  return value.map((entry) => {
    if (!safeText(entry, 4_096) || /^(?:[A-Za-z]:[\\/]|[\\/])/u.test(entry)
      || entry.split(/[\\/]/u).some((part) => part === '..') || seen.has(entry)) throw safety();
    seen.add(entry);
    return entry;
  });
}

export function validateCursorToolArguments(name, rawValue) {
  try {
    if (name === 'cursor_models') {
      if (!exact(rawValue, [])) throw safety();
      return freeze({});
    }
    if (name === 'cursor_ask' || name === 'cursor_plan') {
      if (!exact(rawValue, ['prompt', 'model', 'paths'], ['prompt']) || !safeText(rawValue.prompt, 32_768, { controls: true })
        || Object.hasOwn(rawValue, 'model') && !MODEL.test(rawValue.model)) throw safety();
      const result = { prompt: rawValue.prompt };
      if (Object.hasOwn(rawValue, 'model')) result.model = rawValue.model;
      if (Object.hasOwn(rawValue, 'paths')) result.paths = checkedPaths(rawValue.paths);
      return freeze(result);
    }
    if (name === 'cursor_worktree_run') {
      if (!exact(rawValue, ['repo', 'prompt', 'model', 'baseRef', 'approvalId'], ['repo', 'prompt'])
        || !safeText(rawValue.repo, 4_096) || !safeText(rawValue.prompt, 32_768, { controls: true })
        || Object.hasOwn(rawValue, 'model') && !MODEL.test(rawValue.model)
        || Object.hasOwn(rawValue, 'baseRef') && !REF_OR_OID.test(rawValue.baseRef)
        || Object.hasOwn(rawValue, 'approvalId') && !APPROVAL.test(rawValue.approvalId)) throw safety();
      return freeze(Object.fromEntries(['repo', 'prompt', 'model', 'baseRef', 'approvalId']
        .filter((key) => Object.hasOwn(rawValue, key)).map((key) => [key, rawValue[key]])));
    }
    throw safety();
  } catch { throw safety(); }
}
