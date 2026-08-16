import path from 'node:path';

import { ClaudeyError } from '../core/errors.js';
import { cursorCapabilitiesMatchBinding, isCursorCapabilitySet } from './capabilities.js';
import { isCursorEnvironment } from './env.js';
import { isCursorExecutableBinding, revalidateCursorExecutableBinding } from './executable.js';
import { cursorModelCatalogMatchesBinding, isCursorModelCatalog, requireCursorModel } from './models.js';

const SCOPES = new WeakSet();
const MODES = new Set(['ask', 'plan', 'worktree']);
const MAX_PROMPT_BYTES = 32_768;
const MAX_STDOUT_BYTES = 1_048_576;
const MAX_STDERR_BYTES = 16_384;
const TIMEOUT_MS = 120_000;
const MAX_CONCURRENT = 3;
let activeRuns = 0;

function safety() {
  return new ClaudeyError('SAFETY_REFUSAL', 'The Cursor run could not be constructed safely.');
}

function unsupported() {
  return new ClaudeyError('CAPABILITY_UNSUPPORTED', 'Cursor Agent could not complete the delegated run safely.');
}

function exact(value, keys) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(','));
}

export function createCursorRunScope(value = {}) {
  try {
    if (!exact(value, ['kind', 'cwd', 'platform']) || !['snapshot', 'worktree'].includes(value.kind)
      || typeof value.cwd !== 'string' || value.cwd.length === 0 || value.cwd.includes('\0')
      || value.cwd.includes('\r') || value.cwd.includes('\n')) throw safety();
    const pathApi = value.platform === 'windows' || value.platform === 'win32' ? path.win32
      : value.platform === 'linux' || value.platform === 'darwin' || value.platform === 'macos' ? path.posix : null;
    if (!pathApi || !pathApi.isAbsolute(value.cwd) || pathApi.normalize(value.cwd) !== value.cwd
      || value.cwd === pathApi.parse(value.cwd).root) throw safety();
    const scope = Object.freeze({ kind: value.kind, cwd: value.cwd, platform: value.platform });
    SCOPES.add(scope);
    return scope;
  } catch { throw safety(); }
}

function checkedRequest(value) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw safety();
    const allowed = ['binding', 'capabilities', 'catalog', 'environment', 'mode', 'prompt', 'model', 'scope', 'signal'];
    const keys = Object.keys(value);
    if (keys.some((key) => !allowed.includes(key)) || allowed.slice(0, -1).some((key) => !Object.hasOwn(value, key))) throw safety();
    if (!isCursorExecutableBinding(value.binding) || !isCursorCapabilitySet(value.capabilities)
      || !cursorCapabilitiesMatchBinding(value.capabilities, value.binding)
      || !isCursorModelCatalog(value.catalog) || !cursorModelCatalogMatchesBinding(value.catalog, value.binding)
      || !isCursorEnvironment(value.environment)
      || !MODES.has(value.mode) || typeof value.prompt !== 'string' || Buffer.byteLength(value.prompt, 'utf8') > MAX_PROMPT_BYTES
      || value.prompt.length === 0 || value.prompt.includes('\0') || !SCOPES.has(value.scope)
      || value.mode === 'worktree' !== (value.scope.kind === 'worktree')
      || value.signal !== undefined && (typeof value.signal !== 'object' || typeof value.signal.addEventListener !== 'function')) throw safety();
    return value;
  } catch (caught) {
    try { if (caught?.code === 'MODEL_NOT_FOUND') throw caught; } catch (inner) { throw inner; }
    throw safety();
  }
}

function argsFor(mode, model) {
  const args = ['--mode', mode, '--print', '--output-format', 'json'];
  if (mode !== 'worktree') args.push('--sandbox', 'read-only');
  args.push('--model', model);
  return Object.freeze(args);
}

function parseResult(result) {
  try {
    if (!result || result.code !== 0 || result.cleanupConfirmed !== true
      || typeof result.stdout !== 'string' || typeof result.stderr !== 'string' || result.stderr !== ''
      || Buffer.byteLength(result.stdout, 'utf8') > MAX_STDOUT_BYTES
      || Buffer.byteLength(result.stderr, 'utf8') > MAX_STDERR_BYTES
      || !result.stdout.endsWith('\n') || result.stdout.indexOf('\n') !== result.stdout.length - 1) throw unsupported();
    const value = JSON.parse(result.stdout);
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw unsupported();
    const freeze = (entry) => {
      if (entry && typeof entry === 'object' && !Object.isFrozen(entry)) {
        for (const child of Object.values(entry)) freeze(child);
        Object.freeze(entry);
      }
      return entry;
    };
    return freeze({ type: 'cursor-result', untrusted: true, value });
  } catch { throw unsupported(); }
}

export function createCursorRunner({ invoke, revalidateScope, revalidateModel, revalidateBinding = async () => true } = {}) {
  if (typeof invoke !== 'function' || typeof revalidateScope !== 'function'
    || typeof revalidateModel !== 'function' || typeof revalidateBinding !== 'function') throw safety();
  return Object.freeze({
    async run(rawRequest) {
      const request = checkedRequest(rawRequest);
      const requiredTool = request.mode;
      if (request.capabilities.tools[requiredTool]?.available !== true) throw unsupported();
      const model = requireCursorModel(request.catalog, request.model);
      if (activeRuns >= MAX_CONCURRENT) throw unsupported();
      activeRuns += 1;
      try {
        if (await revalidateModel(request.catalog, model) !== true) {
          throw new ClaudeyError('MODEL_NOT_FOUND', 'The requested model is not available from Cursor Agent.');
        }
        if (await revalidateCursorExecutableBinding(request.binding) !== true
          || await revalidateBinding(request.binding) !== true || await revalidateScope(request.scope) !== true) throw safety();
        const invocation = Object.freeze({
          binding: request.binding,
          args: argsFor(request.mode, model),
          stdin: request.prompt,
          cwd: request.scope.cwd,
          env: request.environment,
          signal: request.signal,
          timeoutMs: TIMEOUT_MS,
          maxStdoutBytes: MAX_STDOUT_BYTES,
          maxStderrBytes: MAX_STDERR_BYTES,
          shell: false
        });
        let result;
        try { result = await invoke(invocation); } catch { throw unsupported(); }
        return parseResult(result);
      } finally { activeRuns -= 1; }
    }
  });
}
