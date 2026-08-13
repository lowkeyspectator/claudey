import { ClaudexError } from '../core/errors.js';
import { cursorCapabilitiesMatchBinding, isCursorCapabilitySet } from './capabilities.js';
import { isCursorExecutableBinding, revalidateCursorExecutableBinding } from './executable.js';

const CATALOGS = new WeakSet();
const CATALOG_BINDINGS = new WeakMap();
const MAX_OUTPUT_BYTES = 16_384;
const MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;

function capabilityFailure() {
  return new ClaudexError('CAPABILITY_UNSUPPORTED', 'The live Cursor model catalog is unavailable.');
}

function safety() {
  return new ClaudexError('SAFETY_REFUSAL', 'The Cursor model selection could not be verified.');
}

function exact(value, keys) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(','));
}

function parse(output) {
  if (typeof output !== 'string' || Buffer.byteLength(output, 'utf8') > MAX_OUTPUT_BYTES
    || !output.endsWith('\n') || output.indexOf('\n') !== output.length - 1) return null;
  let value;
  try { value = JSON.parse(output); } catch { return null; }
  if (!exact(value, ['models']) || !Array.isArray(value.models) || value.models.length === 0) return null;
  const seen = new Set();
  const models = [];
  for (const model of value.models) {
    if (!exact(model, ['id']) || typeof model.id !== 'string' || !MODEL_ID.test(model.id) || seen.has(model.id)) return null;
    seen.add(model.id);
    models.push(model.id);
  }
  return models.sort((left, right) => left.localeCompare(right));
}

async function query(invoke, revalidateBinding, binding, args) {
  try {
    if (await revalidateCursorExecutableBinding(binding) !== true || await revalidateBinding(binding) !== true) return undefined;
    const result = await invoke(Object.freeze({ binding, args: Object.freeze([...args]), stdin: null }));
    if (!result || result.code !== 0 || typeof result.stderr !== 'string' || result.stderr !== '') return undefined;
    return parse(result.stdout);
  } catch { return undefined; }
}

export async function listCursorModels(binding, capabilities, { invoke, revalidateBinding = async () => true } = {}) {
  if (!isCursorExecutableBinding(binding) || !isCursorCapabilitySet(capabilities)
    || !cursorCapabilitiesMatchBinding(capabilities, binding)
    || capabilities.tools.models.available !== true || typeof invoke !== 'function'
    || typeof revalidateBinding !== 'function') throw capabilityFailure();
  let models = await query(invoke, revalidateBinding, binding, ['models', '--json']);
  if (models === undefined) models = await query(invoke, revalidateBinding, binding, ['--list-models', '--json']);
  if (!models) throw capabilityFailure();
  const catalog = Object.freeze({ models: Object.freeze(models) });
  CATALOGS.add(catalog);
  CATALOG_BINDINGS.set(catalog, binding);
  return catalog;
}

export function requireCursorModel(catalog, requested) {
  if (!catalog || typeof catalog !== 'object' || !CATALOGS.has(catalog)) throw safety();
  if (typeof requested !== 'string' || !MODEL_ID.test(requested) || !catalog.models.includes(requested)) {
    throw new ClaudexError('MODEL_NOT_FOUND', 'The requested model is not available from Cursor Agent.');
  }
  return requested;
}

export function isCursorModelCatalog(value) {
  return Boolean(value && typeof value === 'object' && CATALOGS.has(value));
}

export function cursorModelCatalogMatchesBinding(value, binding) {
  return isCursorModelCatalog(value) && isCursorExecutableBinding(binding) && CATALOG_BINDINGS.get(value) === binding;
}
