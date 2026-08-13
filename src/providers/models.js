import { ClaudexError, exitCodeFor } from '../core/errors.js';
import { isSecret } from '../core/secrets.js';
import { validateAuthenticatedModelCatalog } from './capabilities.js';

const GATEWAY_PROVIDERS = Object.freeze(['codex', 'antigravity']);

function failure(code, message, options) {
  return new ClaudexError(code, message, options);
}

function unhealthy() {
  return failure('GATEWAY_UNHEALTHY', 'The managed gateway did not provide a valid authenticated model catalog.');
}

function authRequired(provider) {
  return failure('AUTH_REQUIRED', `Provider "${provider}" is not authenticated.`, {
    hint: `Run claudexctl auth ${provider}.`, details: { provider }
  });
}

function checkedProvider(provider) {
  if (!GATEWAY_PROVIDERS.includes(provider)) throw failure('USAGE_ERROR', 'Model provider must be codex or antigravity.');
  return provider;
}

function checkedContext(context) {
  if (!context || typeof context !== 'object' || context.host !== '127.0.0.1'
    || !Number.isSafeInteger(context.port) || context.port < 1024 || context.port > 65535
    || !isSecret(context.token) || typeof context.ensureHealthy !== 'function' || typeof context.requestModels !== 'function') throw unhealthy();
  return context;
}

function publicCode(error) {
  return typeof error?.code === 'string' && ['AUTH_REQUIRED', 'GATEWAY_UNHEALTHY', 'PORT_IN_USE', 'PROCESS_IDENTITY_MISMATCH'].includes(error.code)
    ? error.code : 'GATEWAY_UNHEALTHY';
}

function lifecycleFailure(error) {
  if (error?.code === 'PORT_IN_USE') return failure('PORT_IN_USE', 'The managed gateway port is already in use.');
  if (error?.code === 'PROCESS_IDENTITY_MISMATCH') return failure('PROCESS_IDENTITY_MISMATCH', 'The managed gateway process identity could not be verified.');
  return unhealthy();
}

export async function listProviderModels(provider, context = {}) {
  checkedProvider(provider);
  const ctx = checkedContext(context);
  try { await ctx.ensureHealthy(ctx); } catch (error) { throw lifecycleFailure(error); }
  let catalog;
  try {
    catalog = await ctx.requestModels({
      host: ctx.host, port: ctx.port, token: ctx.token, allowPreAuthEmpty: true, signal: ctx.signal
    });
  } catch { throw unhealthy(); }
  if (!validateAuthenticatedModelCatalog(catalog, { allowPreAuthEmpty: true })) throw unhealthy();
  const models = catalog.data
    .filter((model) => model.owned_by === provider)
    .map((model) => Object.freeze({ id: model.id, object: model.object, created: model.created, owned_by: model.owned_by }))
    .sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0);
  if (models.length === 0) throw authRequired(provider);
  return Object.freeze({ provider, status: 'available', models: Object.freeze(models) });
}

export async function requireProviderModel(provider, model, context = {}) {
  checkedProvider(provider);
  if (typeof model !== 'string' || model.length < 1 || model.length > 256 || model.trim() !== model || /[\u0000-\u001f\u007f]/.test(model)) {
    throw failure('USAGE_ERROR', 'Model identifier is invalid.');
  }
  const result = await listProviderModels(provider, context);
  const match = result.models.find((candidate) => candidate.id === model);
  if (!match) {
    throw failure('MODEL_NOT_FOUND', `"${model}" is not available for provider "${provider}".`, {
      hint: `Run claudexctl models ${provider}.`, details: { provider, model }
    });
  }
  return match;
}

export async function listAllGatewayModels(context = {}) {
  const listOne = context.listOne ?? ((provider) => listProviderModels(provider, context));
  if (typeof listOne !== 'function') throw unhealthy();
  const providers = [];
  const errors = [];
  for (const provider of GATEWAY_PROVIDERS) {
    try {
      const result = await listOne(provider);
      if (!result || result.provider !== provider || result.status !== 'available' || !Array.isArray(result.models)) throw unhealthy();
      providers.push(result);
    } catch (error) {
      const code = publicCode(error);
      errors.push({ code, exitCode: exitCodeFor({ code }) });
      providers.push(Object.freeze({ provider, status: 'unavailable', code, models: Object.freeze([]) }));
    }
  }
  const successes = providers.filter((provider) => provider.status === 'available').length;
  if (successes > 0) return Object.freeze({ status: successes === providers.length ? 'available' : 'partial', providers: Object.freeze(providers) });
  errors.sort((left, right) => right.exitCode - left.exitCode);
  const code = errors[0]?.code ?? 'GATEWAY_UNHEALTHY';
  throw failure(code, code === 'AUTH_REQUIRED' ? 'No requested provider is authenticated.' : 'No requested provider model catalog is available.', {
    details: { providers }
  });
}
