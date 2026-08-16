import { ClaudeyError } from '../../core/errors.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const VERSION = /^\d+\.\d+\.\d+$/u;

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

function safety() { return new ClaudeyError('SAFETY_REFUSAL', 'Installation status could not be inspected safely.'); }

function inspector(context, name) {
  try {
    const value = context?.[name];
    if (typeof value !== 'function') throw safety();
    return value;
  } catch { throw safety(); }
}

function installation(value) {
  if (!exact(value, ['state', 'version', 'installationId'])
    || value.state === 'installed' && (!VERSION.test(value.version) || !UUID.test(value.installationId))
    || value.state === 'not-installed' && (value.version !== null || value.installationId !== null)
    || !['installed', 'not-installed'].includes(value.state)) throw safety();
  return { state: value.state, version: value.version, installationId: value.installationId };
}

function gateway(value) {
  const states = ['healthy', 'stopped', 'unhealthy', 'not-installed', 'stale-state', 'port-occupied'];
  if (!exact(value, ['state', 'port']) || !states.includes(value.state)
    || value.port !== null && (!Number.isSafeInteger(value.port) || value.port < 1024 || value.port > 65535)
    || value.state === 'not-installed' && value.port !== null) throw safety();
  return { state: value.state, port: value.port };
}

function providers(value) {
  const states = ['authenticated', 'missing', 'unavailable'];
  if (!exact(value, ['codex', 'antigravity', 'grok']) || !states.includes(value.codex)
    || !states.includes(value.antigravity) || !states.includes(value.grok)) throw safety();
  return { codex: value.codex, antigravity: value.antigravity, grok: value.grok };
}

function cursor(value) {
  if (!exact(value, ['registration', 'login', 'writes', 'pendingWorktrees'])
    || !['enabled', 'disabled', 'collision'].includes(value.registration)
    || !['authenticated', 'logged-out', 'unavailable'].includes(value.login)
    || !['enabled', 'disabled'].includes(value.writes)
    || !Number.isSafeInteger(value.pendingWorktrees) || value.pendingWorktrees < 0 || value.pendingWorktrees > 10_000) throw safety();
  return { registration: value.registration, login: value.login, writes: value.writes,
    pendingWorktrees: value.pendingWorktrees };
}

function recovery(value) {
  if (!exact(value, ['journal', 'rollback']) || !['clear', 'pending'].includes(value.journal)
    || !['available', 'unavailable'].includes(value.rollback)) throw safety();
  return { journal: value.journal, rollback: value.rollback };
}

function unhealthyCode(result) {
  if (result.installation.state === 'not-installed' || result.gateway.state === 'not-installed') return 'NOT_INSTALLED';
  if (result.gateway.state === 'port-occupied') return 'PORT_IN_USE';
  if (result.gateway.state === 'stale-state') return 'PROCESS_IDENTITY_MISMATCH';
  if (result.gateway.state !== 'healthy') return 'GATEWAY_UNHEALTHY';
  return 'SAFETY_REFUSAL';
}

async function inspected(context, name, validate) {
  let value;
  try { value = await inspector(context, name)(); } catch { throw safety(); }
  try { return validate(value); } catch { throw safety(); }
}

async function productionStatusContext() {
  const { listProviderModels } = await import('../../providers/models.js');
  const { createProductionContainer, loadInstallation } = await import('../runtime.js');
  const container = createProductionContainer();
  const gateway = container.contexts.models;
  return {
    inspectInstallation: async () => {
      try {
        const installed = await loadInstallation();
        return { state: 'installed', version: installed.version, installationId: installed.installationId };
      } catch (error) {
        if (error?.code === 'NOT_INSTALLED') return { state: 'not-installed', version: null, installationId: null };
        throw error;
      }
    },
    inspectGateway: async () => {
      try {
        await gateway.ensureHealthy();
        return { state: 'healthy', port: gateway.port };
      } catch (error) {
        if (error?.code === 'NOT_INSTALLED') return { state: 'not-installed', port: null };
        if (error?.code === 'PORT_IN_USE') return { state: 'port-occupied', port: gateway.port };
        return { state: 'unhealthy', port: gateway.port };
      }
    },
    inspectProviders: async () => {
      const stateFor = async (provider) => {
        try {
          await listProviderModels(provider, gateway);
          return 'authenticated';
        } catch (error) {
          return error?.code === 'AUTH_REQUIRED' ? 'missing' : 'unavailable';
        }
      };
      return { codex: await stateFor('codex'), antigravity: await stateFor('antigravity'), grok: await stateFor('grok') };
    },
    inspectCursor: async () => ({ registration: 'disabled', login: 'unavailable', writes: 'disabled', pendingWorktrees: 0 }),
    inspectRecovery: async () => ({ journal: 'clear', rollback: 'unavailable' })
  };
}

export async function runStatusCommand(context = {}) {
  const effectiveContext = typeof context?.inspectInstallation === 'function'
    ? context
    : await productionStatusContext();
  const result = freeze({ schemaVersion: 1, healthy: false,
    installation: await inspected(effectiveContext, 'inspectInstallation', installation),
    gateway: await inspected(effectiveContext, 'inspectGateway', gateway),
    providers: await inspected(effectiveContext, 'inspectProviders', providers),
    cursor: await inspected(effectiveContext, 'inspectCursor', cursor),
    recovery: await inspected(effectiveContext, 'inspectRecovery', recovery) });
  const healthy = result.installation.state === 'installed' && result.gateway.state === 'healthy'
    && result.recovery.journal === 'clear' && result.cursor.registration !== 'collision';
  const final = freeze({ ...result, healthy });
  if (!healthy) {
    const code = unhealthyCode(final);
    throw new ClaudeyError(code, code === 'NOT_INSTALLED' ? 'Claudey is not installed.'
      : code === 'PORT_IN_USE' ? 'The configured loopback port is occupied by an unrelated listener.'
        : code === 'PROCESS_IDENTITY_MISMATCH' ? 'The managed gateway process identity could not be verified.'
          : code === 'GATEWAY_UNHEALTHY' ? 'The managed gateway is not healthy.' : 'Installation status is unsafe.',
    { details: { status: final } });
  }
  return final;
}
