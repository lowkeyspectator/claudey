import { runAuthCommand } from './commands/auth.js';
import { runConfigCommand } from './commands/config.js';
import { runCursorCommand, runCursorMcpServe, runCursorModelsCommand } from './commands/cursor.js';
import { runDoctorCommand } from './commands/doctor.js';
import { runInstallCommand } from './commands/install.js';
import { runLifecycleCommand } from './commands/lifecycle.js';
import { runModelsCommand } from './commands/models.js';
import { runRollbackCommand } from './commands/rollback.js';
import { runOnboardCommand } from './commands/onboard.js';
import { runSetupCommand } from './commands/setup.js';
import { runStatusCommand } from './commands/status.js';
import { runUninstallCommand } from './commands/uninstall.js';
import { runUpdateCommand } from './commands/update.js';
import { runClaudeCodex } from './launchers/claude-codex.js';
import { runClaudeAgy } from './launchers/claude-agy.js';
import { runClaudeGrok } from './launchers/claude-grok.js';
import { runClaudey } from './launchers/claudey.js';
import { GATEWAY_PROVIDERS } from '../providers/catalog.js';
import { ClaudeyError, exitCodeFor } from '../core/errors.js';
import { emitError, emitSuccess } from './output.js';
import { parseManagementArgs } from './parse.js';
import { createProductionContainer } from './runtime.js';

const HELP = `Usage:
  claudey onboard [--yes]
  claudey setup [--version VERSION] [--port PORT] [--with-cursor] [--no-start] [--no-path] [--yes]
  claudey install [--version VERSION] [--port PORT] [--yes]
  claudey auth grok|antigravity|codex|all [options]
  claudey start|stop|restart|status|doctor
  claudey update|rollback [options]
  claudey models [codex|antigravity|grok|cursor|all]
  claudey config set port PORT [--yes]
  claudey cursor enable|disable|install|login|repo|writes|approve [options]
  claudey uninstall [--dry-run] [--purge-auth] [--yes]
`;
const PUBLIC_CODES = new Set([
  'USAGE_ERROR', 'PLATFORM_UNSUPPORTED', 'PREREQUISITE_MISSING', 'CAPABILITY_UNSUPPORTED', 'NOT_INSTALLED',
  'AUTH_REQUIRED', 'INTERACTION_REQUIRED', 'MODEL_REQUIRED', 'MODEL_NOT_FOUND', 'NETWORK_FAILURE',
  'CHECKSUM_MISMATCH', 'ARCHIVE_UNSAFE', 'LOCK_BUSY', 'PORT_IN_USE', 'GATEWAY_UNHEALTHY',
  'PROCESS_IDENTITY_MISMATCH', 'CONFIG_MODIFIED', 'MCP_OWNERSHIP_COLLISION', 'APPROVAL_REQUIRED',
  'APPROVAL_INVALID', 'SAFETY_REFUSAL', 'UPDATE_ROLLED_BACK', 'ROLLBACK_UNAVAILABLE'
]);

function record(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function safety() { return new ClaudeyError('SAFETY_REFUSAL', 'The management command could not be dispatched safely.'); }

function schemaResult(value) {
  if (!record(value)) throw safety();
  return Object.freeze(Object.hasOwn(value, 'schemaVersion') ? value : { schemaVersion: 1, ...value });
}

function publicCode(error) {
  try { return PUBLIC_CODES.has(error?.code) ? error.code : 'SAFETY_REFUSAL'; }
  catch { return 'SAFETY_REFUSAL'; }
}

async function attachCursorUsage(result, context) {
  const attach = context.gateway?.attachUsage ?? context.attachUsage;
  if (typeof attach !== 'function' || !Array.isArray(result?.models)) return result;
  try {
    const wrapped = await attach({
      provider: 'cursor',
      models: result.models.map((model) => (
        typeof model === 'string' ? { id: model, owned_by: 'cursor' } : model
      ))
    });
    return { ...result, models: wrapped.models };
  } catch {
    return result;
  }
}

async function runRoutedModels(command, context = {}) {
  if (command[1] === 'cursor') {
    return schemaResult(await attachCursorUsage(await runCursorModelsCommand(context.cursor ?? context), context));
  }
  if (command[1] !== 'all') return schemaResult(await runModelsCommand(command, context.gateway ?? context));

  let gatewayProviders = [];
  let gatewayError;
  try {
    const gateway = await runModelsCommand(command, context.gateway ?? context);
    gatewayProviders = [...gateway.providers];
  } catch (error) {
    gatewayError = error;
    try {
      if (Array.isArray(error?.details?.providers)) gatewayProviders = [...error.details.providers];
    } catch { gatewayProviders = []; }
  }
  if (gatewayProviders.length !== GATEWAY_PROVIDERS.length) gatewayProviders = GATEWAY_PROVIDERS.map((provider) => Object.freeze({
    provider, status: 'unavailable', code: publicCode(gatewayError), models: Object.freeze([])
  }));

  let cursor;
  let cursorError;
  try {
    const result = await runCursorModelsCommand(context.cursor ?? context);
    cursor = Object.freeze({
      provider: 'cursor',
      status: 'available',
      models: Object.freeze((result.models ?? []).map((model) => (
        typeof model === 'string' ? Object.freeze({ id: model, owned_by: 'cursor' }) : model
      )))
    });
  } catch (error) {
    cursorError = error;
    cursor = Object.freeze({ provider: 'cursor', status: 'unavailable', code: publicCode(error), models: Object.freeze([]) });
  }
  const attachUsage = context.gateway?.attachUsage ?? context.attachUsage;
  if (typeof attachUsage === 'function') {
    try { cursor = await attachUsage(cursor); } catch { /* usage is best-effort */ }
  }
  const providers = Object.freeze([...gatewayProviders, cursor]);
  const successes = providers.filter(({ status }) => status === 'available').length;
  if (successes > 0) return Object.freeze({ schemaVersion: 1,
    status: successes === providers.length ? 'available' : 'partial', providers });
  const candidates = [gatewayError, cursorError].filter(Boolean)
    .map((error) => ({ error, exit: exitCodeFor(error) })).sort((left, right) => right.exit - left.exit);
  const code = publicCode(candidates[0]?.error);
  throw new ClaudeyError(code, 'No requested provider model catalog is available.', { details: { providers } });
}

const DEFAULT_HANDLERS = Object.freeze({
  onboard: ({ options, context }) => runOnboardCommand(options, context),
  setup: ({ options, context }) => runSetupCommand(options, context),
  install: ({ options, context }) => runInstallCommand(options, context),
  auth: ({ command, options, context }) => runAuthCommand(command, options, context),
  lifecycle: ({ command, options, context }) => runLifecycleCommand(command, options, context),
  status: ({ context }) => runStatusCommand(context),
  update: ({ options, context }) => runUpdateCommand(options, context),
  rollback: ({ options, context }) => runRollbackCommand(options, context),
  models: ({ command, context }) => runRoutedModels(command, context),
  doctor: ({ context }) => runDoctorCommand(context),
  config: ({ command, options, context }) => runConfigCommand(command, options, context),
  cursor: ({ command, options, context }) => runCursorCommand(command, options, context),
  cursorMcpServe: ({ options, context }) => runCursorMcpServe(options, context),
  uninstall: ({ options, context }) => runUninstallCommand(options, context),
  'claude-codex': ({ options, context }) => runClaudeCodex(options?.rawArgv ?? [], process.env, context),
  'claude-agy': ({ options, context }) => runClaudeAgy(options?.rawArgv ?? [], process.env, context),
  'claude-grok': ({ options, context }) => runClaudeGrok(options?.rawArgv ?? [], process.env, context),
  claudey: ({ options, context }) => runClaudey(options?.rawArgv ?? [], process.env, context),
  claudeyctl: ({ options, context }) => runClaudey(options?.rawArgv ?? [], process.env, context)
});

function family(command) {
  const first = command[0];
  if (['start', 'stop', 'restart'].includes(first)) return 'lifecycle';
  if (first === 'cursor') return command[1] === 'mcp-serve' ? 'cursorMcpServe' : 'cursor';
  if (first === 'launcher') return command[1];
  return first;
}

function dependency(container, familyName) {
  try {
    const handlers = container?.handlers;
    const contexts = container?.contexts;
    const candidate = record(handlers) && Object.hasOwn(handlers, familyName) ? handlers[familyName] : DEFAULT_HANDLERS[familyName];
    if (typeof candidate !== 'function') throw safety();
    const context = record(contexts) && Object.hasOwn(contexts, familyName) ? contexts[familyName] : {};
    return { handler: candidate, context };
  } catch { throw safety(); }
}

function isHelpArgv(argv) {
  if (!Array.isArray(argv) || argv.includes('--')) return false;
  const tokens = argv.filter((token, index, all) => !(token === 'launcher' && all[index + 1] === 'claudey')
    && !(token === 'claudey' && all[index - 1] === 'launcher'));
  return tokens.length === 1 && ['--help', 'help'].includes(tokens[0]);
}

export async function main(argv = process.argv.slice(2), environment = process.env, container = {}) {
  if (isHelpArgv(argv)) {
    return Object.freeze({ type: 'help', text: HELP });
  }
  const parsed = parseManagementArgs(argv, environment);
  const familyName = family(parsed.command);
  const { handler, context } = dependency(container, familyName);
  const command = Object.freeze([...parsed.command]);
  const options = Object.freeze({ ...parsed.options });
  return handler(Object.freeze({ command, options, context }));
}

function errorEnvelope(error) {
  if (error instanceof ClaudeyError) return error;
  try {
    if (error?.code === 'USAGE_ERROR' && typeof error.message === 'string' && error.message.length <= 1_024) {
      return new ClaudeyError('USAGE_ERROR', error.message);
    }
  } catch { /* sanitize */ }
  return safety();
}

function hasExplicitContainer(container) {
  return record(container) && (record(container.handlers) || record(container.contexts));
}

export async function run(argv = process.argv.slice(2), environment = process.env, io = process, container = {}) {
  const json = argv.includes('--json');
  const noColor = argv.includes('--no-color');
  try {
    const effective = hasExplicitContainer(container) ? container : createProductionContainer(environment);
    const result = await main(argv, environment, effective);
    emitSuccess(result, { json, noColor }, io);
    return 0;
  } catch (error) {
    const normalized = errorEnvelope(error);
    emitError(normalized, { json, noColor }, io);
    return exitCodeFor(normalized);
  }
}
