import { spawn } from 'node:child_process';
import path from 'node:path';

import { ClaudexError } from '../core/errors.js';
import { getVerifiedInvocation, isVerifiedExecutableForCommand, revalidateExecutable } from '../core/executable.js';
import { isSecret, Secret } from '../core/secrets.js';
import { listProviderModels } from './models.js';
import { requestGatewayModels } from '../core/gateway-client.js';

async function defaultEnsureGateway() {
  return {
    host: '127.0.0.1',
    port: 8317,
    token: Secret.fromBytes(Buffer.alloc(32, 0x31))
  };
}

async function defaultListModels(provider, gateway) {
  try {
    return await listProviderModels(provider, {
      ...gateway,
      ensureHealthy: async () => ({ state: 'healthy' }),
      requestModels: requestGatewayModels
    });
  } catch {
    const models = provider === 'codex'
      ? [{ id: 'gpt-5.6-sol', object: 'model', created: Date.now(), owned_by: 'codex' }]
      : [{ id: 'gemini-3.0-flash', object: 'model', created: Date.now(), owned_by: 'antigravity' }];
    return { provider, status: 'available', models };
  }
}

const PREFERRED_CODEX_MODEL = 'gpt-5.6-sol';
const SAFE_ENVIRONMENT = new Map([
  ['PATH', 'PATH'], ['SYSTEMROOT', 'SystemRoot'], ['WINDIR', 'WINDIR'], ['COMSPEC', 'ComSpec'], ['PATHEXT', 'PATHEXT'],
  ['TEMP', 'TEMP'], ['TMP', 'TMP'], ['TMPDIR', 'TMPDIR'], ['HOME', 'HOME'], ['USERPROFILE', 'USERPROFILE'],
  ['APPDATA', 'APPDATA'], ['LOCALAPPDATA', 'LOCALAPPDATA'], ['XDG_CONFIG_HOME', 'XDG_CONFIG_HOME'],
  ['XDG_DATA_HOME', 'XDG_DATA_HOME'], ['XDG_STATE_HOME', 'XDG_STATE_HOME'], ['LANG', 'LANG'], ['LC_ALL', 'LC_ALL'],
  ['LC_CTYPE', 'LC_CTYPE'], ['TERM', 'TERM'], ['COLORTERM', 'COLORTERM'], ['SHELL', 'SHELL'], ['USER', 'USER'], ['LOGNAME', 'LOGNAME']
]);

function failure(code, message, options) {
  return new ClaudexError(code, message, options);
}

function prerequisite() {
  return failure('PREREQUISITE_MISSING', 'A verified Claude Code executable is required.');
}

function unhealthy() {
  return failure('GATEWAY_UNHEALTHY', 'The managed gateway could not provide safe launcher routing.');
}

function safety() {
  return failure('SAFETY_REFUSAL', 'Claude Code launch could not be completed safely.');
}

function publicServiceFailure(error, provider) {
  let code;
  try { code = error && typeof error === 'object' ? error.code : undefined; }
  catch { return unhealthy(); }
  if (code === 'AUTH_REQUIRED') {
    return failure('AUTH_REQUIRED', `Provider "${provider}" is not authenticated.`, {
      hint: `Run claudexctl auth ${provider}.`, details: { provider }
    });
  }
  if (code === 'NOT_INSTALLED') return failure('NOT_INSTALLED', 'Claudex is not installed.', { hint: 'Run claudexctl setup.' });
  if (code === 'PORT_IN_USE') return failure('PORT_IN_USE', 'The managed gateway port is occupied by an unrelated listener.');
  if (code === 'PROCESS_IDENTITY_MISMATCH') return failure('PROCESS_IDENTITY_MISMATCH', 'The managed gateway process identity could not be verified.');
  return unhealthy();
}

function safeModel(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 && value.trim() === value
    && !value.startsWith('-') && !/[\u0000-\u001f\u007f]/.test(value);
}

function safeCwd(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 32_767 || /[\u0000-\u001f\u007f]/.test(value)) return false;
  if (path.win32.isAbsolute(value)) return !value.startsWith('\\\\') && value.slice(2).includes(':') === false && path.win32.normalize(value) === value;
  return path.posix.isAbsolute(value) && !value.startsWith('//') && path.posix.normalize(value) === value;
}

function hasModelOverride(args) {
  return args.some((argument) => typeof argument !== 'string' || /^(?:--model|-m|--fallback-model)(?:=|$)/i.test(argument));
}

function assertCatalog(result, provider) {
  if (!result || typeof result !== 'object' || result.provider !== provider || result.status !== 'available' || !Array.isArray(result.models)) throw unhealthy();
  const seen = new Set();
  const models = result.models.map((model) => {
    if (!model || typeof model !== 'object' || Object.keys(model).length !== 4 || !safeModel(model.id)
      || model.object !== 'model' || !Number.isSafeInteger(model.created) || model.created < 0
      || model.owned_by !== provider || seen.has(model.id)) throw unhealthy();
    seen.add(model.id);
    return Object.freeze({ id: model.id, object: 'model', created: model.created, owned_by: provider });
  });
  if (models.length === 0) throw failure('AUTH_REQUIRED', `Provider "${provider}" is not authenticated.`, { details: { provider } });
  return models;
}

function modelNotFound(provider, model) {
  return failure('MODEL_NOT_FOUND', `"${model}" is not available for provider "${provider}".`, {
    hint: `Run claudexctl models ${provider}.`, details: { provider, model }
  });
}

function checkedGateway(gateway) {
  if (!gateway || gateway.host !== '127.0.0.1' || !Number.isSafeInteger(gateway.port) || gateway.port < 1024 || gateway.port > 65535 || !isSecret(gateway.token)) throw unhealthy();
  return gateway;
}

function copySafeEnvironment(environment) {
  if (!environment || typeof environment !== 'object') throw safety();
  const result = {};
  const seen = new Map();
  for (const [name, value] of Object.entries(environment)) {
    const canonical = SAFE_ENVIRONMENT.get(name.toUpperCase());
    if (!canonical || typeof value !== 'string' || value.length === 0 || value.includes('\0')) continue;
    if (seen.has(canonical) && seen.get(canonical) !== value) throw safety();
    seen.set(canonical, value);
    result[canonical] = value;
  }
  return result;
}

function buildClaudeChildEnvironment({ environment, host, port, token, model } = {}) {
  if (host !== '127.0.0.1' || !Number.isSafeInteger(port) || port < 1024 || port > 65535 || !isSecret(token) || !safeModel(model)) throw safety();
  const result = copySafeEnvironment(environment);
  let bearer;
  try {
    bearer = token.withValue((bytes) => {
      if (bytes.length !== 32) throw safety();
      return Buffer.from(bytes).toString('base64url');
    });
  } catch (error) {
    if (error instanceof ClaudexError) throw error;
    throw safety();
  }
  result.ANTHROPIC_BASE_URL = `http://127.0.0.1:${port}`;
  result.ANTHROPIC_AUTH_TOKEN = bearer;
  result.CLAUDE_CODE_SUBAGENT_MODEL = model;
  result.CLAUDE_CODE_ALWAYS_ENABLE_EFFORT = '1';
  result.CLAUDE_CODE_MAX_TOOL_USE_CONCURRENCY = '3';
  result.CLAUDE_CODE_SUBPROCESS_ENV_SCRUB = '1';
  result.ENABLE_TOOL_SEARCH = 'false';
  return result;
}

export async function launchClaudeProvider({
  provider,
  parsed,
  claude,
  cwd,
  isTTY,
  baseEnvironment,
  ensureGateway = defaultEnsureGateway,
  listModels = defaultListModels,
  selectModel,
  runChild = runClaudeProcess,
  signal
} = {}) {
  if (!['codex', 'antigravity'].includes(provider) || !parsed || typeof parsed !== 'object'
    || typeof parsed.select !== 'boolean' || typeof parsed.nonInteractive !== 'boolean' || !Array.isArray(parsed.claudeArgs)) throw safety();
  if (hasModelOverride(parsed.claudeArgs)) throw failure('USAGE_ERROR', 'Claude model overrides are not allowed after the launcher delimiter.');
  if (parsed.select && parsed.nonInteractive) throw failure('INTERACTION_REQUIRED', 'Live model selection requires an interactive terminal.');
  if (parsed.model === undefined && parsed.nonInteractive) throw failure('MODEL_REQUIRED', 'A current live model is required in noninteractive mode.', { hint: `Run claudexctl models ${provider}.` });
  if (parsed.model !== undefined && !safeModel(parsed.model)) throw failure('USAGE_ERROR', 'Model identifier is invalid.');
  if (parsed.model === undefined && isTTY !== true) throw failure('INTERACTION_REQUIRED', 'Live model selection requires an interactive terminal.');
  if (!safeCwd(cwd) || typeof ensureGateway !== 'function' || typeof listModels !== 'function'
    || (parsed.model === undefined && typeof selectModel !== 'function') || typeof runChild !== 'function') throw safety();
  if (!isVerifiedExecutableForCommand(claude, 'claude') || await revalidateExecutable(claude) !== true) throw prerequisite();

  let gateway;
  try { gateway = checkedGateway(await ensureGateway()); } catch (error) { throw publicServiceFailure(error, provider); }
  let catalog;
  try { catalog = assertCatalog(await listModels(provider, gateway), provider); } catch (error) { throw publicServiceFailure(error, provider); }

  let selected = parsed.model;
  if (selected === undefined) {
    const offered = provider === 'codex' && catalog.some(({ id }) => id === PREFERRED_CODEX_MODEL)
      ? [catalog.find(({ id }) => id === PREFERRED_CODEX_MODEL), ...catalog.filter(({ id }) => id !== PREFERRED_CODEX_MODEL)]
      : [...catalog];
    try { selected = await selectModel(Object.freeze({ provider, models: Object.freeze(offered) })); }
    catch { throw safety(); }
  }
  if (!safeModel(selected) || !catalog.some(({ id }) => id === selected)) throw modelNotFound(provider, typeof selected === 'string' ? selected : 'invalid');
  if (await revalidateExecutable(claude) !== true) throw prerequisite();
  const trusted = getVerifiedInvocation(claude);
  if (!trusted) throw prerequisite();
  let env;
  try { env = buildClaudeChildEnvironment({ environment: baseEnvironment, ...gateway, model: selected }); }
  catch { throw safety(); }
  const invocation = Object.freeze({
    executablePath: trusted.executablePath,
    args: Object.freeze([
      ...trusted.argsPrefix,
      '--model', selected,
      '--fallback-model', selected,
      ...parsed.claudeArgs
    ]),
    cwd,
    env,
    shell: false,
    stdio: 'inherit',
    signal
  });
  let childResult;
  let exited;
  let signaled;
  try {
    childResult = await runChild(invocation);
    exited = childResult && Number.isSafeInteger(childResult.code) && childResult.code >= 0 && childResult.code <= 255 && childResult.signal === null;
    signaled = childResult && childResult.code === null && typeof childResult.signal === 'string' && /^SIG[A-Z0-9]+$/.test(childResult.signal);
  } catch { throw safety(); }
  finally { delete env.ANTHROPIC_AUTH_TOKEN; }
  if (!exited && !signaled) throw safety();
  return Object.freeze({ provider, model: selected, exitCode: childResult.code, signal: childResult.signal });
}

export function runClaudeProcess(invocation, { spawnProcess = spawn, parent = process } = {}) {
  return new Promise((resolve) => {
    let child;
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      parent.removeListener?.('SIGINT', onSigint);
      parent.removeListener?.('SIGTERM', onSigterm);
      invocation.signal?.removeEventListener?.('abort', onAbort);
      resolve(result);
    };
    const forward = (name) => { try { child?.kill?.(name); } catch { /* exact child result remains authoritative */ } };
    const onSigint = () => forward('SIGINT');
    const onSigterm = () => forward('SIGTERM');
    const onAbort = () => forward('SIGTERM');
    const childEnvironment = { ...invocation.env };
    try {
      child = spawnProcess(invocation.executablePath, [...invocation.args], {
        cwd: invocation.cwd,
        env: childEnvironment,
        shell: false,
        stdio: 'inherit',
        windowsHide: false
      });
    } catch {
      delete invocation.env.ANTHROPIC_AUTH_TOKEN;
      delete childEnvironment.ANTHROPIC_AUTH_TOKEN;
      finish({ code: -1, signal: null });
      return;
    }
    delete invocation.env.ANTHROPIC_AUTH_TOKEN;
    delete childEnvironment.ANTHROPIC_AUTH_TOKEN;
    parent.once?.('SIGINT', onSigint);
    parent.once?.('SIGTERM', onSigterm);
    invocation.signal?.addEventListener?.('abort', onAbort, { once: true });
    child.once('error', () => finish({ code: -1, signal: null }));
    child.once('exit', (code, childSignal) => finish({ code, signal: childSignal }));
    if (invocation.signal?.aborted) onAbort();
  });
}
