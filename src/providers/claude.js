import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

import { ClaudeyError } from '../core/errors.js';
import { getVerifiedInvocation, isVerifiedExecutableForCommand, revalidateExecutable } from '../core/executable.js';
import { isSecret } from '../core/secrets.js';
import { GATEWAY_PROVIDERS, resolveMixedCatalogModel, sameModelId, visibleModelId } from './catalog.js';
import { listProviderModels } from './models.js';
import { requestGatewayModels } from '../core/gateway-client.js';
import { startPickerGateway } from './picker-gateway.js';
import { attachUsage, collectProviderUsage, formatUsageLine } from './usage.js';

async function defaultEnsureGateway() {
  throw failure('NOT_INSTALLED', 'Claudey is not installed.', { hint: 'Run claudey setup.' });
}

async function defaultListModels(provider, gateway) {
  return listProviderModels(provider, {
    ...gateway,
    ensureHealthy: async () => ({ state: 'healthy' }),
    requestModels: requestGatewayModels
  });
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
  return new ClaudeyError(code, message, options);
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
      hint: `Run claudey auth ${provider}.`, details: { provider }
    });
  }
  if (code === 'NOT_INSTALLED') return failure('NOT_INSTALLED', 'Claudey is not installed.', { hint: 'Run claudey setup.' });
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
    if (!model || typeof model !== 'object' || !safeModel(model.id)
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
    hint: `Run claudey models ${provider}.`, details: { provider, model }
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

const UTILITY_MODEL = /auto-review|embedding|whisper|tts|dall-e|moderation|transcribe|image|realtime|search/i;
const START_RANK = [
  /grok-4\.5/, /grok-4(?!.*mini)/, /gpt-5\.6-sol/, /gpt-5\.6/, /gpt-5(?!.*mini)/,
  /gemini-3\.(?:5|1).*pro/, /gemini-3.*pro/, /gemini-3.*flash/, /composer/
];

function isUtilityModel(id) {
  return UTILITY_MODEL.test(id);
}

function pickerModels(catalog) {
  const coding = catalog.filter((model) => !isUtilityModel(model.id));
  return coding.length > 0 ? coding : [...catalog];
}

function rankPickerModels(catalog) {
  return [...pickerModels(catalog)].sort((left, right) => {
    const leftRank = START_RANK.findIndex((pattern) => pattern.test(left.id));
    const rightRank = START_RANK.findIndex((pattern) => pattern.test(right.id));
    const leftScore = leftRank === -1 ? START_RANK.length : leftRank;
    const rightScore = rightRank === -1 ? START_RANK.length : rightRank;
    if (leftScore !== rightScore) return leftScore - rightScore;
    return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
  });
}

function resolveCatalogModel(catalog, requested) {
  return catalog.find((model) => sameModelId(model.id, requested)) ?? null;
}

function routedVisibleId(model) {
  return visibleModelId(model.owned_by, model.id);
}

async function writePickerSettings(directory, { selected }) {
  if (typeof directory !== 'string' || directory.length < 2 || /[\u0000-\u001f\u007f]/.test(directory)) throw safety();
  const model = routedVisibleId(selected);
  if (!safeModel(model)) throw safety();
  const settingsPath = path.join(directory, 'settings.json');
  let theme;
  try {
    const parsed = JSON.parse(await fs.readFile(settingsPath, 'utf8'));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && typeof parsed.theme === 'string' && parsed.theme.length > 0) {
      theme = parsed.theme;
    }
  } catch { /* missing or invalid session settings are replaced */ }
  const payload = `${JSON.stringify({
    model,
    env: {
      CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY: '1'
    },
    ...(theme ? { theme } : {})
  }, null, 2)}\n`;
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await fs.writeFile(settingsPath, payload, { mode: 0o600 });
  await fs.rm(path.join(directory, 'cache', 'gateway-models.json'), { force: true });
}

function buildClaudeChildEnvironment({ environment, host, port, token, model, aliases, pinSubagent = true, pickerMode = false } = {}) {
  if (host !== '127.0.0.1' || !Number.isSafeInteger(port) || port < 1024 || port > 65535 || !isSecret(token) || !safeModel(model)) throw safety();
  const result = copySafeEnvironment(environment);
  let bearer;
  try {
    bearer = token.withValue((bytes) => {
      if (bytes.length !== 32) throw safety();
      return Buffer.from(bytes).toString('base64url');
    });
  } catch (error) {
    if (error instanceof ClaudeyError) throw error;
    throw safety();
  }
  result.ANTHROPIC_BASE_URL = `http://127.0.0.1:${port}`;
  result.ANTHROPIC_AUTH_TOKEN = bearer;
  result.ANTHROPIC_MODEL = model;
  if (!pickerMode) {
    const pinned = aliases ?? { haiku: model, sonnet: model, opus: model, fable: model };
    if (![pinned.haiku, pinned.sonnet, pinned.opus, pinned.fable].every(safeModel)) throw safety();
    result.ANTHROPIC_DEFAULT_HAIKU_MODEL = pinned.haiku;
    result.ANTHROPIC_DEFAULT_SONNET_MODEL = pinned.sonnet;
    result.ANTHROPIC_DEFAULT_OPUS_MODEL = pinned.opus;
    result.ANTHROPIC_DEFAULT_FABLE_MODEL = pinned.fable;
    result.ANTHROPIC_DEFAULT_HAIKU_MODEL_NAME = pinned.haikuName ?? pinned.haiku;
    result.ANTHROPIC_DEFAULT_SONNET_MODEL_NAME = pinned.sonnetName ?? pinned.sonnet;
    result.ANTHROPIC_DEFAULT_OPUS_MODEL_NAME = pinned.opusName ?? pinned.opus;
    result.ANTHROPIC_DEFAULT_FABLE_MODEL_NAME = pinned.fableName ?? pinned.fable;
    result.ANTHROPIC_CUSTOM_MODEL_OPTION = model;
    result.ANTHROPIC_CUSTOM_MODEL_OPTION_NAME = pinned.customName ?? model;
    if (pinSubagent) result.CLAUDE_CODE_SUBAGENT_MODEL = model;
  }
  if (typeof aliases?.configDir === 'string' && aliases.configDir.length > 0) result.CLAUDE_CONFIG_DIR = aliases.configDir;
  result.CLAUDE_CODE_ALWAYS_ENABLE_EFFORT = '1';
  result.CLAUDE_CODE_MAX_TOOL_USE_CONCURRENCY = '3';
  result.CLAUDE_CODE_SUBPROCESS_ENV_SCRUB = '1';
  if (pickerMode) result.CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY = '1';
  else result.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1';
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
  announce,
  sessionSettingsDir,
  sessionAuthDir,
  startPicker = startPickerGateway,
  signal
} = {}) {
  const mixed = parsed?.all === true;
  if (!['codex', 'antigravity', 'grok'].includes(provider) || !parsed || typeof parsed !== 'object'
    || typeof parsed.select !== 'boolean' || typeof parsed.nonInteractive !== 'boolean' || !Array.isArray(parsed.claudeArgs)
    || (parsed.all !== undefined && typeof parsed.all !== 'boolean')) throw safety();
  if (hasModelOverride(parsed.claudeArgs)) throw failure('USAGE_ERROR', 'Claude model overrides are not allowed after the launcher delimiter.');
  if (parsed.select && parsed.nonInteractive) throw failure('INTERACTION_REQUIRED', 'Live model selection requires an interactive terminal.');
  if (parsed.model === undefined && parsed.nonInteractive) throw failure('MODEL_REQUIRED', 'A current live model is required in noninteractive mode.', { hint: mixed ? 'Run claudey models all.' : `Run claudey models ${provider}.` });
  if (parsed.model !== undefined && !safeModel(parsed.model)) throw failure('USAGE_ERROR', 'Model identifier is invalid.');
  if (parsed.model === undefined && isTTY !== true) throw failure('INTERACTION_REQUIRED', 'Live model selection requires an interactive terminal.');
  if (!safeCwd(cwd) || typeof ensureGateway !== 'function' || typeof listModels !== 'function'
    || (parsed.model === undefined && typeof selectModel !== 'function') || typeof runChild !== 'function') throw safety();
  if (!isVerifiedExecutableForCommand(claude, 'claude') || await revalidateExecutable(claude) !== true) throw prerequisite();

  let gateway;
  try { gateway = checkedGateway(await ensureGateway()); } catch (error) { throw publicServiceFailure(error, provider); }
  const byProvider = new Map();
  let catalog;
  if (mixed) {
    const merged = [];
    const seen = new Set();
    for (const name of GATEWAY_PROVIDERS) {
      try {
        const models = assertCatalog(await listModels(name, gateway), name);
        byProvider.set(name, models);
        for (const model of models) {
          const key = `${model.owned_by}\0${model.id}`;
          if (seen.has(key)) continue;
          seen.add(key);
          merged.push(model);
        }
      } catch (error) {
        if (error?.code !== 'AUTH_REQUIRED') throw publicServiceFailure(error, name);
      }
    }
    if (merged.length === 0) {
      throw failure('AUTH_REQUIRED', 'No requested provider is authenticated.', { hint: 'Run claudey auth codex, claudey auth antigravity, or claudey auth grok.' });
    }
    catalog = merged;
  } else {
    try { catalog = assertCatalog(await listModels(provider, gateway), provider); }
    catch (error) { throw publicServiceFailure(error, provider); }
    byProvider.set(provider, catalog);
  }

  let selected = parsed.model;
  if (selected === undefined) {
    const preferred = mixed
      ? rankPickerModels(catalog)
      : provider === 'codex' && catalog.some(({ id }) => id === PREFERRED_CODEX_MODEL)
        ? [catalog.find(({ id }) => id === PREFERRED_CODEX_MODEL), ...catalog.filter(({ id }) => id !== PREFERRED_CODEX_MODEL)]
        : [...catalog];
    try { selected = await selectModel(Object.freeze({ provider: mixed ? 'all' : provider, models: Object.freeze(preferred) })); }
    catch { throw safety(); }
  }
  const matched = typeof selected === 'string'
    ? (mixed ? resolveMixedCatalogModel(catalog, selected) : resolveCatalogModel(catalog, selected))
    : null;
  if (!safeModel(selected) || !matched) {
    throw modelNotFound(mixed ? 'all' : provider, typeof selected === 'string' ? selected : 'invalid');
  }
  selected = matched.id;
  if (await revalidateExecutable(claude) !== true) throw prerequisite();
  const trusted = getVerifiedInvocation(claude);
  if (!trusted) throw prerequisite();
  let decorated = catalog;
  if (mixed) {
    try {
      const collected = await collectProviderUsage({ authDir: sessionAuthDir });
      decorated = attachUsage({ models: catalog }, collected).models;
    } catch { decorated = catalog; }
  }
  let picker;
  let aliases;
  const routed = mixed ? routedVisibleId(matched) : selected;
  if (mixed) {
    if (typeof startPicker !== 'function') throw safety();
    try { picker = await startPicker({ ...gateway, models: pickerModels(decorated) }); }
    catch { throw safety(); }
    const configDir = typeof sessionSettingsDir === 'string' ? sessionSettingsDir : undefined;
    if (configDir) {
      try { await writePickerSettings(configDir, { selected: matched }); }
      catch {
        try { await picker.close(); } catch { /* picker close cannot own launch */ }
        throw safety();
      }
    }
    aliases = Object.freeze({ configDir });
  }
  let env;
  try {
    env = buildClaudeChildEnvironment({
      environment: baseEnvironment,
      host: gateway.host,
      port: picker?.port ?? gateway.port,
      token: gateway.token,
      model: routed,
      aliases,
      pinSubagent: !mixed,
      pickerMode: mixed
    });
  } catch {
    try { await picker?.close(); } catch { /* picker close cannot own launch */ }
    throw safety();
  }
  if (mixed && typeof announce === 'function') {
    const lines = ['All live models. Open /model to switch.'];
    for (const name of GATEWAY_PROVIDERS) {
      const models = decorated.filter((model) => model.owned_by === name);
      if (models.length === 0) continue;
      lines.push(`${name}:`);
      for (const model of models) lines.push(`  ${formatUsageLine(model)}`);
    }
    try { announce(lines.join('\n')); } catch { /* announcement cannot own launch */ }
  }
  const invocation = Object.freeze({
    executablePath: trusted.executablePath,
    args: Object.freeze([
      ...trusted.argsPrefix,
      '--model', routed,
      '--fallback-model', routed,
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
  finally {
    delete env.ANTHROPIC_AUTH_TOKEN;
    try { await picker?.close(); } catch { /* picker lifetime cannot own the child result */ }
  }
  if (!exited && !signaled) throw safety();
  const owner = matched.owned_by;
  return Object.freeze({ provider: mixed ? owner : provider, model: selected, exitCode: childResult.code, signal: childResult.signal });
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
