import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';

import { getVerifiedInvocation, isVerifiedExecutable, revalidateExecutable } from '../core/executable.js';

const BASELINES = Object.freeze({ cliProxy: '7.2.130', claude: '2.1.229' });
const MAX_OUTPUT_BYTES = 16_384;
const TIMEOUT_MS = 3_000;
const HARD_KILL_DELAY_MS = 100;
const CLEANUP_DEADLINE_MS = 250;

function unsupported(reason = 'CAPABILITY_UNSUPPORTED') {
  return { available: false, code: reason };
}

function available(details = {}) {
  return { available: true, code: 'AVAILABLE', ...details };
}

function decodeBounded(bytes, limit) {
  for (let length = Math.min(bytes.length, limit); length >= 0; length -= 1) {
    try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length)); } catch { /* trim incomplete or invalid trailing bytes */ }
  }
  return '';
}
function byteLength(value) {
  return Buffer.byteLength(value, 'utf8');
}

function parseVersion(output, label) {
  if (typeof output !== 'string') return null;
  const exact = new RegExp(`^${label} ((?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*))\\n$`).exec(output);
  const match = exact ?? (label === 'Claude Code'
    ? new RegExp(`^${label} ((?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*))(?:\\.\\d+)?\\s*$`, 'm').exec(output)
    : null);
  if (!match) return null;
  const parts = match[1].split('.').map(Number);
  return parts.every(Number.isSafeInteger) ? { value: match[1], parts } : null;
}

function isAtLeast(version, baseline) {
  const baselineParts = baseline.split('.').map(Number);
  for (let index = 0; index < 3; index += 1) {
    if (version.parts[index] !== baselineParts[index]) return version.parts[index] > baselineParts[index];
  }
  return true;
}

function strictJson(output) {
  if (typeof output !== 'string' || !output.endsWith('\n') || output.indexOf('\n') !== output.length - 1) return null;
  try {
    const value = JSON.parse(output);
    return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
  } catch { return null; }
}

function hasExactKeys(value, keys) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key)));
}

async function invoke(run, tool, target, args, { stdin = null, env = {} } = {}) {
  if (!isVerifiedExecutable(target) || !args.every((argument) => typeof argument === 'string') || !(typeof stdin === 'string' || stdin === null)) return null;
  try { if (await revalidateExecutable(target) !== true) return null; } catch { return null; }
  const trusted = getVerifiedInvocation(target);
  if (!trusted) return null;
  const invocation = {
    tool,
    executablePath: trusted.executablePath,
    args: [...trusted.argsPrefix, ...args],
    shell: false,
    stdin,
    env: { ...env },
    timeoutMs: TIMEOUT_MS,
    maxStdoutBytes: MAX_OUTPUT_BYTES,
    maxStderrBytes: MAX_OUTPUT_BYTES
  };
  try {
    const result = await run(invocation);
    if (!result || result.code !== 0 || typeof result.stdout !== 'string' || typeof result.stderr !== 'string') return null;
    if (byteLength(result.stdout) > MAX_OUTPUT_BYTES || byteLength(result.stderr) > MAX_OUTPUT_BYTES) return null;
    if (result.stderr !== '' && tool !== 'claude') return null;
    return result.stdout;
  } catch { return null; }
}

async function versionCapability(run, tool, target, label, baseline) {
  const output = await invoke(run, tool, target, ['--version']);
  const version = parseVersion(output, label);
  return version && isAtLeast(version, baseline) ? available({ version: version.value }) : unsupported();
}

async function jsonCapability(run, tool, target, args, validator, options) {
  const output = await invoke(run, tool, target, args, options);
  return validator(strictJson(output)) ? available() : unsupported();
}

function allAvailable(capabilities) {
  return Object.values(capabilities).every((capability) => capability.available);
}

function disabled(keys, code = 'CAPABILITY_UNSUPPORTED') {
  return Object.fromEntries(keys.map((key) => [key, unsupported(code)]));
}

export function validateAuthenticatedModelCatalog(response, { allowPreAuthEmpty = false } = {}) {
  if (!hasExactKeys(response, ['object', 'data']) || response.object !== 'list' || !Array.isArray(response.data)) return false;
  if (response.data.length === 0) return allowPreAuthEmpty === true;
  const seen = new Set();
  return response.data.every((model) => {
    if (!model || typeof model !== 'object' || Array.isArray(model) || typeof model.id !== 'string' || !model.id
      || model.object !== 'model' || typeof model.owned_by !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(model.owned_by)
      || seen.has(model.id)) return false;
    const keys = Object.keys(model);
    if (keys.some((key) => !['id', 'object', 'created', 'owned_by'].includes(key))) return false;
    if (model.created !== undefined && (!Number.isSafeInteger(model.created) || model.created < 0)) return false;
    seen.add(model.id);
    return true;
  });
}

function cursorUnavailable(code = 'CAPABILITY_UNSUPPORTED', identity = unsupported(code), version = unsupported(code)) {
  return {
    identity,
    version,
    ...disabled(['status', 'models', 'jsonPrint', 'stdin', 'askMode', 'planMode', 'sandbox'], code),
    tools: disabled(['models', 'ask', 'plan'], code)
  };
}

function advertisedTool(capabilities, names) {
  for (const name of names) {
    const capability = capabilities[name];
    if (!capability?.available) return unsupported(capability?.code === 'AUTH_REQUIRED' ? 'AUTH_REQUIRED' : 'CAPABILITY_UNSUPPORTED');
  }
  return available();
}

async function probeCursorCapabilities(cursor, { run, nonceFactory }) {
  if (!isVerifiedExecutable(cursor)) return cursorUnavailable();
  let identityOk = false;
  try { identityOk = await revalidateExecutable(cursor) === true; } catch { identityOk = false; }
  const identity = identityOk ? available() : unsupported();
  if (!identity.available) return cursorUnavailable('CAPABILITY_UNSUPPORTED', identity);
  const version = await versionCapability(run, 'cursor', cursor, 'Cursor Agent', '0.0.0');
  if (!version.available) return cursorUnavailable('CAPABILITY_UNSUPPORTED', identity, version);

  const nonce = nonceFactory();
  if (typeof nonce !== 'string' || nonce.length < 1 || nonce.length > 256 || /[\u0000-\u001f\u007f]/.test(nonce)) {
    return cursorUnavailable('CAPABILITY_UNSUPPORTED', identity, version);
  }
  const prompt = `nonce:${nonce}`;
  const statusValue = strictJson(await invoke(run, 'cursor', cursor, ['status', '--json']));
  const status = hasExactKeys(statusValue, ['authenticated']) && typeof statusValue.authenticated === 'boolean'
    ? (statusValue.authenticated ? available() : unsupported('AUTH_REQUIRED'))
    : unsupported();
  const validateModels = (value) => {
    if (!hasExactKeys(value, ['models']) || !Array.isArray(value.models)) return false;
    const seen = new Set();
    return value.models.every((model) => hasExactKeys(model, ['id']) && typeof model.id === 'string' && model.id.length > 0 && !seen.has(model.id) && (seen.add(model.id), true));
  };
  let models = await jsonCapability(run, 'cursor', cursor, ['models', '--json'], validateModels);
  if (!models.available) models = await jsonCapability(run, 'cursor', cursor, ['--list-models', '--json'], validateModels);
  const jsonPrint = await jsonCapability(run, 'cursor', cursor, ['probe', 'json', '--json'],
    (value) => hasExactKeys(value, ['type', 'capability', 'framing']) && value.type === 'probe' && value.capability === 'json' && value.framing === 'json-lines');
  const stdin = await jsonCapability(run, 'cursor', cursor, ['probe', 'stdin', '--json'],
    (value) => hasExactKeys(value, ['type', 'capability', 'echo']) && value.type === 'probe' && value.capability === 'stdin' && value.echo === prompt,
    { stdin: prompt });
  const modeValidator = (capability) => (value) => hasExactKeys(value, ['type', 'capability', 'supported'])
    && value.type === 'probe' && value.capability === capability && value.supported === true;
  const askMode = await jsonCapability(run, 'cursor', cursor, ['probe', 'mode', 'ask', '--json'], modeValidator('ask'));
  const planMode = await jsonCapability(run, 'cursor', cursor, ['probe', 'mode', 'plan', '--json'], modeValidator('plan'));
  const sandbox = await jsonCapability(run, 'cursor', cursor, ['probe', 'sandbox', 'read-only', '--json'], modeValidator('sandbox'));
  const capabilities = { identity, version, status, models, jsonPrint, stdin, askMode, planMode, sandbox };
  return {
    ...capabilities,
    tools: {
      models: advertisedTool(capabilities, ['identity', 'version', 'status', 'models']),
      ask: advertisedTool(capabilities, ['identity', 'version', 'status', 'models', 'jsonPrint', 'stdin', 'askMode', 'sandbox']),
      plan: advertisedTool(capabilities, ['identity', 'version', 'status', 'models', 'jsonPrint', 'stdin', 'planMode', 'sandbox'])
    }
  };
}

function resultEnvelope(cliProxy, claude, cursor) {
  return { ready: allAvailable(cliProxy) && allAvailable(claude), capabilities: { cliProxy, claude, cursor } };
}

export async function probeRequiredCapabilities({ cliProxy, claude, cursor, nonceFactory = randomUUID, run = runFixedCommand } = {}) {
  const cliVersion = await versionCapability(run, 'cliProxy', cliProxy, 'CLIProxyAPI', BASELINES.cliProxy);
  if (!cliVersion.available) {
    return resultEnvelope({ version: cliVersion, ...disabled(['loginCodex', 'loginAntigravity', 'config', 'help']) }, disabled(['version', 'model', 'plugin', 'mcp', 'environment']), cursor ? cursorUnavailable() : { integration: available({ required: false }) });
  }
  const cliHelp = await jsonCapability(run, 'cliProxy', cliProxy, ['--help', '--json'], (value) => hasExactKeys(value, ['commands', 'loginModes'])
    && Array.isArray(value.commands) && value.commands.length === 2 && value.commands.includes('login') && value.commands.includes('config')
    && Array.isArray(value.loginModes) && value.loginModes.length === 2 && value.loginModes.includes('codex') && value.loginModes.includes('antigravity'));
  const requiredKeys = ['host', 'port', 'tls', 'remote-management', 'auth-dir', 'api-keys', 'debug', 'commercial-mode', 'logging-to-file', 'usage-statistics-enabled', 'pprof', 'plugins', 'ws-auth'];
  const cliConfig = await jsonCapability(run, 'cliProxy', cliProxy, ['config', 'probe', '--json'], (value) => hasExactKeys(value, ['explicitConfigSelection', 'requiredKeys', 'commercialMode'])
    && value.explicitConfigSelection === true && Array.isArray(value.requiredKeys) && JSON.stringify(value.requiredKeys) === JSON.stringify(requiredKeys)
    && hasExactKeys(value.commercialMode, ['requiredValue', 'requestLoggingDisabled']) && value.commercialMode.requiredValue === true && value.commercialMode.requestLoggingDisabled === true);
  const cliCapabilities = { version: cliVersion, loginCodex: cliHelp, loginAntigravity: cliHelp, config: cliConfig, help: cliHelp };
  if (!allAvailable(cliCapabilities)) {
    return resultEnvelope(cliCapabilities, disabled(['version', 'model', 'plugin', 'mcp', 'environment']), cursor ? cursorUnavailable() : { integration: available({ required: false }) });
  }
  const claudeVersion = await versionCapability(run, 'claude', claude, 'Claude Code', BASELINES.claude);
  if (!claudeVersion.available) {
    return resultEnvelope(cliCapabilities, { version: claudeVersion, ...disabled(['model', 'plugin', 'mcp', 'environment']) }, cursor ? cursorUnavailable() : { integration: available({ required: false }) });
  }
  const claudeCapabilities = {
    version: claudeVersion,
    model: await jsonCapability(run, 'claude', claude, ['model', '--help', '--json'], (value) => hasExactKeys(value, ['modelSelection']) && value.modelSelection === true),
    plugin: await jsonCapability(run, 'claude', claude, ['plugin', '--help', '--json'], (value) => hasExactKeys(value, ['plugins']) && value.plugins === true),
    mcp: await jsonCapability(run, 'claude', claude, ['mcp', '--help', '--json'], (value) => hasExactKeys(value, ['mcp']) && value.mcp === true),
    environment: await jsonCapability(run, 'claude', claude, ['environment', '--json'], (value) => hasExactKeys(value, ['gatewayVariables'])
      && Array.isArray(value.gatewayVariables) && value.gatewayVariables.length === 2
      && value.gatewayVariables.includes('ANTHROPIC_BASE_URL') && value.gatewayVariables.includes('ANTHROPIC_AUTH_TOKEN'))
  };
  if (!allAvailable(claudeCapabilities)) {
    return resultEnvelope(cliCapabilities, claudeCapabilities, cursor ? cursorUnavailable() : { integration: available({ required: false }) });
  }
  const cursorCapabilities = cursor
    ? await probeCursorCapabilities(cursor, { run, nonceFactory })
    : { integration: available({ required: false }) };
  return resultEnvelope(cliCapabilities, claudeCapabilities, cursorCapabilities);
}

async function runTaskkill(taskkill, pid, force) {
  if (!isVerifiedExecutable(taskkill) || await revalidateExecutable(taskkill) !== true) return { acknowledged: false, error: 'TASKKILL_UNAVAILABLE' };
  const trusted = getVerifiedInvocation(taskkill);
  if (!trusted || trusted.argsPrefix.length !== 0 || !trusted.executablePath.toLowerCase().endsWith('\\taskkill.exe')) return { acknowledged: false, error: 'TASKKILL_UNAVAILABLE' };
  const systemDirectory = trusted.executablePath.slice(0, trusted.executablePath.lastIndexOf('\\'));
  const systemRoot = systemDirectory.slice(0, systemDirectory.lastIndexOf('\\'));
  const args = ['/pid', String(pid), '/t', ...(force ? ['/f'] : [])];
  return new Promise((resolve) => {
    let settled = false;
    let killer;
    let timer;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      killer?.stdout?.destroy();
      killer?.stderr?.destroy();
      killer?.unref();
      resolve(result);
    };
    try {
      killer = spawn(trusted.executablePath, args, { shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], env: { SystemRoot: systemRoot, WINDIR: systemRoot } });
    } catch { finish({ acknowledged: false, error: 'TASKKILL_FAILED' }); return; }
    let stderr = '';
    killer.stderr.on('data', (chunk) => { if (stderr.length < 1_024) stderr += chunk.toString('utf8').slice(0, 1_024 - stderr.length); });
    killer.once('error', () => finish({ acknowledged: false, error: 'TASKKILL_FAILED' }));
    killer.once('close', (code) => finish(code === 0
      ? { acknowledged: true }
      : { acknowledged: false, error: /access is denied/i.test(stderr) ? 'ACCESS_DENIED' : 'TASKKILL_FAILED' }));
    timer = setTimeout(() => { try { killer.kill('SIGKILL'); } catch { /* already exited */ } finish({ acknowledged: false, error: 'TASKKILL_TIMEOUT' }); }, HARD_KILL_DELAY_MS);
  });
}

async function defaultTreeTerminator({ pid, force, taskkill }) {
  if (!Number.isSafeInteger(pid) || pid < 1) return { acknowledged: false, error: 'INVALID_PID' };
  if (process.platform === 'win32') return runTaskkill(taskkill, pid, force);
  try {
    process.kill(-pid, force ? 'SIGKILL' : 'SIGTERM');
    return { acknowledged: true };
  } catch (error) {
    return error?.code === 'ESRCH' ? { acknowledged: true } : { acknowledged: false, error: 'SIGNAL_FAILED' };
  }
}

async function defaultTreeChecker({ pid }) {
  if (process.platform === 'win32') return false;
  try { process.kill(-pid, 0); return false; } catch (error) { return error?.code === 'ESRCH'; }
}

function waitBriefly() { return new Promise((resolve) => setTimeout(resolve, 10)); }
export function runFixedCommand({ executablePath, args, shell, stdin, env, timeoutMs, maxStdoutBytes, maxStderrBytes, signal, taskkill, treeTerminator, treeChecker = defaultTreeChecker, spawnProcess = spawn }) {
  return new Promise((resolve) => {
    if (shell !== false || typeof executablePath !== 'string' || !(/^\//.test(executablePath) || /^[A-Za-z]:\\/.test(executablePath))
      || /[\u0000-\u001f\u007f]/.test(executablePath) || !Array.isArray(args) || !args.every((argument) => typeof argument === 'string')
      || !(stdin === null || typeof stdin === 'string') || !env || typeof env !== 'object' || Array.isArray(env)
      || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || !Number.isSafeInteger(maxStdoutBytes) || maxStdoutBytes < 1
      || !Number.isSafeInteger(maxStderrBytes) || maxStderrBytes < 1 || (treeTerminator !== undefined && typeof treeTerminator !== 'function') || typeof treeChecker !== 'function' || typeof spawnProcess !== 'function') {
      resolve({ code: -1, stdout: '', stderr: 'invalid invocation', cleanupConfirmed: false, cleanupError: 'INVALID_INVOCATION' });
      return;
    }
    let child;
    try {
      child = spawnProcess(executablePath, args, { shell: false, env: { ...env }, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, detached: process.platform !== 'win32' });
    } catch {
      resolve({ code: -1, stdout: '', stderr: '', cleanupConfirmed: true });
      return;
    }
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let settled = false;
    let stopping = false;
    let closeObserved = false;
    let lastTerminationConfirmed = false;
    let mainTimer;
    let hardTimer;
    let terminalTimer;
    const finish = (code, cleanupConfirmed) => {
      if (settled) return;
      settled = true;
      clearTimeout(mainTimer);
      clearTimeout(hardTimer);
      clearTimeout(terminalTimer);
      signal?.removeEventListener('abort', stop);
      child.removeAllListeners();
      child.stdin.removeAllListeners();
      child.stdout.removeAllListeners();
      child.stderr.removeAllListeners();
      child.stdin.destroy();
      child.stdout.destroy();
      child.stderr.destroy();
      child.unref();
      resolve({
        code,
        stdout: decodeBounded(stdout, maxStdoutBytes),
        stderr: decodeBounded(stderr, maxStderrBytes),
        ...(stopping ? { cleanupConfirmed, ...(cleanupConfirmed ? {} : { cleanupError: 'CLEANUP_UNCONFIRMED' }) } : {})
      });
    };
    const maybeFinishStopped = () => {
      if (stopping && closeObserved && lastTerminationConfirmed) finish(-1, true);
    };
    const terminate = async (force) => {
      let action;
      try { action = await (treeTerminator ?? ((request) => defaultTreeTerminator({ ...request, taskkill })))({ pid: child.pid, force }); }
      catch { action = { acknowledged: false }; }
      if (action?.acknowledged === true) {
        for (let attempt = 0; attempt < 12 && !lastTerminationConfirmed; attempt += 1) {
          try { lastTerminationConfirmed = await treeChecker({ pid: child.pid }) === true; } catch { lastTerminationConfirmed = false; }
          if (!lastTerminationConfirmed) await waitBriefly();
        }
      }
      maybeFinishStopped();
      return action;
    };
    const stop = () => {
      if (stopping || settled) return;
      stopping = true;
      clearTimeout(mainTimer);
      terminalTimer = setTimeout(() => finish(-1, false), CLEANUP_DEADLINE_MS);
      void terminate(false);
      hardTimer = setTimeout(() => { if (!(lastTerminationConfirmed && closeObserved)) void terminate(true); }, HARD_KILL_DELAY_MS);
    };
    const append = (current, chunk, limit) => {
      const combined = Buffer.concat([current, chunk]);
      return { bytes: combined.subarray(0, limit), overflow: combined.length > limit };
    };
    child.stdout.on('data', (chunk) => {
      const next = append(stdout, chunk, maxStdoutBytes);
      stdout = next.bytes;
      if (next.overflow) stop();
    });
    child.stderr.on('data', (chunk) => {
      const next = append(stderr, chunk, maxStderrBytes);
      stderr = next.bytes;
      if (next.overflow) stop();
    });
    child.stdin.once('error', stop);
    child.once('error', () => stopping ? (closeObserved = true, maybeFinishStopped()) : finish(-1, true));
    child.once('close', (code) => {
      closeObserved = true;
      if (stopping) maybeFinishStopped();
      else finish(code ?? -1, true);
    });
    mainTimer = setTimeout(stop, timeoutMs);
    if (signal?.aborted) stop(); else signal?.addEventListener('abort', stop, { once: true });
    try { child.stdin.end(stdin === null ? undefined : stdin); } catch { stop(); }
  });
}

function capabilityError() {
  const error = new Error('CAPABILITY_UNSUPPORTED');
  error.code = 'CAPABILITY_UNSUPPORTED';
  return error;
}

export async function resolveCursorExecutable({ candidates, run = runFixedCommand } = {}) {
  if (!Array.isArray(candidates)) throw capabilityError();
  for (const command of ['cursor-agent', 'agent']) {
    const matches = candidates.filter((candidate) => candidate?.command === command);
    if (matches.length > 1) throw capabilityError();
    if (matches.length === 0 || !isVerifiedExecutable(matches[0].target)) continue;
    const version = await versionCapability(run, 'cursor', matches[0].target, 'Cursor Agent', '0.0.0');
    if (version.available) return matches[0].target;
  }
  throw capabilityError();
}
