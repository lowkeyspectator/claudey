import { spawn } from 'node:child_process';

const BASELINES = Object.freeze({ cliProxy: '7.2.130', claude: '2.1.229' });
const MAX_OUTPUT_BYTES = 16_384;
const TIMEOUT_MS = 3_000;
const CURSOR_PROMPT = 'Reply with exactly OK.';

function unsupported(reason = 'CAPABILITY_UNSUPPORTED') {
  return { available: false, code: reason };
}

function available(version) {
  return { available: true, code: 'AVAILABLE', ...(version ? { version } : {}) };
}

function byteLength(value) {
  return Buffer.byteLength(value, 'utf8');
}

function parseVersion(output, label) {
  if (typeof output !== 'string') return null;
  const match = new RegExp(`^${label} ((?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*))\\n$`).exec(output);
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
  } catch {
    return null;
  }
}

function isSafeIdentity(target) {
  return Boolean(target && typeof target.executablePath === 'string' && (/^\//.test(target.executablePath) || /^[A-Za-z]:\\/.test(target.executablePath))
    && Array.isArray(target.argsPrefix) && typeof target.identity === 'string' && target.identity.length > 0);
}

async function invoke(run, tool, target, args, { stdin = null, env = {} } = {}) {
  if (!isSafeIdentity(target) || typeof target.revalidate !== 'function' || !args.every((arg) => typeof arg === 'string') || typeof stdin !== 'string' && stdin !== null) return null;
  try { if (await target.revalidate() !== true) return null; } catch { return null; }
  const invocation = {
    tool,
    executablePath: target.executablePath,
    args: [...target.argsPrefix, ...args],
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
    if (byteLength(result.stdout) > MAX_OUTPUT_BYTES || byteLength(result.stderr) > MAX_OUTPUT_BYTES || result.stderr !== '') return null;
    return result.stdout;
  } catch {
    return null;
  }
}

async function versionCapability(run, tool, target, label, baseline) {
  const output = await invoke(run, tool, target, ['--version']);
  const version = parseVersion(output, label);
  return version && isAtLeast(version, baseline) ? available(version.value) : unsupported();
}

async function jsonCapability(run, tool, target, args, validator, options) {
  const output = await invoke(run, tool, target, args, options);
  return validator(strictJson(output)) ? available() : unsupported();
}

function hasExactKeys(value, keys) {
  return value && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function allAvailable(capabilities) {
  return Object.values(capabilities).every((capability) => capability.available);
}

export function validateAuthenticatedModelCatalog(response) {
  if (!response || typeof response !== 'object' || Array.isArray(response) || Object.keys(response).length !== 1 || !Array.isArray(response.data)) return false;
  const seen = new Set();
  return response.data.every((model) => {
    if (!hasExactKeys(model, ['id', 'object', 'owned_by']) || typeof model.id !== 'string' || model.object !== 'model' || !['codex', 'antigravity'].includes(model.owned_by) || seen.has(model.id)) return false;
    seen.add(model.id);
    return true;
  });
}

function disabled(keys) {
  return Object.fromEntries(keys.map((key) => [key, unsupported()]));
}

export async function probeRequiredCapabilities({ cliProxy, claude, cursor, configPath, run = runFixedCommand } = {}) {
  const cliVersion = await versionCapability(run, 'cliProxy', cliProxy, 'CLIProxyAPI', BASELINES.cliProxy);
  if (!cliVersion.available) return { ready: false, capabilities: { cliProxy: { version: cliVersion, ...disabled(['loginCodex', 'loginAntigravity', 'config', 'help']) }, claude: disabled(['version', 'model', 'plugin', 'mcp', 'environment']), cursor: cursor ? disabled(['version', 'status', 'models', 'print']) : { integration: { available: true, code: 'NOT_REQUIRED' } } } };
  const cliHelp = await jsonCapability(run, 'cliProxy', cliProxy, ['--help', '--json'], (value) => hasExactKeys(value, ['commands', 'loginModes', 'configSelection']) && Array.isArray(value.commands) && value.commands.includes('login') && value.commands.includes('config') && Array.isArray(value.loginModes) && value.loginModes.includes('codex') && value.loginModes.includes('antigravity') && value.configSelection === true);
  const cliCapabilities = { version: cliVersion, loginCodex: cliHelp, loginAntigravity: cliHelp, config: cliHelp, help: cliHelp };
  if (!allAvailable(cliCapabilities)) return { ready: false, capabilities: { cliProxy: cliCapabilities, claude: disabled(['version', 'model', 'plugin', 'mcp', 'environment']), cursor: cursor ? disabled(['version', 'status', 'models', 'print']) : { integration: { available: true, code: 'NOT_REQUIRED' } } } };
  const claudeVersion = await versionCapability(run, 'claude', claude, 'Claude Code', BASELINES.claude);
  if (!claudeVersion.available) return { ready: false, capabilities: { cliProxy: cliCapabilities, claude: { version: claudeVersion, ...disabled(['model', 'plugin', 'mcp', 'environment']) }, cursor: cursor ? disabled(['version', 'status', 'models', 'print']) : { integration: { available: true, code: 'NOT_REQUIRED' } } } };
  const claudeCapabilities = {
    version: claudeVersion,
    model: await jsonCapability(run, 'claude', claude, ['model', '--help', '--json'], (value) => hasExactKeys(value, ['modelSelection']) && value.modelSelection === true),
    plugin: await jsonCapability(run, 'claude', claude, ['plugin', '--help', '--json'], (value) => hasExactKeys(value, ['plugins']) && value.plugins === true),
    mcp: await jsonCapability(run, 'claude', claude, ['mcp', '--help', '--json'], (value) => hasExactKeys(value, ['mcp']) && value.mcp === true),
    environment: await jsonCapability(run, 'claude', claude, ['environment', '--json'], (value) => hasExactKeys(value, ['gatewayVariables']) && Array.isArray(value.gatewayVariables) && value.gatewayVariables.length === 2 && value.gatewayVariables.includes('ANTHROPIC_BASE_URL') && value.gatewayVariables.includes('ANTHROPIC_AUTH_TOKEN'))
  };
  if (!allAvailable(claudeCapabilities)) return { ready: false, capabilities: { cliProxy: cliCapabilities, claude: claudeCapabilities, cursor: cursor ? disabled(['version', 'status', 'models', 'print']) : { integration: { available: true, code: 'NOT_REQUIRED' } } } };
  const cursorCapabilities = cursor ? {
    version: await versionCapability(run, 'cursor', cursor, 'Cursor Agent', '0.0.0'),
    status: await jsonCapability(run, 'cursor', cursor, ['status', '--json'], (value) => hasExactKeys(value, ['authenticated']) && typeof value.authenticated === 'boolean'),
    models: await jsonCapability(run, 'cursor', cursor, ['models', '--json'], (value) => hasExactKeys(value, ['models']) && Array.isArray(value.models) && value.models.every((model) => hasExactKeys(model, ['id']) && typeof model.id === 'string')),
    print: await jsonCapability(run, 'cursor', cursor, ['print', '--json', '--mode', 'ask', '--sandbox', 'read-only'], (value) => hasExactKeys(value, ['type', 'echo']) && value.type === 'result' && value.echo === CURSOR_PROMPT, { stdin: CURSOR_PROMPT })
  } : { integration: { available: true, code: 'NOT_REQUIRED' } };
  return { ready: true, capabilities: { cliProxy: cliCapabilities, claude: claudeCapabilities, cursor: cursorCapabilities } };
}
export function runFixedCommand({ executablePath, args, shell, stdin, env, timeoutMs, maxStdoutBytes, maxStderrBytes, signal }) {
  return new Promise((resolve) => {
    if (shell !== false || !isSafeIdentity({ executablePath, argsPrefix: [], identity: executablePath }) || !Array.isArray(args) || !args.every((arg) => typeof arg === 'string') || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
      resolve({ code: -1, stdout: '', stderr: 'invalid invocation' });
      return;
    }
    const child = spawn(executablePath, args, { shell: false, env: { ...env }, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, detached: process.platform !== 'win32' });
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let settled = false;
    let hardTimer;
    let terminalTimer;
    const finish = (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimer);
      clearTimeout(terminalTimer);
      signal?.removeEventListener('abort', stop);
      resolve({ code, stdout: stdout.toString('utf8'), stderr: stderr.toString('utf8') });
    };
    const killTree = (signalName) => {
      try {
        if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, signalName);
        else child.kill(signalName);
      } catch { /* child already exited */ }
    };
    const stop = () => {
      killTree('SIGTERM');
      clearTimeout(hardTimer);
      hardTimer = setTimeout(() => killTree('SIGKILL'), 100);
      clearTimeout(terminalTimer);
      terminalTimer = setTimeout(() => finish(-1), 250);
    };
    const append = (current, chunk, limit) => {
      const combined = Buffer.concat([current, chunk]);
      return { bytes: combined.subarray(0, limit), overflow: combined.length > limit };
    };
    child.stdout.on('data', (chunk) => { const next = append(stdout, chunk, maxStdoutBytes); stdout = next.bytes; if (next.overflow) stop(); });
    child.stderr.on('data', (chunk) => { const next = append(stderr, chunk, maxStderrBytes); stderr = next.bytes; if (next.overflow) stop(); });
    child.stdin.once('error', stop);
    child.once('error', () => finish(-1));
    child.once('close', (code) => finish(code ?? -1));
    terminalTimer = setTimeout(stop, timeoutMs);
    if (signal?.aborted) stop(); else signal?.addEventListener('abort', stop, { once: true });
    try { if (stdin === null) child.stdin.end(); else child.stdin.end(stdin); } catch { stop(); }
  });
}