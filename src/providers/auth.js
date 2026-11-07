import { spawn } from 'node:child_process';
import path from 'node:path';

import { GATEWAY_CONFIG_CHILD } from '../core/config.js';
import { ClaudeyError } from '../core/errors.js';
import { getVerifiedInvocation, isVerifiedExecutableForCommand, revalidateExecutable } from '../core/executable.js';
import { runFixedCommand } from './capabilities.js';

const MAX_HELP_BYTES = 16_384;
const HELP_TIMEOUT_MS = 3_000;
const PRIVATE_DESCRIPTORS = new WeakMap();
const REVIEWED_AUTH_VERSION = '7.2.130';
const DEFAULT_CALLBACK_PORTS = Object.freeze({ codex: 1455, antigravity: 51121, grok: 1456 });
const REQUIRED_FLAGS = Object.freeze(['antigravity-login', 'codex-login', 'config', 'no-browser', 'oauth-callback-port']);
const KNOWN_LOGIN_FLAGS = new Set(['login', 'antigravity-login', 'claude-login', 'codex-device-login', 'codex-login', 'devin-login', 'grok-login', 'kimi-ai-login', 'kimi-login', 'meta-login', 'xai-login']);
const SAFE_ENVIRONMENT = new Map([
  ['PATH', 'PATH'], ['SYSTEMROOT', 'SystemRoot'], ['WINDIR', 'WINDIR'], ['COMSPEC', 'ComSpec'],
  ['PATHEXT', 'PATHEXT'], ['TEMP', 'TEMP'], ['TMP', 'TMP'], ['HOME', 'HOME'],
  ['USERPROFILE', 'USERPROFILE'], ['LOCALAPPDATA', 'LOCALAPPDATA'], ['APPDATA', 'APPDATA'],
  ['LANG', 'LANG'], ['LC_ALL', 'LC_ALL'], ['TERM', 'TERM']
]);

export const AUTH_WARNING = 'CLIProxyAPI is a third-party project that is not audited or endorsed by OpenAI, Anthropic, Google, or Cursor. Subscription OAuth through a proxy may have terms-of-service or account consequences.';

function authError(code, message, options) {
  return new ClaudeyError(code, message, options);
}

function unsupported() {
  return authError('CAPABILITY_UNSUPPORTED', 'The installed gateway does not expose the required authentication capability.');
}

function interactionRequired() {
  return authError('INTERACTION_REQUIRED', 'Provider authentication requires an interactive person and terminal.');
}

function authRequired() {
  return authError('AUTH_REQUIRED', 'Provider authentication did not complete successfully.');
}

function safeTextPath(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 32_767 && !/[\u0000-\u001f\u007f]/.test(value);
}

function safeManagedPaths(configPath, cwd) {
  if (!safeTextPath(configPath) || !safeTextPath(cwd)) return false;
  const windows = /^[A-Za-z]:\\/.test(configPath) || /^[A-Za-z]:\\/.test(cwd);
  if (windows) {
    if (!/^[A-Za-z]:\\/.test(configPath) || !/^[A-Za-z]:\\/.test(cwd) || configPath.includes('/') || cwd.includes('/')
      || configPath.slice(2).includes(':') || cwd.slice(2).includes(':')
      || path.win32.normalize(configPath) !== configPath || path.win32.normalize(cwd) !== cwd) return false;
    const ambiguous = (value) => value.slice(3).split('\\').some((segment) => !segment || segment === '.' || segment === '..' || /[ .]$/.test(segment));
    return !ambiguous(configPath) && !ambiguous(cwd)
      && path.win32.basename(configPath).toLowerCase() === GATEWAY_CONFIG_CHILD.toLowerCase()
      && path.win32.dirname(configPath).toLowerCase() === cwd.toLowerCase();
  }
  if (!path.posix.isAbsolute(configPath) || !path.posix.isAbsolute(cwd) || configPath.startsWith('//') || cwd.startsWith('//')
    || path.posix.normalize(configPath) !== configPath || path.posix.normalize(cwd) !== cwd) return false;
  const ambiguous = (value) => value.slice(1).split('/').some((segment) => !segment || segment === '.' || segment === '..');
  return !ambiguous(configPath) && !ambiguous(cwd) && path.posix.basename(configPath) === GATEWAY_CONFIG_CHILD
    && path.posix.dirname(configPath) === cwd;
}

function parseInstalledVersion(output) {
  if (typeof output !== 'string') throw unsupported();
  const match = /^CLIProxyAPI ((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))\n$/.exec(output)
    ?? /CLIProxyAPI Version: ((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))/u.exec(output);
  if (!match) throw unsupported();
  const parts = match[1].split('.').map(Number);
  const baseline = REVIEWED_AUTH_VERSION.split('.').map(Number);
  for (let index = 0; index < parts.length; index += 1) {
    if (parts[index] < baseline[index]) throw unsupported();
    if (parts[index] > baseline[index]) break;
  }
  return match[1];
}

function stderrIsGoFlagNoise(stderr) {
  if (stderr === '') return true;
  return stderr.replaceAll('\r\n', '\n').split('\n').filter(Boolean).every((line) => (
    /flag provided but not defined/i.test(line)
    || /^Usage of /u.test(line)
    || /^ {2}-[A-Za-z]/u.test(line)
    || /^ {4}\S/u.test(line)
  ));
}

function usableProbeResult(result) {
  if (!result || typeof result.stdout !== 'string' || typeof result.stderr !== 'string'
    || Buffer.byteLength(result.stdout, 'utf8') > MAX_HELP_BYTES
    || Buffer.byteLength(result.stderr, 'utf8') > MAX_HELP_BYTES
    || result.cleanupConfirmed === false) return false;
  if (result.code === 0 && result.stderr === '') return true;
  const combined = `${result.stdout}\n${result.stderr}`;
  if (result.code === 0 && stderrIsGoFlagNoise(result.stderr) && /Usage of |CLIProxyAPI Version:/u.test(combined)) return true;
  return result.code === 2 && /flag provided but not defined/i.test(result.stderr)
    && /CLIProxyAPI Version: |Usage of | {2}-codex-login/u.test(combined);
}

function probeText(result) {
  if (result.stderr === '') return result.stdout;
  if (result.stdout === '' || result.stdout.endsWith('\n')) return `${result.stdout}${result.stderr}`;
  return `${result.stdout}\n${result.stderr}`;
}

function parseInstalledHelp(output, version) {
  const normalized = typeof output === 'string' ? output.replaceAll('\r\n', '\n').replaceAll('\r', '\n') : output;
  if (typeof normalized !== 'string' || Buffer.byteLength(normalized, 'utf8') > MAX_HELP_BYTES || !normalized.endsWith('\n')) throw unsupported();
  output = normalized;
  const flags = new Set();
  for (const line of output.split('\n')) {
    const match = /^  -([a-z][a-z0-9-]*)(?:\s+(?:int|string))?$/.exec(line);
    if (!match) continue;
    if (flags.has(match[1])) throw unsupported();
    flags.add(match[1]);
  }
  if (!REQUIRED_FLAGS.every((flag) => flags.has(flag))) throw unsupported();
  for (const flag of flags) if (flag.endsWith('-login') && !KNOWN_LOGIN_FLAGS.has(flag)) throw unsupported();
  const providers = {
    codex: {
      browser: flags.has('codex-login'),
      deviceCode: flags.has('codex-device-login'),
      noBrowser: flags.has('no-browser'),
      callbackPort: flags.has('oauth-callback-port'),
      defaultCallbackPort: flags.has('oauth-callback-port') ? DEFAULT_CALLBACK_PORTS.codex : null
    },
    antigravity: {
      browser: flags.has('antigravity-login'),
      noBrowser: flags.has('no-browser'),
      callbackPort: flags.has('oauth-callback-port'),
      defaultCallbackPort: flags.has('oauth-callback-port') ? DEFAULT_CALLBACK_PORTS.antigravity : null
    },
    grok: {
      browser: flags.has('grok-login') || flags.has('xai-login'),
      deviceCode: flags.has('grok-login'),
      noBrowser: flags.has('no-browser') && (flags.has('grok-login') || flags.has('xai-login')),
      callbackPort: flags.has('oauth-callback-port'),
      defaultCallbackPort: flags.has('oauth-callback-port') ? DEFAULT_CALLBACK_PORTS.grok : null,
      preferGrokLogin: flags.has('grok-login')
    }
  };
  return Object.freeze({
    codex: Object.freeze(providers.codex),
    antigravity: Object.freeze(providers.antigravity),
    grok: Object.freeze(providers.grok)
  });
}

function checkedDescriptor(descriptor) {
  const facts = PRIVATE_DESCRIPTORS.get(descriptor);
  if (!facts) throw unsupported();
  return facts;
}

function buildMinimalEnvironment(environment) {
  if (!environment || typeof environment !== 'object') throw unsupported();
  const result = {};
  for (const [key, value] of Object.entries(environment)) {
    const canonical = SAFE_ENVIRONMENT.get(key.toUpperCase());
    if (canonical && typeof value === 'string' && !value.includes('\0')) result[canonical] = value;
  }
  return result;
}

function checkedPort(value) {
  return Number.isSafeInteger(value) && value >= 1024 && value <= 65535;
}

function checkedMode(provider, mode, capabilities) {
  if (provider === 'codex') {
    if (mode === 'browser' && capabilities.browser) return ['--codex-login'];
    if (mode === 'device-code' && capabilities.deviceCode) return ['--codex-device-login'];
    if (mode === 'no-browser' && capabilities.noBrowser) return ['--codex-login', '--no-browser'];
  }
  if (provider === 'antigravity') {
    if (mode === 'browser' && capabilities.browser) return ['--antigravity-login'];
    if (mode === 'no-browser' && capabilities.noBrowser) return ['--antigravity-login', '--no-browser'];
  }
  if (provider === 'grok') {
    const loginFlag = capabilities.preferGrokLogin === true ? '--grok-login' : '--xai-login';
    if (mode === 'browser' && capabilities.browser) return [loginFlag];
    if (mode === 'device-code' && capabilities.deviceCode) return ['--grok-login'];
    if (mode === 'no-browser' && capabilities.noBrowser) return [loginFlag, '--no-browser'];
  }
  if (!['codex', 'antigravity', 'grok'].includes(provider) || !['browser', 'device-code', 'no-browser'].includes(mode)) {
    throw authError('USAGE_ERROR', 'The provider authentication mode is invalid.');
  }
  throw unsupported();
}

export async function probeAuthCapabilities({ cliProxy, run = runFixedCommand } = {}) {
  if (!isVerifiedExecutableForCommand(cliProxy, 'cliproxyapi') || typeof run !== 'function') throw unsupported();
  const invokeProbe = async (name, argument) => {
    if (await revalidateExecutable(cliProxy) !== true) throw unsupported();
    const trusted = getVerifiedInvocation(cliProxy);
    if (!trusted) throw unsupported();
    let result;
    try {
      result = await run({
        tool: name,
        executablePath: trusted.executablePath,
        args: [...trusted.argsPrefix, argument],
        shell: false,
        stdin: null,
        env: {},
        timeoutMs: HELP_TIMEOUT_MS,
        maxStdoutBytes: MAX_HELP_BYTES,
        maxStderrBytes: MAX_HELP_BYTES
      });
    } catch { throw unsupported(); }
    if (!usableProbeResult(result)) throw unsupported();
    return probeText(result);
  };
  const version = parseInstalledVersion(await invokeProbe('cliProxyAuthVersion', '--version'));
  const providers = parseInstalledHelp(await invokeProbe('cliProxyAuthHelp', '--help'), version);
  const descriptor = Object.freeze({ providers });
  PRIVATE_DESCRIPTORS.set(descriptor, Object.freeze({ cliProxy, providers }));
  return descriptor;
}

export async function authenticateProvider({
  provider,
  mode = 'browser',
  callbackPort,
  nonInteractive = false,
  ci = false,
  isTTY,
  configPath,
  cwd,
  environment = {},
  capabilities,
  signal,
  inspectCallbackPort,
  warn,
  runInteractive = runInteractiveAuthProcess
} = {}) {
  if (nonInteractive === true || ci === true || isTTY !== true) throw interactionRequired();
  if (nonInteractive !== false || ci !== false) throw authError('USAGE_ERROR', 'Interactive authentication options are invalid.');
  if (!safeManagedPaths(configPath, cwd) || typeof inspectCallbackPort !== 'function'
    || typeof warn !== 'function' || typeof runInteractive !== 'function') throw authError('USAGE_ERROR', 'Authentication context is invalid.');
  if (callbackPort !== undefined && !checkedPort(callbackPort)) throw authError('USAGE_ERROR', 'Callback port must be an integer from 1024 through 65535.');
  const facts = checkedDescriptor(capabilities);
  const providerCapabilities = facts.providers[provider];
  if (!providerCapabilities) throw authError('USAGE_ERROR', 'Authentication provider is invalid.');
  const modeArgs = checkedMode(provider, mode, providerCapabilities);
  if (callbackPort !== undefined && !providerCapabilities.callbackPort) throw unsupported();

  if (mode !== 'device-code' && callbackPort === undefined && !checkedPort(providerCapabilities.defaultCallbackPort)) throw unsupported();
  const effectivePort = mode === 'device-code' ? null : (callbackPort ?? providerCapabilities.defaultCallbackPort);
  if (effectivePort !== null) {
    let ownership;
    try { ownership = await inspectCallbackPort({ host: '127.0.0.1', port: effectivePort, provider }); }
    catch { throw authError('PORT_IN_USE', 'The OAuth callback port could not be confirmed free.'); }
    if (!ownership || ownership.state !== 'free' || ownership.port !== effectivePort) {
      const pid = Number.isSafeInteger(ownership?.pid) && ownership.pid > 0 ? ownership.pid : undefined;
      throw authError('PORT_IN_USE', 'The OAuth callback port is already in use.', { details: { provider, port: effectivePort, ...(pid ? { pid } : {}) } });
    }
  }

  if (await revalidateExecutable(facts.cliProxy) !== true) throw unsupported();
  const trusted = getVerifiedInvocation(facts.cliProxy);
  if (!trusted) throw unsupported();
  const args = [...trusted.argsPrefix, '--config', configPath, ...modeArgs];
  if (callbackPort !== undefined) args.push('--oauth-callback-port', String(callbackPort));
  const invocation = Object.freeze({
    executablePath: trusted.executablePath,
    args: Object.freeze(args),
    cwd,
    env: Object.freeze(buildMinimalEnvironment(environment)),
    shell: false,
    stdio: 'inherit',
    fileModeMask: 0o077,
    signal
  });
  try { warn(AUTH_WARNING); } catch { throw authRequired(); }
  let result;
  try { result = await runInteractive(invocation); } catch { throw authRequired(); }
  const exited = result && Number.isSafeInteger(result.code) && result.code >= 0 && result.code <= 255 && result.signal === null;
  const signaled = result && result.code === null && typeof result.signal === 'string' && /^SIG[A-Z0-9]+$/.test(result.signal);
  if (!exited && !signaled) throw authRequired();
  if (result.code !== 0 || result.signal !== null) {
    return Object.freeze({ authenticated: false, provider, mode, exitCode: result.code, signal: result.signal });
  }
  return Object.freeze({ authenticated: true, provider, mode });
}

export function runInteractiveAuthProcess(invocation, {
  spawnProcess = spawn,
  parent = process,
  umask = process.umask.bind(process)
} = {}) {
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
    const forward = (name) => { try { child?.kill?.(name); } catch { /* child exit determines the public result */ } };
    const onSigint = () => forward('SIGINT');
    const onSigterm = () => forward('SIGTERM');
    const onAbort = () => forward('SIGTERM');
    let priorMask;
    try {
      priorMask = umask();
      umask(invocation.fileModeMask);
      child = spawnProcess(invocation.executablePath, [...invocation.args], {
        cwd: invocation.cwd,
        env: { ...invocation.env },
        shell: false,
        stdio: 'inherit',
        windowsHide: false
      });
    } catch {
      finish({ code: -1, signal: null });
      return;
    } finally {
      if (priorMask !== undefined) {
        try { umask(priorMask); } catch { /* a failed restore makes the runner fail through its child result */ }
      }
    }
    parent.once?.('SIGINT', onSigint);
    parent.once?.('SIGTERM', onSigterm);
    invocation.signal?.addEventListener?.('abort', onAbort, { once: true });
    child.once('error', () => finish({ code: -1, signal: null }));
    child.once('exit', (code, childSignal) => finish({ code, signal: childSignal }));
    if (invocation.signal?.aborted) onAbort();
  });
}
