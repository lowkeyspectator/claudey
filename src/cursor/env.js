import { ClaudeyError } from '../core/errors.js';

const ENVIRONMENTS = new WeakSet();
const WINDOWS = Object.freeze([
  'SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'PATH', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA',
  'LANG', 'LC_ALL', 'LC_CTYPE', 'TERM', 'COLORTERM'
]);
const POSIX = Object.freeze([
  'HOME', 'PATH', 'TMPDIR', 'USER', 'LOGNAME', 'SHELL', 'TERM', 'COLORTERM', 'LANG', 'LC_ALL', 'LC_CTYPE',
  'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'XDG_CACHE_HOME'
]);

function safety() {
  return new ClaudeyError('SAFETY_REFUSAL', 'The Cursor child environment could not be constructed safely.');
}

export function buildCursorEnvironment(parentEnvironment = {}, { platform = process.platform } = {}) {
  try {
    if (!parentEnvironment || typeof parentEnvironment !== 'object' || Array.isArray(parentEnvironment)) throw safety();
    Object.keys(parentEnvironment);
    const allowlist = platform === 'win32' || platform === 'windows' ? WINDOWS
      : platform === 'linux' || platform === 'darwin' || platform === 'macos' ? POSIX : null;
    if (!allowlist) throw safety();
    const child = {};
    for (const name of allowlist) {
      const value = parentEnvironment[name];
      if (value === undefined) continue;
      if (typeof value !== 'string' || value.length > 32_768 || value.includes('\0')) throw safety();
      child[name] = value;
    }
    Object.freeze(child);
    ENVIRONMENTS.add(child);
    return child;
  } catch { throw safety(); }
}

export function isCursorEnvironment(value) {
  return Boolean(value && typeof value === 'object' && ENVIRONMENTS.has(value));
}
