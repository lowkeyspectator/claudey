import path from 'node:path';

import { ClaudeyError } from './errors.js';

function safetyRefusal(message) {
  return new ClaudeyError('SAFETY_REFUSAL', message);
}

function unsupported(message) {
  return new ClaudeyError('PLATFORM_UNSUPPORTED', message);
}

function flag(inspection, name) {
  const value = inspection?.[name];
  return typeof value === 'function' ? value.call(inspection) === true : value === true;
}

function inspectRoot(root, safety) {
  if (typeof safety.inspectPath !== 'function') return;
  const inspection = safety.inspectPath(root);
  if (flag(inspection, 'isSymbolicLink') || flag(inspection, 'isLink') || flag(inspection, 'isReparsePoint')) {
    throw safetyRefusal('Managed roots cannot resolve through links or reparse points.');
  }
}

function canonicalRoot(root, pathApi, label, safety, { wsl = false } = {}) {
  if (typeof root !== 'string' || root.length === 0 || root.includes('\0') || root.includes('\r') || root.includes('\n')) {
    throw safetyRefusal(`${label} must be a nonempty safe absolute path.`);
  }
  if (!pathApi.isAbsolute(root)) throw safetyRefusal(`${label} must be an absolute path.`);
  if (pathApi === path.win32 && root.startsWith('\\\\')) throw safetyRefusal(`${label} cannot be a UNC path.`);

  if (wsl && !Array.isArray(safety.mountTable)) {
    throw safetyRefusal('WSL managed roots require authoritative mount metadata.');
  }

  const normalized = pathApi.normalize(root);
  if (normalized === pathApi.parse(normalized).root) throw safetyRefusal(`${label} cannot be a filesystem root.`);
  inspectRoot(normalized, safety);

  const canonical = typeof safety.canonicalize === 'function' ? safety.canonicalize(normalized) : normalized;
  if (typeof canonical !== 'string' || !pathApi.isAbsolute(canonical)) {
    throw safetyRefusal(`${label} could not be canonicalized safely.`);
  }
  const canonicalNormalized = pathApi.normalize(canonical);
  inspectRoot(canonicalNormalized, safety);
  if (wsl && isWindowsDriveMount(canonicalNormalized, safety.mountTable)) {
    throw safetyRefusal('WSL managed roots cannot use mounted Windows paths.');
  }
  return canonicalNormalized;
}

function isWindowsDriveMount(value, mountTable = []) {
  if (/^\/mnt\/[a-z](?:\/|$)/iu.test(value)) return true;
  for (const entry of mountTable) {
    const mountPoint = typeof entry === 'string' ? entry : entry?.mountPoint;
    const source = typeof entry === 'object' && entry !== null ? `${entry.source ?? entry.device ?? ''}` : '';
    const windowsDrive = entry?.isWindowsDrive === true || entry?.type === 'windows-drive' || /^[a-z]:/iu.test(source);
    if (!windowsDrive || typeof mountPoint !== 'string' || !path.posix.isAbsolute(mountPoint)) continue;
    const normalizedMount = path.posix.normalize(mountPoint);
    if (value === normalizedMount || value.startsWith(`${normalizedMount}/`)) return true;
  }
  return false;
}

function familyOf(platform) {
  const value = typeof platform === 'string'
    ? platform
    : platform?.family ?? platform?.runtimePlatform ?? platform?.platform;
  if (value === 'windows' || value === 'win32') return 'windows';
  if (value === 'macos' || value === 'darwin') return 'macos';
  if (value === 'linux') return 'linux';
  throw unsupported('Managed paths are unavailable for this platform.');
}

function windowsPaths(env, safety) {
  const localAppData = canonicalRoot(env.LOCALAPPDATA, path.win32, 'LOCALAPPDATA', safety);
  const appData = canonicalRoot(env.APPDATA, path.win32, 'APPDATA', safety);
  const managerRoot = path.win32.join(localAppData, 'claudey');
  const configRoot = path.win32.join(appData, 'claudey');
  return {
    managerRoot,
    releaseRoot: path.win32.join(managerRoot, 'releases'),
    launcherRoot: path.win32.join(managerRoot, 'launchers'),
    stateRoot: path.win32.join(managerRoot, 'state'),
    userBinRoot: path.win32.join(managerRoot, 'bin'),
    configRoot,
    authRoot: path.win32.join(configRoot, 'auth')
  };
}

function posixHome(env, safety, wsl) {
  return canonicalRoot(env.HOME, path.posix, 'HOME', safety, { wsl });
}

function macosPaths(env, safety) {
  const home = posixHome(env, safety, false);
  const managerRoot = path.posix.join(home, 'Library', 'Application Support', 'claudey');
  return {
    managerRoot,
    releaseRoot: path.posix.join(managerRoot, 'releases'),
    launcherRoot: path.posix.join(managerRoot, 'launchers'),
    configRoot: managerRoot,
    authRoot: path.posix.join(managerRoot, 'auth'),
    stateRoot: path.posix.join(managerRoot, 'state'),
    userBinRoot: path.posix.join(home, '.local', 'bin')
  };
}

function xdgRoot(env, key, fallback, safety, wsl) {
  const provided = env[key];
  const root = provided === undefined || provided === '' ? fallback : provided;
  return canonicalRoot(root, path.posix, key, safety, { wsl });
}

function linuxPaths(platform, env, safety) {
  const wsl = platform?.isWsl === true;
  const home = posixHome(env, safety, wsl);
  const dataRoot = xdgRoot(env, 'XDG_DATA_HOME', path.posix.join(home, '.local', 'share'), safety, wsl);
  const configBase = xdgRoot(env, 'XDG_CONFIG_HOME', path.posix.join(home, '.config'), safety, wsl);
  const stateBase = xdgRoot(env, 'XDG_STATE_HOME', path.posix.join(home, '.local', 'state'), safety, wsl);
  const managerRoot = path.posix.join(dataRoot, 'claudey');
  const configRoot = path.posix.join(configBase, 'claudey');
  return {
    managerRoot,
    releaseRoot: path.posix.join(managerRoot, 'releases'),
    launcherRoot: path.posix.join(managerRoot, 'launchers'),
    configRoot,
    authRoot: path.posix.join(configRoot, 'auth'),
    stateRoot: path.posix.join(stateBase, 'claudey'),
    userBinRoot: path.posix.join(home, '.local', 'bin')
  };
}

export function getManagedPaths(platform, env = {}, safety = {}) {
  const family = familyOf(platform);
  if (family === 'windows') return windowsPaths(env, safety);
  if (family === 'macos') return macosPaths(env, safety);
  return linuxPaths(platform, env, safety);
}
