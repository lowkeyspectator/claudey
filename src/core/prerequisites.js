const WINDOWS_POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const TRUSTED_NODE_MAJORS = new Set([22, 24, 26]);

function unavailable(code = 'PREREQUISITE_MISSING') {
  return { available: false, code };
}

function available(details = {}) {
  return { available: true, code: 'AVAILABLE', ...details };
}

function isVerifiedIdentity(identity, expectedPath) {
  return Boolean(
    identity
    && identity.path === expectedPath
    && identity.canonicalPath === expectedPath
    && identity.isLink === false
  );
}

function parseNodeVersion(value) {
  if (typeof value !== 'string') return null;
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(value);
  if (!match || match.some((part) => part.length > 15)) return null;
  const [major, minor, patch] = match.slice(1).map(Number);
  if (![major, minor, patch].every(Number.isSafeInteger)) return null;
  return { major, minor, patch };
}

function nodeCapability(nodeVersion, supportedNodeMajors) {
  const version = parseNodeVersion(nodeVersion);
  if (!version || version.major < 22 || (version.major === 22 && (version.minor < 20 || (version.minor === 20 && version.patch < 0)))) {
    return unavailable();
  }
  if (!TRUSTED_NODE_MAJORS.has(version.major) || !Array.isArray(supportedNodeMajors) || !supportedNodeMajors.includes(version.major)) return unavailable();
  return available({ version: nodeVersion });
}

function powerShellCapability(powerShell) {
  if (!isVerifiedIdentity(powerShell, WINDOWS_POWERSHELL)) return unavailable();
  const { response } = powerShell;
  if (!response || typeof response !== 'object' || Array.isArray(response)) return unavailable();
  if (Object.keys(response).length !== 3 || response.schemaVersion !== 1 || response.ok !== true) return unavailable();
  if (!response.result || typeof response.result !== 'object' || Array.isArray(response.result)) return unavailable();
  if (Object.keys(response.result).length !== 1 || typeof response.result.version !== 'string' || !/^\d+\.\d+$/.test(response.result.version)) return unavailable();
  const [major, minor] = response.result.version.split('.').map(Number);
  if (!Number.isSafeInteger(major) || !Number.isSafeInteger(minor) || major < 5 || (major === 5 && minor < 1)) return unavailable();
  return available({ version: response.result.version });
}

export function assessPrerequisites({
  platform,
  nodeVersion,
  supportedNodeMajors,
  tar,
  git,
  cursorWorktreeRequested = false,
  powerShell
} = {}) {
  const capabilities = { node: nodeCapability(nodeVersion, supportedNodeMajors) };

  if (platform === 'win32') {
    capabilities.powerShell = powerShellCapability(powerShell);
  } else {
    capabilities.tar = isVerifiedIdentity(tar, '/usr/bin/tar') ? available() : unavailable();
  }

  const gitIsAbsolute = platform === 'win32' ? (value) => /^[A-Za-z]:\\/.test(value) : (value) => typeof value === 'string' && value.startsWith('/');
  capabilities.git = cursorWorktreeRequested
    ? (git && gitIsAbsolute(git.path) && git.canonicalPath === git.path && git.isLink === false ? available() : unavailable())
    : { available: true, code: 'NOT_REQUIRED' };

  return {
    ready: Object.values(capabilities).every((capability) => capability.available),
    capabilities
  };
}
