import path from 'node:path';

import { getVerifiedInvocation, isVerifiedExecutable, isVerifiedExecutableForCommand, revalidateExecutable } from './executable.js';

const TRUSTED_NODE_MAJORS = new Set([22, 24, 26]);

function unavailable(code = 'PREREQUISITE_MISSING') { return { available: false, code }; }
function available(details = {}) { return { available: true, code: 'AVAILABLE', ...details }; }

function parseNodeVersion(value) {
  if (typeof value !== 'string') return null;
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(value);
  if (!match || match.slice(1).some((part) => part.length > 15)) return null;
  const [major, minor, patch] = match.slice(1).map(Number);
  return [major, minor, patch].every(Number.isSafeInteger) ? { major, minor, patch } : null;
}

function nodeCapability(nodeVersion, supportedNodeMajors) {
  const version = parseNodeVersion(nodeVersion);
  if (!version || version.major < 22 || (version.major === 22 && version.minor < 20)) return unavailable();
  if (!TRUSTED_NODE_MAJORS.has(version.major) || !Array.isArray(supportedNodeMajors) || !supportedNodeMajors.includes(version.major)) return unavailable();
  return available({ version: nodeVersion });
}

async function executableCapability(target, expectedPath) {
  if (!isVerifiedExecutable(target) || await revalidateExecutable(target) !== true) return unavailable();
  const invocation = getVerifiedInvocation(target);
  if (!invocation || invocation.argsPrefix.length !== 0) return unavailable();
  const matches = process.platform === 'win32' || /^[A-Za-z]:\\/.test(expectedPath)
    ? invocation.executablePath.toLowerCase() === expectedPath.toLowerCase()
    : invocation.executablePath === expectedPath;
  return matches ? available({ executable: target }) : unavailable();
}

async function gitCapability(target, systemAdapter) {
  if (!isVerifiedExecutableForCommand(target, 'git') || await revalidateExecutable(target) !== true
    || !systemAdapter || typeof systemAdapter.probeGitVersion !== 'function') return unavailable();
  const invocation = getVerifiedInvocation(target);
  if (!invocation || invocation.argsPrefix.length !== 0) return unavailable();
  const request = Object.freeze({
    executable: target,
    executablePath: invocation.executablePath,
    args: Object.freeze(['--version']),
    shell: false,
    timeoutMs: 3_000,
    maxStdoutBytes: 256,
    maxStderrBytes: 256
  });
  let result;
  try { result = await systemAdapter.probeGitVersion(request); } catch { return unavailable(); }
  if (!result || result.code !== 0 || result.stderr !== '' || typeof result.stdout !== 'string'
    || Buffer.byteLength(result.stdout, 'utf8') > request.maxStdoutBytes) return unavailable();
  const match = /^git version ((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:\.windows\.(?:0|[1-9]\d*))?)\n$/.exec(result.stdout);
  return match ? available({ executable: target, version: match[1] }) : unavailable();
}
export async function assessPrerequisites({
  platform,
  nodeVersion,
  supportedNodeMajors,
  tar,
  git,
  cursorWorktreeRequested = false,
  powerShell,
  taskkill,
  systemAdapter
} = {}) {
  const capabilities = { node: nodeCapability(nodeVersion, supportedNodeMajors) };
  if (platform === 'win32') {
    if (!systemAdapter || typeof systemAdapter.systemDirectory !== 'function' || typeof systemAdapter.probePowerShellVersion !== 'function') {
      capabilities.powerShell = unavailable();
      capabilities.taskkill = unavailable();
    } else {
      let systemDirectory;
      try { systemDirectory = await systemAdapter.systemDirectory(); } catch { systemDirectory = null; }
      if (typeof systemDirectory !== 'string' || !/^[A-Za-z]:\\(?:[^\\\r\n]+\\)*[^\\\r\n]+$/.test(systemDirectory)) {
        capabilities.powerShell = unavailable();
        capabilities.taskkill = unavailable();
      } else {
        const powerShellPath = path.win32.join(systemDirectory, 'WindowsPowerShell', 'v1.0', 'powershell.exe');
        const taskkillPath = path.win32.join(systemDirectory, 'taskkill.exe');
        capabilities.powerShell = await executableCapability(powerShell, powerShellPath);
        capabilities.taskkill = await executableCapability(taskkill, taskkillPath);
        if (capabilities.powerShell.available) {
          let version;
          try { version = await systemAdapter.probePowerShellVersion(powerShell); } catch { version = null; }
          const match = typeof version === 'string' && /^(\d+)\.(\d+)$/.exec(version);
          if (!match || Number(match[1]) < 5 || (Number(match[1]) === 5 && Number(match[2]) < 1)) capabilities.powerShell = unavailable();
          else capabilities.powerShell = available({ executable: powerShell, version });
        }
      }
    }
  } else {
    capabilities.tar = await executableCapability(tar, '/usr/bin/tar');
  }
  capabilities.git = cursorWorktreeRequested
    ? await gitCapability(git, systemAdapter)
    : { available: true, code: 'NOT_REQUIRED' };
  return { ready: Object.values(capabilities).every((capability) => capability.available), capabilities };
}
