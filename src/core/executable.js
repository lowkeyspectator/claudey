import { ClaudexError } from './errors.js';

const KNOWN_NPM_ENTRIES = Object.freeze({ claude: '@anthropic-ai\\claude-code\\cli.js' });

function refusal(message) {
  throw new ClaudexError('PREREQUISITE_MISSING', message);
}

function isAbsolute(path, platform) {
  return typeof path === 'string' && (platform === 'win32'
    ? /^[A-Za-z]:\\(?:[^\\]+\\)*[^\\]+$/.test(path) && !path.includes('\\..\\') && !path.includes('\\.\\')
    : /^\/(?:[^/]+\/)*[^/]+$/.test(path) && !path.includes('/../') && !path.includes('/./'));
}

function isSafeNative(candidate, platform) {
  return Boolean(candidate && candidate.type === 'native' && candidate.isLink === false
    && candidate.path === candidate.canonicalPath && isAbsolute(candidate.path, platform)
    && (platform !== 'win32' || candidate.path.toLowerCase().endsWith('.exe')));
}

function resolveNpmShim(command, candidate, platform) {
  const knownEntry = KNOWN_NPM_ENTRIES[command];
  if (platform !== 'win32' || !knownEntry || !candidate || candidate.type !== 'npm-shim') refusal('Executable shim is not supported');
  if (candidate.isLink !== false || candidate.path !== candidate.canonicalPath || !isAbsolute(candidate.path, platform)) refusal('Executable shim identity is unsafe');
  if (!isSafeNative(candidate.node, platform) || !isAbsolute(candidate.entryPath, platform)) refusal('Node identity is unsafe');
  const shimDirectory = candidate.canonicalPath.slice(0, candidate.canonicalPath.lastIndexOf('\\'));
  const nodeDirectory = candidate.node.canonicalPath.slice(0, candidate.node.canonicalPath.lastIndexOf('\\'));
  const expectedEntry = `${shimDirectory}\\node_modules\\${knownEntry}`;
  const expectedScript = `@ECHO off\r\n"%~dp0\\node.exe" "%~dp0\\node_modules\\${knownEntry}" %*\r\n`;
  if (nodeDirectory !== shimDirectory || candidate.entryPath !== expectedEntry || candidate.script !== expectedScript) refusal('Executable shim has an unsafe shape');
  return { kind: 'node-entry', executablePath: candidate.node.canonicalPath, argsPrefix: [candidate.entryPath], identity: `${candidate.node.canonicalPath}\u0000${candidate.entryPath}` };
}

export function resolveVerifiedExecutable({ command, platform, candidates, expectedIdentity } = {}) {
  if (typeof command !== 'string' || !Array.isArray(candidates) || candidates.length === 0) refusal('Executable candidate is required');
  const nativeCandidates = candidates.filter((candidate) => candidate?.type === 'native');
  if (nativeCandidates.length > 1 || nativeCandidates.some((candidate) => !isSafeNative(candidate, platform))) refusal('Executable identity is ambiguous or unsafe');
  const result = nativeCandidates.length === 1
    ? { kind: 'native', executablePath: nativeCandidates[0].canonicalPath, argsPrefix: [], identity: nativeCandidates[0].canonicalPath }
    : candidates.length === 1 ? resolveNpmShim(command, candidates[0], platform) : refusal('Executable identity is ambiguous or unsafe');
  if (expectedIdentity !== undefined && result.identity !== expectedIdentity) throw new ClaudexError('PROCESS_IDENTITY_MISMATCH', 'Executable identity changed');
  return result;
}
