import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { validateProjectReleaseManifest } from './package.mjs';

export const REQUIRED_REPORT_TARGETS = Object.freeze([
  'windows-10-1809-x64',
  'windows-11-arm64',
  'macos-13-x64',
  'macos-13-arm64',
  'wsl',
  'current-windows-x64',
  'current-windows-arm64',
  'current-darwin-x64',
  'current-darwin-arm64',
  'current-linux-x64',
  'current-linux-arm64'
]);

const MAX_REPORT_BYTES = 1024 * 1024;
const MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;
const MAX_AGE_HOURS = 168;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const REVISION = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const SAFE_TEXT = /^[^\u0000\r\n]{1,128}$/u;
const OUTCOMES = new Set(['passed', 'failed', 'unavailable', 'not-run', 'not-applicable']);
const FAILURES = new WeakSet();

const TARGET_FACTS = Object.freeze({
  'windows-10-1809-x64': Object.freeze({ osName: 'Windows 10', platform: 'win32', runtimeArch: 'x64', nativeArch: 'x64', wsl: false }),
  'windows-11-arm64': Object.freeze({ osName: 'Windows 11', platform: 'win32', runtimeArch: 'arm64', nativeArch: 'arm64', wsl: false }),
  'macos-13-x64': Object.freeze({ osName: 'macOS', platform: 'darwin', runtimeArch: 'x64', nativeArch: 'x64', wsl: false }),
  'macos-13-arm64': Object.freeze({ osName: 'macOS', platform: 'darwin', runtimeArch: 'arm64', nativeArch: 'arm64', wsl: false }),
  wsl: Object.freeze({ osName: 'WSL', platform: 'linux', wsl: true }),
  'current-windows-x64': Object.freeze({ osName: 'Windows', platform: 'win32', runtimeArch: 'x64', nativeArch: 'x64', wsl: false }),
  'current-windows-arm64': Object.freeze({ osName: 'Windows', platform: 'win32', runtimeArch: 'arm64', nativeArch: 'arm64', wsl: false }),
  'current-darwin-x64': Object.freeze({ osName: 'macOS', platform: 'darwin', runtimeArch: 'x64', nativeArch: 'x64', wsl: false }),
  'current-darwin-arm64': Object.freeze({ osName: 'macOS', platform: 'darwin', runtimeArch: 'arm64', nativeArch: 'arm64', wsl: false }),
  'current-linux-x64': Object.freeze({ osName: 'Linux', platform: 'linux', runtimeArch: 'x64', nativeArch: 'x64', wsl: false }),
  'current-linux-arm64': Object.freeze({ osName: 'Linux', platform: 'linux', runtimeArch: 'arm64', nativeArch: 'arm64', wsl: false })
});

const REPORT_KEYS = Object.freeze(['schemaVersion', 'release', 'target', 'observedAt', 'maxAgeHours', 'tools',
  'upstream', 'capabilities', 'operations', 'auth', 'inference', 'cursor', 'checkout', 'security']);
const OPERATION_KEYS = Object.freeze(['cleanBootstrap', 'repeatBootstrap', 'update', 'rollback', 'dryRunUninstall',
  'uninstall', 'repeatUninstall']);
const AUTH_KEYS = Object.freeze(['codexBrowser', 'codexDeviceCode', 'codexNoBrowser', 'antigravityBrowser',
  'antigravityNoBrowser']);
const CAPABILITY_KEYS = Object.freeze(['codexDeviceCode', 'codexNoBrowser', 'antigravityNoBrowser']);
const CURSOR_KEYS = Object.freeze(['login', 'models', 'ask', 'plan', 'approvedWorktree']);
const SECURITY_KEYS = Object.freeze(['loopbackOnly', 'bearerAuthentication', 'permissions', 'cleanup', 'canaryScan']);

function failure() {
  const error = new Error('Release validation evidence is invalid or incomplete.');
  error.code = 'VALIDATION_REPORT_INVALID';
  FAILURES.add(error);
  return error;
}

function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return (prototype === Object.prototype || prototype === null)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function digest(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function artifact(value) {
  if (!exact(value, ['name', 'sha256', 'size']) || !NAME.test(value.name) || !SHA256.test(value.sha256)
    || !Number.isSafeInteger(value.size) || value.size < 1 || value.size > MAX_ARTIFACT_BYTES) throw failure();
  return value;
}

function identity(value) {
  if (!exact(value, ['version', 'sha256']) || typeof value.version !== 'string' || !SAFE_TEXT.test(value.version)
    || !SHA256.test(value.sha256)) throw failure();
  return value;
}

function outcome(value) {
  if (!exact(value, ['outcome', 'evidenceSha256']) || !OUTCOMES.has(value.outcome)
    || !SHA256.test(value.evidenceSha256)) throw failure();
  return value;
}

function outcomeMap(value, keys) {
  if (!exact(value, keys)) throw failure();
  for (const key of keys) outcome(value[key]);
  return value;
}

function canonicalTimestamp(value) {
  if (typeof value !== 'string') throw failure();
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) throw failure();
  return timestamp;
}

function atLeast(value, floor) {
  if (!VERSION.test(value)) return false;
  const left = value.split('.').map(Number);
  const right = floor.split('.').map(Number);
  if ([...left, ...right].some((part) => !Number.isSafeInteger(part))) return false;
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] > right[index];
  }
  return true;
}

function target(value) {
  if (!exact(value, ['id', 'osName', 'osVersion', 'platform', 'runtimeArch', 'nativeArch', 'wslVersion'])
    || typeof value.id !== 'string' || !Object.hasOwn(TARGET_FACTS, value.id)
    || typeof value.osVersion !== 'string' || !SAFE_TEXT.test(value.osVersion)) throw failure();
  const expected = TARGET_FACTS[value.id];
  if (value.osName !== expected.osName || value.platform !== expected.platform
    || !['x64', 'arm64'].includes(value.runtimeArch) || !['x64', 'arm64'].includes(value.nativeArch)) throw failure();
  if (expected.wsl) {
    if (![1, 2].includes(value.wslVersion) || value.runtimeArch !== value.nativeArch) throw failure();
  } else if (value.wslVersion !== null || value.runtimeArch !== expected.runtimeArch || value.nativeArch !== expected.nativeArch) {
    throw failure();
  }
  if (value.id === 'windows-10-1809-x64' && !/^10\.0\.17763(?:\.\d+)?$/u.test(value.osVersion)) throw failure();
  if ((value.id === 'macos-13-x64' || value.id === 'macos-13-arm64') && !/^13(?:\.|$)/u.test(value.osVersion)) throw failure();
  return value;
}

function checkoutState(value) {
  if (!exact(value, ['sourceSha256', 'indexSha256', 'headRevision']) || !SHA256.test(value.sourceSha256)
    || !SHA256.test(value.indexSha256) || !REVISION.test(value.headRevision)) throw failure();
  return value;
}

function sameArtifact(left, right) {
  return left.name === right.name && left.sha256 === right.sha256 && left.size === right.size;
}

export function validateValidationReport(value) {
  try {
    if (!exact(value, REPORT_KEYS) || value.schemaVersion !== 1 || value.maxAgeHours !== MAX_AGE_HOURS) throw failure();
    if (!exact(value.release, ['tag', 'version', 'sourceRevision', 'projectManifestSha256', 'managerPayload', 'shim'])
      || !VERSION.test(value.release.version) || value.release.tag !== `v${value.release.version}`
      || !REVISION.test(value.release.sourceRevision) || !SHA256.test(value.release.projectManifestSha256)) throw failure();
    artifact(value.release.managerPayload);
    if (value.release.shim !== null) artifact(value.release.shim);
    target(value.target);
    if (value.target.platform === 'win32') {
      const expectedName = `claudey-windows-${value.target.runtimeArch}.exe`;
      if (value.release.shim === null || value.release.shim.name !== expectedName) throw failure();
    } else if (value.release.shim !== null) throw failure();
    canonicalTimestamp(value.observedAt);
    if (!exact(value.tools, ['node', 'claude', 'cursor'])) throw failure();
    identity(value.tools.node); identity(value.tools.claude); identity(value.tools.cursor);
    if (!atLeast(value.tools.node.version, '22.20.0') || !atLeast(value.tools.claude.version, '2.1.229')) throw failure();
    if (!exact(value.upstream, ['cliProxyApi'])) throw failure();
    identity(value.upstream.cliProxyApi);
    if (!atLeast(value.upstream.cliProxyApi.version, '7.2.130')) throw failure();
    if (!exact(value.capabilities, CAPABILITY_KEYS)) throw failure();
    for (const key of CAPABILITY_KEYS) {
      const capability = value.capabilities[key];
      if (!exact(capability, ['supported', 'probeSha256']) || typeof capability.supported !== 'boolean'
        || !SHA256.test(capability.probeSha256)) throw failure();
    }
    outcomeMap(value.operations, OPERATION_KEYS);
    outcomeMap(value.auth, AUTH_KEYS);
    outcomeMap(value.inference, ['claudey', 'claudeAgy']);
    outcomeMap(value.cursor, CURSOR_KEYS);
    if (!exact(value.checkout, ['before', 'after'])) throw failure();
    checkoutState(value.checkout.before); checkoutState(value.checkout.after);
    if (JSON.stringify(value.checkout.before) !== JSON.stringify(value.checkout.after)
      || value.checkout.before.headRevision !== value.release.sourceRevision) throw failure();
    outcomeMap(value.security, SECURITY_KEYS);
    return freeze(value);
  } catch (error) {
    if (FAILURES.has(error)) throw error;
    throw failure();
  }
}

function requirePassed(map, keys) {
  for (const key of keys) if (map[key].outcome !== 'passed') throw failure();
}

function expectedShim(manifest, report) {
  if (report.target.platform !== 'win32') return null;
  return manifest.shims[`windows-${report.target.runtimeArch}`];
}

export function validateReleaseReports({ manifest, manifestSha256, reports, now = new Date().toISOString() } = {}) {
  try {
    const project = validateProjectReleaseManifest(manifest);
    if (!SHA256.test(manifestSha256) || !Array.isArray(reports) || reports.length !== REQUIRED_REPORT_TARGETS.length) throw failure();
    const nowMs = canonicalTimestamp(now);
    const checked = reports.map(validateValidationReport);
    if (new Set(checked.map((report) => report.upstream.cliProxyApi.version)).size !== 1) throw failure();
    const byTarget = new Map(checked.map((report) => [report.target.id, report]));
    if (byTarget.size !== REQUIRED_REPORT_TARGETS.length
      || REQUIRED_REPORT_TARGETS.some((targetId) => !byTarget.has(targetId))) throw failure();
    for (const report of checked) {
      const observed = canonicalTimestamp(report.observedAt);
      if (observed > nowMs + MAX_FUTURE_SKEW_MS || nowMs - observed > report.maxAgeHours * 60 * 60 * 1000) throw failure();
      if (report.release.tag !== `v${project.managerVersion}` || report.release.version !== project.managerVersion
        || report.release.sourceRevision !== project.sourceRevision || report.release.projectManifestSha256 !== manifestSha256
        || !sameArtifact(report.release.managerPayload, project.payload)) throw failure();
      const shim = expectedShim(project, report);
      if (shim === null ? report.release.shim !== null : report.release.shim === null
        || shim !== null && !sameArtifact(report.release.shim, shim)) throw failure();
      requirePassed(report.operations, OPERATION_KEYS);
      requirePassed(report.auth, ['codexBrowser', 'antigravityBrowser']);
      for (const key of CAPABILITY_KEYS) {
        const expected = report.capabilities[key].supported ? 'passed' : 'not-applicable';
        if (report.auth[key].outcome !== expected) throw failure();
      }
      requirePassed(report.inference, ['claudey', 'claudeAgy']);
      requirePassed(report.cursor, CURSOR_KEYS);
      requirePassed(report.security, SECURITY_KEYS);
    }
    const result = { schemaVersion: 1, releaseTag: `v${project.managerVersion}`, releaseVersion: project.managerVersion,
      reportCount: checked.length, targets: [...REQUIRED_REPORT_TARGETS] };
    return freeze(result);
  } catch (error) {
    if (FAILURES.has(error)) throw error;
    throw failure();
  }
}

async function readRegular(targetPath) {
  const before = await fs.lstat(targetPath, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size < 2n
    || before.size > BigInt(MAX_REPORT_BYTES)) throw failure();
  const handle = await fs.open(targetPath, 'r');
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || opened.dev !== before.dev || opened.ino !== before.ino
      || opened.size !== before.size || opened.mtimeNs !== before.mtimeNs) throw failure();
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size
      || after.mtimeNs !== opened.mtimeNs || BigInt(bytes.length) !== opened.size) throw failure();
    return bytes;
  } finally { await handle.close(); }
}

function parseJson(bytes) {
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw failure(); }
}

function parse(argv) {
  let manifestPath;
  let now;
  const reports = [];
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index]; const value = argv[index + 1];
    if (typeof value !== 'string' || value.length === 0) throw failure();
    if (flag === '--manifest' && manifestPath === undefined) manifestPath = path.resolve(value);
    else if (flag === '--now' && now === undefined) now = value;
    else if (flag === '--report') reports.push(path.resolve(value));
    else throw failure();
  }
  if (!manifestPath || reports.length !== REQUIRED_REPORT_TARGETS.length || new Set(reports).size !== reports.length
    || reports.includes(manifestPath)) throw failure();
  return { manifestPath, now: now ?? new Date().toISOString(), reports };
}

async function cli(argv) {
  const options = parse(argv);
  const manifestBytes = await readRegular(options.manifestPath);
  const reports = [];
  for (const reportPath of options.reports) reports.push(parseJson(await readRegular(reportPath)));
  const result = validateReleaseReports({ manifest: parseJson(manifestBytes), manifestSha256: digest(manifestBytes),
    reports, now: options.now });
  process.stdout.write(`validation reports: valid (${result.reportCount}/${REQUIRED_REPORT_TARGETS.length})\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  cli(process.argv.slice(2)).catch(() => {
    process.stderr.write('error[VALIDATION_REPORT_INVALID]: Release validation evidence is invalid or incomplete.\n');
    process.exitCode = 7;
  });
}
