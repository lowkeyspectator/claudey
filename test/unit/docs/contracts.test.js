import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  REQUIRED_REPORT_TARGETS,
  validateReleaseReports,
  validateValidationReport
} from '../../../scripts/e2e-validate-report.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const validator = path.join(root, 'scripts', 'e2e-validate-report.mjs');
const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);
const SHA_C = 'c'.repeat(64);
const SHA_D = 'd'.repeat(64);
const REVISION = '1'.repeat(40);
const NOW = '2026-08-13T12:00:00.000Z';

const targetFacts = Object.freeze({
  'windows-10-1809-x64': ['Windows 10', '10.0.17763', 'win32', 'x64', 'x64', null],
  'windows-11-arm64': ['Windows 11', '11.0.26100', 'win32', 'arm64', 'arm64', null],
  'macos-13-x64': ['macOS', '13.7.8', 'darwin', 'x64', 'x64', null],
  'macos-13-arm64': ['macOS', '13.7.8', 'darwin', 'arm64', 'arm64', null],
  wsl: ['WSL', 'Ubuntu 22.04', 'linux', 'x64', 'x64', 2],
  'current-windows-x64': ['Windows', '11.0.26100', 'win32', 'x64', 'x64', null],
  'current-windows-arm64': ['Windows', '11.0.26100', 'win32', 'arm64', 'arm64', null],
  'current-darwin-x64': ['macOS', '15.6', 'darwin', 'x64', 'x64', null],
  'current-darwin-arm64': ['macOS', '15.6', 'darwin', 'arm64', 'arm64', null],
  'current-linux-x64': ['Linux', 'Ubuntu 24.04', 'linux', 'x64', 'x64', null],
  'current-linux-arm64': ['Linux', 'Ubuntu 24.04', 'linux', 'arm64', 'arm64', null]
});

function artifact(name, sha256, size = 123) { return { name, sha256, size }; }
function outcome(value = 'passed') { return { outcome: value, evidenceSha256: SHA_D }; }

function manifest() {
  const payload = artifact('claudey-manager-1.2.3.tar.gz', SHA_A, 500);
  const x64 = { ...artifact('claudey-windows-x64.exe', SHA_B, 600), compiler: { name: 'MSVC', version: '19.44', flags: ['/O2'] } };
  const arm64 = { ...artifact('claudey-windows-arm64.exe', SHA_C, 700), compiler: { name: 'MSVC', version: '19.44', flags: ['/O2'] } };
  const sbom = artifact('claudey-manager-1.2.3.spdx.json', 'e'.repeat(64), 400);
  return {
    schemaVersion: 1, managerVersion: '1.2.3', sourceRevision: REVISION, managerShimCompatibilityVersion: 1,
    payload, shims: { 'windows-x64': x64, 'windows-arm64': arm64 },
    targets: {
      'windows-x64': { payload: payload.name, shim: x64.name },
      'windows-arm64': { payload: payload.name, shim: arm64.name },
      'darwin-x64': { payload: payload.name, shim: null },
      'darwin-arm64': { payload: payload.name, shim: null },
      'linux-x64': { payload: payload.name, shim: null },
      'linux-arm64': { payload: payload.name, shim: null }
    },
    sbom,
    provenanceSubjects: [payload, x64, arm64, sbom].map(({ name, sha256 }) => ({ name, sha256 }))
      .sort((left, right) => left.name.localeCompare(right.name, 'en'))
  };
}

function report(targetId, manifestSha256) {
  const [osName, osVersion, platform, runtimeArch, nativeArch, wslVersion] = targetFacts[targetId];
  const shim = platform === 'win32'
    ? (runtimeArch === 'x64' ? artifact('claudey-windows-x64.exe', SHA_B, 600) : artifact('claudey-windows-arm64.exe', SHA_C, 700))
    : null;
  const required = ['cleanBootstrap', 'repeatBootstrap', 'update', 'rollback', 'dryRunUninstall', 'uninstall', 'repeatUninstall'];
  const auth = ['codexBrowser', 'codexDeviceCode', 'codexNoBrowser', 'antigravityBrowser', 'antigravityNoBrowser'];
  const security = ['loopbackOnly', 'bearerAuthentication', 'permissions', 'cleanup', 'canaryScan'];
  return {
    schemaVersion: 1,
    release: {
      tag: 'v1.2.3', version: '1.2.3', sourceRevision: REVISION, projectManifestSha256: manifestSha256,
      managerPayload: artifact('claudey-manager-1.2.3.tar.gz', SHA_A, 500), shim
    },
    target: { id: targetId, osName, osVersion, platform, runtimeArch, nativeArch, wslVersion },
    observedAt: '2026-08-13T10:00:00.000Z',
    maxAgeHours: 168,
    tools: {
      node: { version: '24.19.0', sha256: '2'.repeat(64) },
      claude: { version: '2.1.229', sha256: '3'.repeat(64) },
      cursor: { version: '2026.08', sha256: '4'.repeat(64) }
    },
    upstream: { cliProxyApi: { version: '7.2.130', sha256: '5'.repeat(64) } },
    capabilities: {
      codexDeviceCode: { supported: true, probeSha256: '6'.repeat(64) },
      codexNoBrowser: { supported: true, probeSha256: '7'.repeat(64) },
      antigravityNoBrowser: { supported: true, probeSha256: '8'.repeat(64) }
    },
    operations: Object.fromEntries(required.map((name) => [name, outcome()])),
    auth: Object.fromEntries(auth.map((name) => [name, outcome()])),
    inference: { claudey: outcome(), claudeAgy: outcome() },
    cursor: { login: outcome(), models: outcome(), ask: outcome(), plan: outcome(), approvedWorktree: outcome() },
    checkout: {
      before: { sourceSha256: '9'.repeat(64), indexSha256: '0'.repeat(64), headRevision: REVISION },
      after: { sourceSha256: '9'.repeat(64), indexSha256: '0'.repeat(64), headRevision: REVISION }
    },
    security: Object.fromEntries(security.map((name) => [name, outcome()]))
  };
}

function clone(value) { return structuredClone(value); }

test('operations documentation contains every public command, supported target asset, and mandatory warning', async () => {
  const paths = ['README.md', 'docs/security.md', 'docs/troubleshooting.md', 'SECURITY.md',
    'docs/validation/README.md', 'docs/validation/release-smoke-checklist.md'];
  const documents = Object.fromEntries(await Promise.all(paths.map(async (name) => [name, await fs.readFile(path.join(root, name), 'utf8')])));
  const readme = documents['README.md'];
  for (const command of [
    './install.sh [--version VERSION] [--yes] [--no-path] [--rollback-manager]',
    '.\\install.ps1 [-Version VERSION] [-Yes] [-NoPath] [-RollbackManager]',
    'claudey onboard [--yes]',
    'claudey setup [--version VERSION] [--port PORT] [--with-cursor] [--no-start] [--no-path] [--yes]',
    'claudey install [--version VERSION] [--port PORT] [--yes]',
    'claudey auth codex [--device-code | --no-browser] [--callback-port PORT]',
    'claudey auth antigravity [--no-browser] [--callback-port PORT]',
    'claudey auth grok [--device-code | --no-browser] [--callback-port PORT]',
    'claudey auth all [options]',
    'claudey start [--foreground]', 'claudey stop', 'claudey restart', 'claudey status [--json]',
    'claudey update [--check | --version VERSION] [--yes]', 'claudey rollback [--version VERSION] [--yes]',
    'claudey models [codex | antigravity | grok | cursor | all] [--json]', 'claudey doctor [--json]',
    'claudey config set port PORT [--yes]', 'claudey cursor enable [--scope user | local]',
    'claudey cursor disable [--scope user | local]', 'claudey cursor install [--yes]',
    'claudey cursor login', 'claudey cursor repo add [PATH]', 'claudey cursor repo list',
    'claudey cursor repo remove [PATH]', 'claudey cursor writes enable --yes',
    'claudey cursor writes disable', 'claudey cursor approve APPROVAL_ID',
    'claudey uninstall [--dry-run] [--purge-auth] [--yes]',
    'claudey [--model MODEL | --select | --yolo] [-- CLAUDE_ARGS...]',
    'claude-codex [--model MODEL | --select | --all | --yolo] [-- CLAUDE_ARGS...]',
    'claude-agy [--model MODEL | --select | --yolo] [-- CLAUDE_ARGS...]',
    'claude-grok [--model MODEL | --select | --yolo] [-- CLAUDE_ARGS...]'
  ]) assert.ok(readme.includes(command), command);
  for (const row of [
    'Windows x64 | Windows 10 1809 | `win32/x64` | `_windows_amd64.zip`',
    'Windows ARM64 | Windows 10 1809 ARM64 | `win32/arm64` | `_windows_aarch64.zip`',
    'macOS Intel | macOS 13 | `darwin/x64` | `_darwin_amd64.tar.gz`',
    'macOS Apple silicon | macOS 13 | `darwin/arm64` | `_darwin_aarch64.tar.gz`',
    'Linux x64 | Ubuntu 20.04+/Debian 10+ glibc | `linux/x64` | `_linux_amd64.tar.gz`',
    'Linux ARM64 | Ubuntu 20.04+/Debian 10+ glibc | `linux/arm64` | `_linux_aarch64.tar.gz`',
    'WSL 1/2 | supported glibc distribution | Linux architecture | matching Linux suffix'
  ]) assert.ok(readme.includes(row), row);
  const all = Object.values(documents).join('\n').toLowerCase();
  for (const warning of [
    'normal `claude` remains isolated', 'explicit oauth', 'explicit cursor installation', 'provider terms',
    'third-party', '127.0.0.1', 'bearer', 'checksum', 'provenance', 'same-user process is not a sandbox',
    'wsl is a separate installation', 'port collision', 'execution policy', 'upstream drift',
    'dynamic entitlements', 'redaction', 'recovery', 'rollback', 'uninstall'
  ]) assert.ok(all.includes(warning), warning);
  assert.match(documents['SECURITY.md'], /PRIVATE_REPORTING_NOT_VERIFIED/u);
  assert.match(documents['SECURITY.md'], /publication is blocked/iu);
  assert.doesNotMatch(documents['SECURITY.md'], /security\/advisories\/new/u);
});

test('validation report schema is closed and the validator deeply freezes exact target evidence', async () => {
  const schema = JSON.parse(await fs.readFile(path.join(root, 'schemas', 'validation-report.schema.json'), 'utf8'));
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(REQUIRED_REPORT_TARGETS, Object.keys(targetFacts));
  const rawManifest = Buffer.from(`${JSON.stringify(manifest())}\n`);
  const digest = crypto.createHash('sha256').update(rawManifest).digest('hex');
  const value = validateValidationReport(report('windows-10-1809-x64', digest));
  assert.equal(Object.isFrozen(value), true);
  assert.equal(Object.isFrozen(value.release.managerPayload), true);
  assert.equal(Object.isFrozen(value.operations), true);
  for (const mutation of [
    (candidate) => { candidate.extra = true; },
    (candidate) => { candidate.release.extra = true; },
    (candidate) => { candidate.target.platform = 'linux'; },
    (candidate) => { candidate.release.shim.name = 'claudey-windows-arm64.exe'; },
    (candidate) => { candidate.maxAgeHours = 169; },
    (candidate) => { candidate.tools.node.version = '22.19.0'; },
    (candidate) => { candidate.tools.claude.version = '2.1.228'; },
    (candidate) => { candidate.upstream.cliProxyApi.version = '7.2.129'; },
    (candidate) => { candidate.checkout.after.headRevision = '2'.repeat(40); }
  ]) {
    const hostile = report('windows-10-1809-x64', digest); mutation(hostile);
    assert.throws(() => validateValidationReport(hostile), { code: 'VALIDATION_REPORT_INVALID' });
  }
});

test('release validation requires all distinct targets, freshness, manifest bindings, clean checkout, and passed evidence', () => {
  const project = manifest();
  const bytes = Buffer.from(`${JSON.stringify(project)}\n`);
  const manifestSha256 = crypto.createHash('sha256').update(bytes).digest('hex');
  const reports = REQUIRED_REPORT_TARGETS.map((target) => report(target, manifestSha256));
  const result = validateReleaseReports({ manifest: project, manifestSha256, reports, now: NOW });
  assert.deepEqual(result, { schemaVersion: 1, releaseTag: 'v1.2.3', releaseVersion: '1.2.3', reportCount: 11,
    targets: [...REQUIRED_REPORT_TARGETS] });
  assert.equal(Object.isFrozen(result), true);
  const failures = [
    reports.slice(1),
    [...reports.slice(0, -1), clone(reports[0])],
    reports.map((item, index) => index === 0 ? { ...clone(item), observedAt: '2026-08-01T00:00:00.000Z' } : item),
    reports.map((item, index) => index === 0 ? { ...clone(item), observedAt: '2026-08-13T12:06:00.000Z' } : item),
    reports.map((item, index) => index === 0 ? { ...clone(item), release: { ...item.release, tag: 'v1.2.4' } } : item),
    reports.map((item, index) => index === 0 ? { ...clone(item), release: { ...item.release,
      managerPayload: { ...item.release.managerPayload, sha256: SHA_B } } } : item),
    reports.map((item, index) => index === 0 ? { ...clone(item), upstream: { cliProxyApi: {
      ...item.upstream.cliProxyApi, version: '7.3.0' } } } : item),
    reports.map((item, index) => index === 0 ? { ...clone(item), operations: { ...item.operations, update: outcome('failed') } } : item),
    reports.map((item, index) => index === 0 ? { ...clone(item), auth: { ...item.auth, codexBrowser: outcome('not-run') } } : item),
    reports.map((item, index) => index === 0 ? { ...clone(item), inference: { ...item.inference, claudeAgy: outcome('unavailable') } } : item),
    reports.map((item, index) => index === 0 ? { ...clone(item), cursor: { ...item.cursor, ask: outcome('unavailable') } } : item),
    reports.map((item, index) => index === 0 ? { ...clone(item), security: { ...item.security, canaryScan: outcome('not-run') } } : item)
  ];
  for (const hostile of failures) assert.throws(() => validateReleaseReports({ manifest: project, manifestSha256,
    reports: hostile, now: NOW }), { code: 'VALIDATION_REPORT_INVALID' });
});

test('not-applicable is accepted only for an optional auth mode disproved by its installed capability probe', () => {
  const project = manifest();
  const manifestSha256 = crypto.createHash('sha256').update(`${JSON.stringify(project)}\n`).digest('hex');
  const optional = REQUIRED_REPORT_TARGETS.map((target) => report(target, manifestSha256));
  optional[0].capabilities.codexDeviceCode.supported = false;
  optional[0].auth.codexDeviceCode = outcome('not-applicable');
  assert.doesNotThrow(() => validateReleaseReports({ manifest: project, manifestSha256, reports: optional, now: NOW }));
  const falselySkipped = REQUIRED_REPORT_TARGETS.map((target) => report(target, manifestSha256));
  falselySkipped[0].auth.codexDeviceCode = outcome('not-applicable');
  assert.throws(() => validateReleaseReports({ manifest: project, manifestSha256, reports: falselySkipped, now: NOW }),
    { code: 'VALIDATION_REPORT_INVALID' });
  const unavailable = REQUIRED_REPORT_TARGETS.map((target) => report(target, manifestSha256));
  unavailable[0].capabilities.codexDeviceCode.supported = false;
  unavailable[0].auth.codexDeviceCode = outcome('unavailable');
  assert.throws(() => validateReleaseReports({ manifest: project, manifestSha256, reports: unavailable, now: NOW }),
    { code: 'VALIDATION_REPORT_INVALID' });
});

test('CLI validates only bounded regular report files and emits a sanitized result', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'claudey-validation-report-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const project = manifest();
  const manifestBytes = Buffer.from(`${JSON.stringify(project)}\n`);
  const manifestSha256 = crypto.createHash('sha256').update(manifestBytes).digest('hex');
  const manifestPath = path.join(directory, 'project-manifest.json');
  await fs.writeFile(manifestPath, manifestBytes, { flag: 'wx' });
  const paths = [];
  for (const target of REQUIRED_REPORT_TARGETS) {
    const reportPath = path.join(directory, `${target}.json`);
    await fs.writeFile(reportPath, `${JSON.stringify(report(target, manifestSha256))}\n`, { flag: 'wx' });
    paths.push(reportPath);
  }
  const args = ['--manifest', manifestPath, '--now', NOW, ...paths.flatMap((item) => ['--report', item])];
  let result = spawnSync(process.execPath, [validator, ...args], { cwd: root, encoding: 'utf8',
    env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot } });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'validation reports: valid (11/11)\n');
  assert.equal(result.stderr, '');
  const hostile = JSON.parse(await fs.readFile(paths[0], 'utf8'));
  hostile.security.canaryScan = outcome('failed');
  await fs.writeFile(paths[0], `${JSON.stringify(hostile)}\n`);
  result = spawnSync(process.execPath, [validator, ...args], { cwd: root, encoding: 'utf8',
    env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot } });
  assert.equal(result.status, 7);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, 'error[VALIDATION_REPORT_INVALID]: Release validation evidence is invalid or incomplete.\n');
  assert.doesNotMatch(result.stderr, /failed|canary|windows/iu);
  await fs.writeFile(paths[0], `${JSON.stringify(report(REQUIRED_REPORT_TARGETS[0], manifestSha256))}\n`);
  const hardlink = path.join(directory, 'report-hardlink.json');
  await fs.link(paths[0], hardlink);
  result = spawnSync(process.execPath, [validator, ...args], { cwd: root, encoding: 'utf8',
    env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot } });
  assert.equal(result.status, 7);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, 'error[VALIDATION_REPORT_INVALID]: Release validation evidence is invalid or incomplete.\n');
});
