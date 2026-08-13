import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const lanesPath = path.join(root, 'ci', 'node-lanes.json');
const checker = path.join(root, 'scripts', 'check-node-lanes.mjs');
const workflowPath = path.join(root, '.github', 'workflows', 'ci.yml');
const compatibilityPath = path.join(root, '.github', 'workflows', 'upstream-compatibility.yml');
const SHA_ACTION = /^\s*uses:\s+(actions\/[a-z0-9-]+)@([0-9a-f]{40})\s+#\s+v\d+\.\d+\.\d+$/gmu;
const ACTION_ALLOWLIST = new Set([
  'actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683',
  'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020',
  'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'
]);

function runChecker(args, input) {
  return spawnSync(process.execPath, [checker, ...args], { cwd: root, input, encoding: 'utf8',
    env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot } });
}

function release(version, lts) {
  return { version: `v${version}`, date: '2026-08-12', files: ['linux-x64', 'linux-arm64'], npm: '11.0.0',
    v8: '14.0.0', uv: '1.52.1', zlib: '1.3.1', openssl: '3.5.0', modules: '137', lts, security: false };
}

function assertPinnedActions(source, minimum) {
  const usesLines = source.split(/\r?\n/u).filter((line) => /^\s*uses:/u.test(line));
  const matches = [...source.matchAll(SHA_ACTION)];
  assert.equal(matches.length, usesLines.length);
  assert.ok(matches.length >= minimum);
  for (const match of matches) assert.equal(ACTION_ALLOWLIST.has(`${match[1]}@${match[2]}`), true);
}

test('checked-in Node lanes are exact, closed, dated, and independently validated', async () => {
  const lanes = JSON.parse(await fs.readFile(lanesPath, 'utf8'));
  assert.deepEqual(lanes, { floor: '22.20.0', lts: '24.19.0', current: '26.7.0', verifiedAt: '2026-08-12',
    source: 'https://nodejs.org/dist/index.json' });
  const result = runChecker(['--validate', lanesPath]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'node lanes: valid\n');
});

test('fixture index comparison accepts only exact configured LTS/current releases and rejects drift or hostile JSON', async () => {
  const valid = JSON.stringify([
    release('26.7.0', false), release('24.19.0', 'Krypton'), release('22.20.0', 'Jod'), release('24.18.9', 'Krypton')
  ]);
  let result = runChecker(['--index-stdin'], valid);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /node lanes: current/u);
  for (const fixture of [
    JSON.stringify([release('26.7.1', false), release('24.19.0', 'Krypton')]),
    JSON.stringify([release('26.7.0', false), release('24.19.1', 'Krypton')]),
    JSON.stringify([release('26.7.0', 'hostile'), release('24.19.0', false)]),
    JSON.stringify([release('27.0.0', false), release('26.7.0', false), release('24.19.0', 'Krypton')]),
    JSON.stringify([release('26.8.0', 'Lambda'), release('26.7.0', false), release('24.19.0', 'Krypton')]),
    JSON.stringify([{ ...release('26.7.0', false), extra: true }, release('24.19.0', 'Krypton')]),
    '{}', 'not-json', `${valid} trailing`
  ]) {
    result = runChecker(['--index-stdin'], fixture);
    assert.notEqual(result.status, 0, fixture);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /NODE_LANES_STALE/u);
  }
  const proposedIndex = JSON.stringify([release('26.8.0', false), release('24.20.1', 'Krypton')]);
  result = runChecker(['--propose-index-stdin', '2026-08-13'], proposedIndex);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { floor: '22.20.0', lts: '24.20.1', current: '26.8.0',
    verifiedAt: '2026-08-13', source: 'https://nodejs.org/dist/index.json' });
  const unchanged = JSON.parse(await fs.readFile(lanesPath, 'utf8'));
  assert.equal(unchanged.current, '26.7.0');
});

test('six-target CI is a blocking three-lane matrix with complete native, bootstrap, hostile, failure, and canary gates', async () => {
  const source = await fs.readFile(workflowPath, 'utf8');
  for (const token of [
    'windows-latest', 'windows-11-arm', 'macos-15-intel', 'macos-15', 'ubuntu-24.04', 'ubuntu-24.04-arm',
    "lane: [floor, lts, current]", 'fail-fast: false', 'npm.cmd run check', 'npm.cmd run test:unit',
    'npm.cmd run test:integration', 'node --test test/fixtures', 'npm run check', 'npm run test:unit',
    'npm run test:integration', 'bootstrap-windows.test.js', 'bootstrap-posix.test.js',
    'permissions-native.test.js', 'runner.test.js', 'archive-extraction.test.js', 'windows-shim.test.js',
    'CLAUDEX_SECRET_CANARY', 'powershell.exe', 'pwsh.exe', 'build-windows-shim.ps1', 'retention-days: 7'
  ]) assert.match(source, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.doesNotMatch(source, /continue-on-error\s*:\s*true/u);
  assert.doesNotMatch(source, /(?:secrets\.|pull_request_target|permissions:\s*write-all)/u);
  assert.doesNotMatch(source, /(?:steps\.[A-Za-z0-9_]*-|outputs\.[A-Za-z0-9_]*-)/u);
  for (const identifier of [...source.matchAll(/^\s+id:\s+([^\s]+)$/gmu)].map((match) => match[1])) {
    assert.match(identifier, /^[A-Za-z_][A-Za-z0-9_]*$/u);
  }
  assert.match(source, /permissions:\s*\n\s+contents:\s+read/u);
  assert.match(source, /runs-on:\s*\$\{\{ matrix\.os \}\}/u);
  const rows = [...source.matchAll(/- os: (windows-latest|windows-11-arm|macos-15-intel|macos-15|ubuntu-24\.04|ubuntu-24\.04-arm)\s+shell: (windows|posix)\s+arch: (x64|arm64)/gu)]
    .map((match) => match.slice(1));
  assert.deepEqual(rows, [
    ['windows-latest', 'windows', 'x64'], ['windows-11-arm', 'windows', 'arm64'],
    ['macos-15-intel', 'posix', 'x64'], ['macos-15', 'posix', 'arm64'],
    ['ubuntu-24.04', 'posix', 'x64'], ['ubuntu-24.04-arm', 'posix', 'arm64']
  ]);
  assert.equal(rows.length * 3, 18);
  assertPinnedActions(source, 4);
  assert.ok((source.match(/npm\.cmd run check/gu) ?? []).length >= 2);
  assert.ok((source.match(/npm run check/gu) ?? []).length >= 2);
});

test('baseline containers run natively on matching Linux architectures and remain blocking', async () => {
  const source = await fs.readFile(workflowPath, 'utf8');
  for (const image of ['ubuntu:20.04', 'debian:10']) assert.match(source, new RegExp(image.replace('.', '\\.')));
  assert.match(source, /if:\s*startsWith\(matrix\.os, 'ubuntu-'\)/u);
  assert.match(source, /docker run --rm --platform "linux\/\$\{\{ matrix\.arch == 'x64' && 'amd64' \|\| 'arm64' \}\}"/u);
  assert.match(source, /-v "\$node_root:\/opt\/node:ro"/u);
  assert.match(source, /--user "\$\(id -u\):\$\(id -g\)"/u);
  assert.match(source, /CLDX_EXPECTED_ARCH/u);
  assert.match(source, /uname -m/u);
  assert.match(source, /mkdir -m 700 "\$baseline_home"/u);
  assert.match(source, /-v "\$baseline_home:\/home\/claudex"/u);
  for (const token of ['vswhere.exe', 'Launch-VsDevShell.ps1', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', 'Microsoft.VisualStudio.Component.VC.Tools.ARM64',
    "Get-Command 'cl.exe'"]) assert.match(source, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  for (const token of ['/opt/node/bin/npm run check', '/opt/node/bin/npm run test:unit',
    '/opt/node/bin/npm run test:integration', '/opt/node/bin/node --test test/fixtures',
    'test/integration/bootstrap-posix.test.js', 'test/integration/permissions-native.test.js']) {
    assert.match(source, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
  assert.doesNotMatch(source, /qemu|buildx|continue-on-error/u);
});

test('scheduled compatibility reports lane drift without rewriting while release invocation is a blocking online gate', async () => {
  const source = await fs.readFile(compatibilityPath, 'utf8');
  for (const token of ['schedule:', 'workflow_dispatch:', 'workflow_call:',
    'node scripts/check-node-lanes.mjs --online', 'NODE_LANES_STALE', 'retention-days: 7']) {
    assert.match(source, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
  assert.match(source, /if:\s*github\.event_name == 'workflow_call'/u);
  assert.match(source, /if:\s*github\.event_name != 'workflow_call'/u);
  assert.doesNotMatch(source, /(?:git\s+(?:add|commit|push)|sed\s+-i|Set-Content|Out-File|permissions:\s*write-all|continue-on-error:\s*true)/u);
  assert.match(source, /permissions:\s*\n\s+contents:\s+read/u);
  assertPinnedActions(source, 2);
});
