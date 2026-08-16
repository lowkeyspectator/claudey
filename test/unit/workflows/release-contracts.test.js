import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { buildSpdxDocument } from '../../../scripts/sbom.mjs';
import {
  buildReleaseChecksums,
  verifyAttestationResults,
  verifyReleaseArtifacts,
  verifyShimDescriptor
} from '../../../scripts/verify-release-artifacts.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const workflowPath = path.join(root, '.github', 'workflows', 'release.yml');
const verifierPath = path.join(root, 'scripts', 'verify-release-artifacts.mjs');
const REVISION = '1'.repeat(40);
const ACTIONS = new Set([
  'actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683',
  'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020',
  'actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f',
  'actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0',
  'actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d'
]);

function hash(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function artifact(name, bytes) { return { name, sha256: hash(bytes), size: bytes.length }; }

function fixture() {
  const payloadBytes = Buffer.from('payload');
  const x64Bytes = Buffer.from('x64 shim');
  const arm64Bytes = Buffer.from('arm64 shim');
  const installSh = Buffer.from('#!/bin/sh\nset -eu\n');
  const installPs1 = Buffer.from("Set-StrictMode -Version Latest\r\n");
  const sbom = buildSpdxDocument({ managerVersion: '1.2.3', sourceRevision: REVISION,
    inventory: [{ path: 'bin/claudeyctl.js', sha256: 'a'.repeat(64), size: 10, mode: 0o755 }] });
  const payload = artifact('claudey-manager-1.2.3.tar.gz', payloadBytes);
  const x64 = { ...artifact('claudey-windows-x64.exe', x64Bytes),
    compiler: { name: 'MSVC', version: '19.44', flags: ['/O2'] } };
  const arm64 = { ...artifact('claudey-windows-arm64.exe', arm64Bytes),
    compiler: { name: 'MSVC', version: '19.44', flags: ['/O2'] } };
  const sbomArtifact = artifact('claudey-manager-1.2.3.spdx.json', sbom.bytes);
  const manifest = {
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
    sbom: sbomArtifact,
    provenanceSubjects: [payload, x64, arm64, sbomArtifact].map(({ name, sha256 }) => ({ name, sha256 }))
      .sort((left, right) => left.name.localeCompare(right.name, 'en'))
  };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest)}\n`);
  const artifacts = new Map([
    [payload.name, payloadBytes], [x64.name, x64Bytes], [arm64.name, arm64Bytes],
    [sbomArtifact.name, sbom.bytes], ['install.sh', installSh], ['install.ps1', installPs1],
    ['project-manifest.json', manifestBytes]
  ]);
  return { manifest, manifestBytes, artifacts };
}

function attestationResult(subjects) {
  return Buffer.from(`${JSON.stringify([{
    attestation: { bundle: true },
    verificationResult: {
      signature: { certificate: { subjectAlternativeName: 'release.yml' } },
      verifiedTimestamps: [{ type: 'transparency-log' }],
      statement: { predicateType: 'https://slsa.dev/provenance/v1', subject: subjects }
    }
  }])}\n`);
}

function actionUses(source) {
  return [...source.matchAll(/^\s*uses:\s+(actions\/[a-z0-9-]+)@([0-9a-f]{40})\s+#\s+v\d+\.\d+\.\d+$/gmu)]
    .map((match) => `${match[1]}@${match[2]}`);
}

test('release workflow is a blocking artifact-consuming DAG and publishes only after every required gate', async () => {
  const source = await fs.readFile(workflowPath, 'utf8');
  for (const token of [
    'workflow_dispatch:', 'release_tag:', 'validation_run_id:', "github.ref_type == 'tag'",
    'node-lane-freshness:', 'uses: ./.github/workflows/upstream-compatibility.yml',
    'build-windows-shims:', 'test-matrix:', 'package-release:', 'redownload-rehash:', 'bootstrap-smoke:',
    'validation-reports:', 'provenance:', 'publish:', 'scripts/build-windows-shim.ps1',
    'scripts/assemble-release-manifest.mjs', 'scripts/verify-release-artifacts.mjs',
    'scripts/e2e-validate-report.mjs', 'PRIVATE_REPORTING_NOT_VERIFIED', 'subject-checksums:',
    'gh attestation verify', '--source-digest "$GITHUB_SHA"', '--source-ref "$GITHUB_REF"',
    '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"', 'gh release create',
    'retention-days: 7', 'overwrite: false', 'CLAUDEY_SECRET_CANARY'
  ]) assert.ok(source.includes(token), token);
  for (const osName of ['windows-latest', 'windows-11-arm', 'macos-15-intel', 'macos-15', 'ubuntu-24.04', 'ubuntu-24.04-arm']) {
    assert.ok(source.includes(osName), osName);
  }
  assert.match(source, /lane:\s*\[floor, lts, current\]/u);
  assert.match(source, /os:\s*\[windows-latest, windows-11-arm, macos-15-intel, macos-15, ubuntu-24\.04, ubuntu-24\.04-arm\]/u);
  assert.match(source, /publish:\s*\n\s+needs:\s*\[[^\]]*provenance[^\]]*validation-reports[^\]]*bootstrap-smoke[^\]]*redownload-rehash[^\]]*test-matrix[^\]]*build-windows-shims[^\]]*node-lane-freshness[^\]]*release-context[^\]]*\]/u);
  assert.equal((source.match(/--report validation-reports\//gu) ?? []).length, 11);
  assert.equal((source.match(/uses:\s+actions\/upload-artifact@/gu) ?? []).length, 3);
  assert.equal((source.match(/retention-days:\s+7/gu) ?? []).length, 3);
  assert.equal((source.match(/overwrite:\s+false/gu) ?? []).length, 3);
  assert.doesNotMatch(source, /(?:pull_request_target|continue-on-error:\s*true|secrets\.|node-version-file:|if:\s*always\(\)|needs\.[A-Za-z0-9_]*-|outputs\.[A-Za-z0-9_]*-)/u);
  assert.match(source, /repository:\s*\$\{\{ github\.repository \}\}[\s\S]*run-id:\s*\$\{\{ inputs\.validation_run_id \}\}/u);
  const usesLines = source.split(/\r?\n/u).filter((line) => /^\s*uses:\s+actions\//u.test(line));
  const uses = actionUses(source);
  assert.equal(uses.length, usesLines.length);
  assert.ok(uses.length >= 12);
  for (const value of uses) assert.equal(ACTIONS.has(value), true, value);
});

test('release workflow keeps write permissions confined to provenance and publish jobs', async () => {
  const source = await fs.readFile(workflowPath, 'utf8');
  assert.match(source, /^permissions:\s*\n\s+contents:\s+read\s*\n\s+actions:\s+read/mu);
  assert.equal((source.match(/contents:\s+write/gu) ?? []).length, 1);
  assert.equal((source.match(/id-token:\s+write/gu) ?? []).length, 1);
  assert.equal((source.match(/attestations:\s+write/gu) ?? []).length, 1);
  assert.match(source, /provenance:[\s\S]*?permissions:\s*\n\s+contents:\s+read\s*\n\s+actions:\s+read\s*\n\s+id-token:\s+write\s*\n\s+attestations:\s+write/u);
  assert.match(source, /publish:[\s\S]*?permissions:\s*\n\s+contents:\s+write\s*\n\s+actions:\s+read\s*\n\s+attestations:\s+read/u);
});

test('checksums bind the exact manifest, payload, SBOM, shims, and bootstrap scripts', () => {
  const value = fixture();
  const checksums = buildReleaseChecksums({ manifestBytes: value.manifestBytes, artifacts: value.artifacts });
  const names = checksums.toString('utf8').trim().split('\n').map((line) => line.slice(66));
  assert.deepEqual(names, [...value.artifacts.keys()].sort((left, right) => left.localeCompare(right, 'en')));
  const verified = verifyReleaseArtifacts({ manifestBytes: value.manifestBytes, artifacts: value.artifacts,
    checksumsBytes: checksums });
  assert.deepEqual(verified, { schemaVersion: 1, managerVersion: '1.2.3', sourceRevision: REVISION,
    subjects: names.map((name) => ({ name, sha256: hash(value.artifacts.get(name)) })) });
  assert.equal(Object.isFrozen(verified), true);
  for (const mutation of [
    (f) => f.artifacts.set(f.manifest.payload.name, Buffer.from('changed')),
    (f) => f.artifacts.set(f.manifest.sbom.name, Buffer.from('{}')),
    (f) => f.artifacts.delete('install.ps1'),
    (f) => f.artifacts.set('foreign.bin', Buffer.from('foreign')),
    (f) => { f.manifest.provenanceSubjects[0].sha256 = 'f'.repeat(64); f.manifestBytes = Buffer.from(`${JSON.stringify(f.manifest)}\n`); f.artifacts.set('project-manifest.json', f.manifestBytes); }
  ]) {
    const hostile = fixture(); mutation(hostile);
    assert.throws(() => verifyReleaseArtifacts({ manifestBytes: hostile.manifestBytes, artifacts: hostile.artifacts,
      checksumsBytes: checksums }), { code: 'RELEASE_ARTIFACT_INVALID' });
  }
});

test('actual attestation verification output must cover every exact checksum subject', () => {
  const value = fixture();
  const checksums = buildReleaseChecksums({ manifestBytes: value.manifestBytes, artifacts: value.artifacts });
  const subjects = [...value.artifacts].map(([name, bytes]) => ({ name, digest: { sha256: hash(bytes) } }))
    .sort((left, right) => left.name.localeCompare(right.name, 'en'));
  const results = new Map([...value.artifacts].map(([name]) => [name, attestationResult(subjects)]));
  assert.doesNotThrow(() => verifyAttestationResults({ manifestBytes: value.manifestBytes, artifacts: value.artifacts,
    checksumsBytes: checksums, results }));
  for (const mutation of [
    (map) => map.delete('install.sh'),
    (map) => map.set('install.sh', attestationResult(subjects.map((subject) => subject.name === 'install.sh'
      ? { name: subject.name, digest: { sha256: 'f'.repeat(64) } } : subject))),
    (map) => map.set('install.sh', Buffer.from('[]\n')),
    (map) => map.set('install.sh', Buffer.from(JSON.stringify([{
      attestation: { bundle: true }, verificationResult: { signature: { certificate: {} }, verifiedTimestamps: [],
        statement: { predicateType: 'https://slsa.dev/provenance/v1', subject: subjects } }
    }]))),
    (map) => map.set('foreign.bin', attestationResult(subjects))
  ]) {
    const hostile = new Map(results); mutation(hostile);
    assert.throws(() => verifyAttestationResults({ manifestBytes: value.manifestBytes, artifacts: value.artifacts,
      checksumsBytes: checksums, results: hostile }), { code: 'RELEASE_ARTIFACT_INVALID' });
  }
});

test('native shim descriptors are bound to real bytes, target, source revision, compiler, and compatibility', () => {
  const bytes = Buffer.from('shim');
  const descriptor = {
    schemaVersion: 1, target: 'windows-x64', sourceRevision: REVISION, name: 'claudey-windows-x64.exe',
    sha256: hash(bytes), size: bytes.length, managerShimCompatibilityVersion: 1,
    compiler: { name: 'MSVC', version: '19.44', flags: ['/O2', '/guard:cf'] }
  };
  const result = verifyShimDescriptor({ descriptor, bytes, target: 'windows-x64', sourceRevision: REVISION });
  assert.equal(Object.isFrozen(result), true);
  for (const mutation of [
    (value) => { value.sha256 = 'f'.repeat(64); },
    (value) => { value.target = 'windows-arm64'; },
    (value) => { value.sourceRevision = '2'.repeat(40); },
    (value) => { value.compiler.flags = []; },
    (value) => { value.extra = true; }
  ]) {
    const hostile = structuredClone(descriptor); mutation(hostile);
    assert.throws(() => verifyShimDescriptor({ descriptor: hostile, bytes, target: 'windows-x64',
      sourceRevision: REVISION }), { code: 'RELEASE_ARTIFACT_INVALID' });
  }
});

test('verifier CLI writes once, re-reads regular files, and fails with one sanitized error', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'claudey-release-verify-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const value = fixture();
  for (const [name, bytes] of value.artifacts) await fs.writeFile(path.join(directory, name), bytes, { flag: 'wx' });
  const checksumPath = path.join(directory, 'SHA256SUMS');
  let child = spawnSync(process.execPath, [verifierPath, '--write-checksums', '--artifacts', directory,
    '--manifest', path.join(directory, 'project-manifest.json'), '--out', checksumPath], { cwd: root, encoding: 'utf8' });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, '');
  child = spawnSync(process.execPath, [verifierPath, '--verify', '--artifacts', directory,
    '--manifest', path.join(directory, 'project-manifest.json'), '--checksums', checksumPath], { cwd: root, encoding: 'utf8' });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, 'release artifacts: valid (7 subjects)\n');
  await fs.writeFile(path.join(directory, value.manifest.payload.name), 'tampered');
  child = spawnSync(process.execPath, [verifierPath, '--verify', '--artifacts', directory,
    '--manifest', path.join(directory, 'project-manifest.json'), '--checksums', checksumPath], { cwd: root, encoding: 'utf8' });
  assert.equal(child.status, 7);
  assert.equal(child.stdout, '');
  assert.equal(child.stderr, 'error[RELEASE_ARTIFACT_INVALID]: Release artifacts or provenance are invalid.\n');
  assert.doesNotMatch(child.stderr, /tampered|payload|manager/iu);
});
