import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { validateProjectReleaseManifest } from './package.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;
const REVISION = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u;
const MAX_METADATA_BYTES = 1024 * 1024;
const MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;
const FAILURE_SET = new WeakSet();

function failure() {
  const error = new Error('Release artifacts or provenance are invalid.');
  error.code = 'RELEASE_ARTIFACT_INVALID';
  FAILURE_SET.add(error);
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

function hash(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function parseJson(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 2 || bytes.length > MAX_METADATA_BYTES) throw failure();
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw failure(); }
}

function expectedNames(manifest) {
  const names = [manifest.payload.name, manifest.sbom.name, manifest.shims['windows-x64'].name,
    manifest.shims['windows-arm64'].name, 'install.sh', 'install.ps1', 'project-manifest.json'];
  if (new Set(names).size !== names.length || names.some((name) => !NAME.test(name))) throw failure();
  return names.sort((left, right) => left.localeCompare(right, 'en'));
}

function validateSbom(bytes, manifest) {
  const value = parseJson(bytes);
  if (!exact(value, ['spdxVersion', 'dataLicense', 'SPDXID', 'name', 'documentNamespace', 'creationInfo',
    'packages', 'files', 'relationships']) || value.spdxVersion !== 'SPDX-2.3' || value.dataLicense !== 'CC0-1.0'
    || value.SPDXID !== 'SPDXRef-DOCUMENT' || value.name !== `claudey-manager-${manifest.managerVersion}`
    || value.documentNamespace !== `https://github.com/ramsaijanapana/claudey/spdx/${manifest.managerVersion}/${manifest.sourceRevision}`
    || !Array.isArray(value.packages) || value.packages.length !== 1
    || value.packages[0]?.name !== 'claudey-manager' || value.packages[0]?.versionInfo !== manifest.managerVersion
    || !Array.isArray(value.files) || value.files.length < 1 || !Array.isArray(value.relationships)
    || value.relationships.length !== value.files.length + 1) throw failure();
}

function inspect({ manifestBytes, artifacts }) {
  if (!(manifestBytes instanceof Uint8Array) || manifestBytes.length < 2 || manifestBytes.length > MAX_METADATA_BYTES
    || !(artifacts instanceof Map)) throw failure();
  let manifest;
  try { manifest = validateProjectReleaseManifest(parseJson(manifestBytes)); } catch { throw failure(); }
  const names = expectedNames(manifest);
  if (artifacts.size !== names.length || names.some((name) => !artifacts.has(name))) throw failure();
  const manifestArtifact = artifacts.get('project-manifest.json');
  if (!(manifestArtifact instanceof Uint8Array) || !Buffer.from(manifestArtifact).equals(Buffer.from(manifestBytes))) throw failure();
  const descriptorByName = new Map([
    [manifest.payload.name, manifest.payload],
    [manifest.sbom.name, manifest.sbom],
    [manifest.shims['windows-x64'].name, manifest.shims['windows-x64']],
    [manifest.shims['windows-arm64'].name, manifest.shims['windows-arm64']]
  ]);
  const subjects = [];
  for (const name of names) {
    const value = artifacts.get(name);
    if (!(value instanceof Uint8Array) || value.length < 1 || value.length > MAX_ARTIFACT_BYTES) throw failure();
    const sha256 = hash(value);
    const descriptor = descriptorByName.get(name);
    if (descriptor && (descriptor.sha256 !== sha256 || descriptor.size !== value.length)) throw failure();
    subjects.push({ name, sha256 });
  }
  validateSbom(artifacts.get(manifest.sbom.name), manifest);
  const manifestSubjects = new Map(manifest.provenanceSubjects.map(({ name, sha256 }) => [name, sha256]));
  if (manifestSubjects.size !== 4 || [...manifestSubjects].some(([name, sha256]) => !artifacts.has(name)
    || hash(artifacts.get(name)) !== sha256)) throw failure();
  return { manifest, names, subjects };
}

export function buildReleaseChecksums({ manifestBytes, artifacts } = {}) {
  try {
    const checked = inspect({ manifestBytes, artifacts });
    return Buffer.from(`${checked.subjects.map(({ name, sha256 }) => `${sha256}  ${name}`).join('\n')}\n`, 'utf8');
  } catch (error) {
    if (FAILURE_SET.has(error)) throw error;
    throw failure();
  }
}

export function verifyReleaseArtifacts({ manifestBytes, artifacts, checksumsBytes } = {}) {
  try {
    const checked = inspect({ manifestBytes, artifacts });
    const expected = buildReleaseChecksums({ manifestBytes, artifacts });
    if (!(checksumsBytes instanceof Uint8Array) || checksumsBytes.length < 1 || checksumsBytes.length > 64 * 1024
      || !Buffer.from(checksumsBytes).equals(expected)) throw failure();
    return freeze({ schemaVersion: 1, managerVersion: checked.manifest.managerVersion,
      sourceRevision: checked.manifest.sourceRevision, subjects: checked.subjects.map((subject) => ({ ...subject })) });
  } catch (error) {
    if (FAILURE_SET.has(error)) throw error;
    throw failure();
  }
}

function exactAttestationSubjects(value, expected) {
  if (!Array.isArray(value) || value.length !== expected.length) return false;
  const normalized = [];
  for (const subject of value) {
    if (!exact(subject, ['name', 'digest']) || !NAME.test(subject.name) || !exact(subject.digest, ['sha256'])
      || !SHA256.test(subject.digest.sha256)) return false;
    normalized.push({ name: subject.name, sha256: subject.digest.sha256 });
  }
  normalized.sort((left, right) => left.name.localeCompare(right.name, 'en'));
  return JSON.stringify(normalized) === JSON.stringify(expected);
}

function hasVerifiedResult(bytes, expected) {
  const value = parseJson(bytes);
  if (!Array.isArray(value) || value.length < 1 || value.length > 30) return false;
  return value.some((entry) => {
    const result = entry?.verificationResult;
    const statement = result?.statement;
    return entry.attestation && typeof entry.attestation === 'object' && !Array.isArray(entry.attestation)
      && result?.signature?.certificate && typeof result.signature.certificate === 'object'
      && Object.keys(result.signature.certificate).length > 0
      && Array.isArray(result.verifiedTimestamps) && result.verifiedTimestamps.length > 0
      && statement?.predicateType === 'https://slsa.dev/provenance/v1'
      && exactAttestationSubjects(statement.subject, expected);
  });
}

export function verifyAttestationResults({ manifestBytes, artifacts, checksumsBytes, results } = {}) {
  try {
    const verified = verifyReleaseArtifacts({ manifestBytes, artifacts, checksumsBytes });
    if (!(results instanceof Map) || results.size !== verified.subjects.length
      || verified.subjects.some(({ name }) => !results.has(name))) throw failure();
    for (const value of results.values()) {
      if (!(value instanceof Uint8Array) || value.length < 2 || value.length > MAX_METADATA_BYTES
        || !hasVerifiedResult(value, verified.subjects)) throw failure();
    }
    return verified;
  } catch (error) {
    if (FAILURE_SET.has(error)) throw error;
    throw failure();
  }
}

function compiler(value) {
  if (!exact(value, ['name', 'version', 'flags']) || typeof value.name !== 'string' || value.name.length < 1
    || value.name.length > 64 || typeof value.version !== 'string' || value.version.length < 1
    || value.version.length > 128 || !Array.isArray(value.flags) || value.flags.length < 1
    || value.flags.length > 64 || new Set(value.flags).size !== value.flags.length
    || value.flags.some((flag) => typeof flag !== 'string' || flag.length < 1 || flag.length > 256
      || /[\u0000\r\n]/u.test(flag))) throw failure();
}

export function verifyShimDescriptor({ descriptor, bytes, target, sourceRevision } = {}) {
  try {
    if (!['windows-x64', 'windows-arm64'].includes(target) || !REVISION.test(sourceRevision)
      || !(bytes instanceof Uint8Array) || bytes.length < 1 || bytes.length > 64 * 1024 * 1024
      || !exact(descriptor, ['schemaVersion', 'target', 'sourceRevision', 'name', 'sha256', 'size',
        'managerShimCompatibilityVersion', 'compiler']) || descriptor.schemaVersion !== 1
      || descriptor.target !== target || descriptor.sourceRevision !== sourceRevision
      || descriptor.name !== `claudey-${target}.exe` || !SHA256.test(descriptor.sha256)
      || descriptor.sha256 !== hash(bytes) || descriptor.size !== bytes.length
      || descriptor.managerShimCompatibilityVersion !== 1) throw failure();
    compiler(descriptor.compiler);
    return freeze(structuredClone(descriptor));
  } catch (error) {
    if (FAILURE_SET.has(error)) throw error;
    throw failure();
  }
}

async function readRegular(targetPath, maximum = MAX_ARTIFACT_BYTES) {
  const before = await fs.lstat(targetPath, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size < 1n
    || before.size > BigInt(maximum)) throw failure();
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

async function checkedDirectory(directory) {
  const metadata = await fs.lstat(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw failure();
  return fs.realpath(directory);
}

async function loadRelease(artifactRoot, manifestPath, extraNames = []) {
  const canonicalRoot = await checkedDirectory(artifactRoot);
  if (await fs.realpath(path.dirname(manifestPath)) !== canonicalRoot || path.basename(manifestPath) !== 'project-manifest.json') throw failure();
  const manifestBytes = await readRegular(manifestPath, MAX_METADATA_BYTES);
  let manifest;
  try { manifest = validateProjectReleaseManifest(parseJson(manifestBytes)); } catch { throw failure(); }
  const names = expectedNames(manifest);
  const entries = (await fs.readdir(canonicalRoot)).sort((left, right) => left.localeCompare(right, 'en'));
  const expectedEntries = [...names, ...extraNames].sort((left, right) => left.localeCompare(right, 'en'));
  if (JSON.stringify(entries) !== JSON.stringify(expectedEntries)) throw failure();
  const artifacts = new Map();
  for (const name of names) artifacts.set(name, await readRegular(path.join(canonicalRoot, name),
    name === 'project-manifest.json' ? MAX_METADATA_BYTES : MAX_ARTIFACT_BYTES));
  return { manifestBytes, artifacts, canonicalRoot };
}

function parse(argv) {
  const modes = new Set(['--write-checksums', '--verify', '--verify-attestations', '--verify-shim']);
  const mode = argv[0];
  if (!modes.has(mode) || argv.length % 2 === 0) throw failure();
  const options = {};
  for (let index = 1; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (typeof key !== 'string' || !key.startsWith('--') || typeof value !== 'string' || value.length === 0
      || Object.hasOwn(options, key)) throw failure();
    options[key] = value;
  }
  const required = mode === '--write-checksums' ? ['--artifacts', '--manifest', '--out']
    : mode === '--verify' ? ['--artifacts', '--manifest', '--checksums']
      : mode === '--verify-attestations' ? ['--artifacts', '--manifest', '--checksums', '--results']
        : ['--descriptor', '--shim', '--target', '--source-revision'];
  if (Object.keys(options).sort().join(',') !== required.sort().join(',')) throw failure();
  return { mode, options };
}

async function cli(argv) {
  const { mode, options } = parse(argv);
  if (mode === '--verify-shim') {
    const descriptor = parseJson(await readRegular(path.resolve(options['--descriptor']), MAX_METADATA_BYTES));
    const bytes = await readRegular(path.resolve(options['--shim']), 64 * 1024 * 1024);
    verifyShimDescriptor({ descriptor, bytes, target: options['--target'], sourceRevision: options['--source-revision'] });
    process.stdout.write('native shim: valid\n');
    return;
  }
  const artifactRoot = path.resolve(options['--artifacts']);
  const manifestPath = path.resolve(options['--manifest']);
  const checksumPath = path.resolve(options[mode === '--write-checksums' ? '--out' : '--checksums']);
  if (path.dirname(checksumPath) !== artifactRoot || path.basename(checksumPath) !== 'SHA256SUMS') throw failure();
  const loaded = await loadRelease(artifactRoot, manifestPath, mode === '--write-checksums' ? [] : ['SHA256SUMS']);
  if (mode === '--write-checksums') {
    const bytes = buildReleaseChecksums(loaded);
    await fs.writeFile(checksumPath, bytes, { flag: 'wx', mode: 0o600 });
    return;
  }
  const checksumsBytes = await readRegular(checksumPath, 64 * 1024);
  if (mode === '--verify') {
    const result = verifyReleaseArtifacts({ ...loaded, checksumsBytes });
    process.stdout.write(`release artifacts: valid (${result.subjects.length} subjects)\n`);
    return;
  }
  const resultsRoot = await checkedDirectory(path.resolve(options['--results']));
  const expectedResultNames = [...loaded.artifacts.keys()].map((name) => `${name}.attestation.json`)
    .sort((left, right) => left.localeCompare(right, 'en'));
  const resultEntries = (await fs.readdir(resultsRoot)).sort((left, right) => left.localeCompare(right, 'en'));
  if (JSON.stringify(resultEntries) !== JSON.stringify(expectedResultNames)) throw failure();
  const results = new Map();
  for (const name of loaded.artifacts.keys()) results.set(name,
    await readRegular(path.join(resultsRoot, `${name}.attestation.json`), MAX_METADATA_BYTES));
  const verified = verifyAttestationResults({ ...loaded, checksumsBytes, results });
  process.stdout.write(`release attestations: valid (${verified.subjects.length} subjects)\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  cli(process.argv.slice(2)).catch(() => {
    process.stderr.write('error[RELEASE_ARTIFACT_INVALID]: Release artifacts or provenance are invalid.\n');
    process.exitCode = 7;
  });
}
