import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

import { validateProjectReleaseManifest } from './package.mjs';

const VERSION = /^\d+\.\d+\.\d+$/u;
const REVISION = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u;
const WINDOWS_TARGETS = Object.freeze(['windows-x64', 'windows-arm64']);
const TARGETS = Object.freeze([
  'windows-x64', 'windows-arm64', 'darwin-x64', 'darwin-arm64', 'linux-x64', 'linux-arm64'
]);
const MAX_DESCRIPTOR_BYTES = 1024 * 1024;
const MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;
const FAILURES = new WeakSet();

function failure() {
  const error = new Error('The project release manifest is invalid.');
  error.code = 'MANIFEST_INVALID';
  FAILURES.add(error);
  return error;
}

function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return (prototype === Object.prototype || prototype === null)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function hash(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function artifact(value) {
  if (!exact(value, ['name', 'sha256', 'size']) || !NAME.test(value.name) || !SHA256.test(value.sha256)
    || !Number.isSafeInteger(value.size) || value.size < 1 || value.size > MAX_ARTIFACT_BYTES) throw failure();
  return value;
}

function payloadDescriptor(value) {
  if (!exact(value, ['schemaVersion', 'kind', 'managerVersion', 'sourceRevision', 'artifact', 'inventorySha256'])
    || value.schemaVersion !== 1 || value.kind !== 'manager-payload' || !VERSION.test(value.managerVersion)
    || !REVISION.test(value.sourceRevision) || !SHA256.test(value.inventorySha256)) throw failure();
  artifact(value.artifact);
  return value;
}

function sbomDescriptor(value) {
  if (!exact(value, ['schemaVersion', 'kind', 'managerVersion', 'sourceRevision', 'artifact'])
    || value.schemaVersion !== 1 || value.kind !== 'manager-sbom' || !VERSION.test(value.managerVersion)
    || !REVISION.test(value.sourceRevision)) throw failure();
  artifact(value.artifact);
  return value;
}

function compiler(value) {
  if (!exact(value, ['name', 'version', 'flags']) || typeof value.name !== 'string'
    || value.name.length < 1 || value.name.length > 64 || typeof value.version !== 'string'
    || value.version.length < 1 || value.version.length > 128 || !Array.isArray(value.flags)
    || value.flags.length < 1 || value.flags.length > 64 || new Set(value.flags).size !== value.flags.length
    || value.flags.some((flag) => typeof flag !== 'string' || flag.length < 1 || flag.length > 256
      || /[\u0000\r\n]/u.test(flag))) throw failure();
  return value;
}

function shimDescriptor(value) {
  if (!exact(value, ['schemaVersion', 'target', 'sourceRevision', 'name', 'sha256', 'size',
    'managerShimCompatibilityVersion', 'compiler']) || value.schemaVersion !== 1
    || !WINDOWS_TARGETS.includes(value.target) || !REVISION.test(value.sourceRevision)
    || value.name !== `claudex-${value.target}.exe` || !Number.isSafeInteger(value.managerShimCompatibilityVersion)
    || value.managerShimCompatibilityVersion < 1) throw failure();
  artifact({ name: value.name, sha256: value.sha256, size: value.size });
  compiler(value.compiler);
  return value;
}

async function verifiedArtifact(descriptor, readArtifact) {
  const value = await readArtifact(descriptor.name);
  if (!(value instanceof Uint8Array)) throw failure();
  const bytes = Buffer.from(value);
  if (bytes.length !== descriptor.size || bytes.length < 1 || bytes.length > MAX_ARTIFACT_BYTES
    || hash(bytes) !== descriptor.sha256) throw failure();
}

export async function assembleReleaseManifest({
  payloadDescriptor: payloadValue,
  sbomDescriptor: sbomValue,
  shimDescriptors: shimValues,
  readArtifact
} = {}) {
  try {
    const payload = payloadDescriptor(payloadValue);
    const sbom = sbomDescriptor(sbomValue);
    if (!Array.isArray(shimValues) || shimValues.length !== 2 || typeof readArtifact !== 'function') throw failure();
    const checkedShims = shimValues.map(shimDescriptor);
    const byTarget = new Map(checkedShims.map((descriptor) => [descriptor.target, descriptor]));
    if (byTarget.size !== 2 || WINDOWS_TARGETS.some((target) => !byTarget.has(target))) throw failure();
    const x64 = byTarget.get('windows-x64');
    const arm64 = byTarget.get('windows-arm64');
    if (payload.managerVersion !== sbom.managerVersion || payload.sourceRevision !== sbom.sourceRevision
      || checkedShims.some((descriptor) => descriptor.sourceRevision !== payload.sourceRevision)
      || x64.managerShimCompatibilityVersion !== arm64.managerShimCompatibilityVersion) throw failure();
    const descriptors = [payload.artifact, sbom.artifact, x64, arm64];
    if (new Set(descriptors.map(({ name }) => name)).size !== descriptors.length) throw failure();
    for (const descriptor of descriptors) await verifiedArtifact(descriptor, readArtifact);
    const targets = {};
    for (const target of TARGETS) {
      targets[target] = { payload: payload.artifact.name,
        shim: target === 'windows-x64' ? x64.name : target === 'windows-arm64' ? arm64.name : null };
    }
    const manifest = {
      schemaVersion: 1,
      managerVersion: payload.managerVersion,
      sourceRevision: payload.sourceRevision,
      managerShimCompatibilityVersion: x64.managerShimCompatibilityVersion,
      payload: { ...payload.artifact },
      shims: {
        'windows-x64': { name: x64.name, sha256: x64.sha256, size: x64.size, compiler: structuredClone(x64.compiler) },
        'windows-arm64': { name: arm64.name, sha256: arm64.sha256, size: arm64.size,
          compiler: structuredClone(arm64.compiler) }
      },
      targets,
      sbom: { ...sbom.artifact },
      provenanceSubjects: descriptors.map(({ name, sha256 }) => ({ name, sha256 }))
        .sort((left, right) => left.name.localeCompare(right.name, 'en'))
    };
    return freeze(validateProjectReleaseManifest(manifest));
  } catch (error) {
    if (FAILURES.has(error)) throw error;
    throw failure();
  }
}

async function readRegular(target, maximum) {
  const before = await fs.lstat(target, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size < 1n
    || before.size > BigInt(maximum)) throw failure();
  const handle = await fs.open(target, 'r');
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

async function readJson(target) {
  const bytes = await readRegular(path.resolve(target), MAX_DESCRIPTOR_BYTES);
  return JSON.parse(bytes.toString('utf8'));
}

function parse(argv) {
  if (argv.length === 2 && argv[0] === '--validate') return { validate: path.resolve(argv[1]) };
  const allowed = new Set(['--payload-descriptor', '--sbom-descriptor', '--shim-x64-descriptor',
    '--shim-arm64-descriptor', '--artifacts', '--out']);
  if (argv.length !== allowed.size * 2) throw failure();
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!allowed.has(key) || typeof value !== 'string' || value.length === 0 || Object.hasOwn(result, key)) throw failure();
    result[key] = path.resolve(value);
  }
  if (Object.keys(result).length !== allowed.size) throw failure();
  return result;
}

async function ensureArtifactRoot(root) {
  const metadata = await fs.lstat(root);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw failure();
}

async function publish(options) {
  const artifactsRoot = options['--artifacts'];
  const output = options['--out'];
  await ensureArtifactRoot(artifactsRoot);
  const outputDirectory = path.dirname(output);
  const outputDirectoryMetadata = await fs.lstat(outputDirectory);
  if (!outputDirectoryMetadata.isDirectory() || outputDirectoryMetadata.isSymbolicLink()) throw failure();
  await fs.lstat(output).then(() => { throw failure(); }, (error) => { if (error?.code !== 'ENOENT') throw error; });
  const payload = await readJson(options['--payload-descriptor']);
  const sbom = await readJson(options['--sbom-descriptor']);
  const shims = [await readJson(options['--shim-x64-descriptor']), await readJson(options['--shim-arm64-descriptor'])];
  const manifest = await assembleReleaseManifest({ payloadDescriptor: payload, sbomDescriptor: sbom,
    shimDescriptors: shims, readArtifact: async (name) => readRegular(path.join(artifactsRoot, name), MAX_ARTIFACT_BYTES) });
  const bytes = Buffer.from(`${JSON.stringify(manifest)}\n`, 'utf8');
  const temporary = path.join(outputDirectory, `.claudex-manifest-${crypto.randomUUID()}.tmp`);
  try {
    await fs.writeFile(temporary, bytes, { flag: 'wx', mode: 0o600 });
    const child = spawnSync(process.execPath, [path.resolve(import.meta.filename), '--validate', temporary], {
      cwd: outputDirectory, encoding: 'utf8', shell: false, windowsHide: true, timeout: 30_000, maxBuffer: 64 * 1024,
      env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot }
    });
    if (child.error || child.status !== 0 || child.signal !== null || child.stdout !== '') throw failure();
    await fs.link(temporary, output);
  } finally { await fs.rm(temporary, { force: true }); }
}

async function cli(argv) {
  const options = parse(argv);
  if (options.validate) {
    validateProjectReleaseManifest(JSON.parse((await readRegular(options.validate, MAX_DESCRIPTOR_BYTES)).toString('utf8')));
    return;
  }
  await publish(options);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  cli(process.argv.slice(2)).catch(() => {
    process.stderr.write('error[MANIFEST_INVALID]: Release manifest assembly failed safely.\n');
    process.exitCode = 7;
  });
}
