import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';
import { pathToFileURL } from 'node:url';

import { buildSpdxDocument } from './sbom.mjs';

const VERSION = /^\d+\.\d+\.\d+$/u;
const REVISION = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u;
const TARGETS = Object.freeze(['windows-x64', 'windows-arm64', 'darwin-x64', 'darwin-arm64', 'linux-x64', 'linux-arm64']);
const ROOT_FILES = new Set(['LICENSE', 'package.json']);
const BIN_FILES = new Set(['bin/claudex', 'bin/claude-agy', 'bin/claudexctl', 'bin/claudexctl.js']);
const WINDOWS_HELPERS = new Set([
  'scripts/windows/archive-helper.ps1', 'scripts/windows/process-helper.ps1',
  'scripts/windows/request-dacl-helper.ps1', 'scripts/windows/security-helper.ps1'
]);
const PLUGIN_FILES = new Set([
  'plugins/cursor-agent/.claude-plugin/plugin.json', 'plugins/cursor-agent/.mcp.json',
  'plugins/cursor-agent/server/index.mjs'
]);
const RUNTIME_SOURCE_FILES = new Set([
  'src/cli/commands/auth.js', 'src/cli/commands/config.js', 'src/cli/commands/cursor.js',
  'src/cli/commands/doctor.js', 'src/cli/commands/install.js', 'src/cli/commands/lifecycle.js',
  'src/cli/commands/models.js', 'src/cli/commands/rollback.js', 'src/cli/commands/setup.js',
  'src/cli/commands/status.js', 'src/cli/commands/uninstall.js', 'src/cli/commands/update.js',
  'src/cli/launchers/claude-agy.js', 'src/cli/launchers/claudex.js', 'src/cli/main.js',
  'src/cli/output.js', 'src/cli/parse.js', 'src/core/activation.js', 'src/core/archive.js',
  'src/core/checksum.js', 'src/core/config.js', 'src/core/errors.js', 'src/core/executable.js',
  'src/core/fs-safe.js', 'src/core/gateway-client.js', 'src/core/journal.js', 'src/core/lifecycle.js',
  'src/core/limits.js', 'src/core/lock.js', 'src/core/manifest.js', 'src/core/path-mutation.js',
  'src/core/paths.js', 'src/core/permissions.js', 'src/core/port.js', 'src/core/prerequisites.js',
  'src/core/process.js', 'src/core/release.js', 'src/core/result.js', 'src/core/schema.js',
  'src/core/secrets.js', 'src/core/transaction.js', 'src/cursor/approval.js',
  'src/cursor/capabilities.js', 'src/cursor/env.js', 'src/cursor/executable.js', 'src/cursor/git.js',
  'src/cursor/mcp-schema.js', 'src/cursor/mcp-server.js', 'src/cursor/models.js', 'src/cursor/registry.js',
  'src/cursor/runner.js', 'src/cursor/service.js', 'src/cursor/snapshot.js', 'src/cursor/worktree.js',
  'src/platform/asset-map.js', 'src/platform/detect.js', 'src/platform/index.js', 'src/platform/linux.js',
  'src/platform/macos.js', 'src/platform/posix.js', 'src/platform/windows.js', 'src/platform/windows-helpers.js',
  'src/providers/auth.js', 'src/providers/capabilities.js', 'src/providers/claude.js', 'src/providers/models.js'
]);
const REQUIRED = Object.freeze([...ROOT_FILES, ...BIN_FILES, ...WINDOWS_HELPERS, ...PLUGIN_FILES,
  ...RUNTIME_SOURCE_FILES, '.claude-plugin/marketplace.json'].sort());
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 32 * 1024 * 1024;
const FAILURES = new WeakSet();

function failure(code = 'PACKAGE_UNSAFE') {
  const error = new Error('The manager payload is unsafe.'); error.code = code; FAILURES.add(error); return error;
}

function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return (prototype === Object.prototype || prototype === null)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function hash(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function freeze(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function allowed(relative) {
  if (ROOT_FILES.has(relative) || BIN_FILES.has(relative) || WINDOWS_HELPERS.has(relative)) return true;
  if (relative === '.claude-plugin/marketplace.json') return true;
  if (RUNTIME_SOURCE_FILES.has(relative) || PLUGIN_FILES.has(relative)) return true;
  return false;
}

function unsafeSecretName(relative) {
  const base = path.posix.basename(relative).toLowerCase();
  return base === '.env' || base === '.npmrc' || base === 'credentials' || base === 'credentials.json'
    || /\.(?:pem|key|p12|pfx|jks)$/u.test(base);
}

async function walk(directory, root, files) {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name, 'en'));
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name);
    const relative = path.relative(root, absolute).split(path.sep).join('/');
    if (entry.isSymbolicLink() || !entry.isFile() && !entry.isDirectory()) throw failure();
    if (entry.isDirectory()) await walk(absolute, root, files);
    else {
      if (!allowed(relative) || unsafeSecretName(relative)) throw failure();
      files.push(relative);
    }
  }
}

async function readRegular(target) {
  const before = await fs.lstat(target, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size > BigInt(MAX_FILE_BYTES)) throw failure();
  const bytes = await fs.readFile(target);
  const after = await fs.lstat(target, { bigint: true });
  if (!after.isFile() || after.isSymbolicLink() || after.nlink !== 1n || before.dev !== after.dev || before.ino !== after.ino
    || before.size !== after.size || before.mtimeNs !== after.mtimeNs || BigInt(bytes.length) !== after.size) throw failure();
  return bytes;
}

async function inventory(root, managerVersion, secretCanary) {
  const candidates = [];
  for (const target of ['.claude-plugin', 'bin', 'plugins', 'scripts/windows', 'src']) {
    const directory = path.join(root, ...target.split('/'));
    const metadata = await fs.lstat(directory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw failure();
    await walk(directory, root, candidates);
  }
  for (const target of ROOT_FILES) candidates.push(target);
  candidates.sort();
  if (new Set(candidates).size !== candidates.length || REQUIRED.some((required) => !candidates.includes(required))) throw failure();
  const sourcePackage = JSON.parse((await readRegular(path.join(root, 'package.json'))).toString('utf8'));
  if (sourcePackage.dependencies || sourcePackage.optionalDependencies || sourcePackage.peerDependencies) throw failure();
  const runtimePackage = Buffer.from(`${JSON.stringify({ name: 'claudexctl', version: managerVersion, private: true,
    type: 'module', engines: { node: '>=22.20.0' }, bin: { claudexctl: 'bin/claudexctl.js' } })}\n`, 'utf8');
  const result = [];
  let total = 0;
  for (const relative of candidates) {
    const bytes = relative === 'package.json' ? runtimePackage : await readRegular(path.join(root, ...relative.split('/')));
    if (bytes.length > MAX_FILE_BYTES || secretCanary && bytes.includes(Buffer.from(secretCanary))) throw failure();
    total += bytes.length;
    if (total > MAX_PAYLOAD_BYTES) throw failure();
    const mode = relative.startsWith('bin/') ? 0o755 : 0o644;
    result.push(freeze({ path: relative, sha256: hash(bytes), size: bytes.length, mode, bytes }));
  }
  return result;
}

function octal(value, length) {
  const encoded = value.toString(8);
  if (encoded.length > length - 1) throw failure();
  return `${encoded.padStart(length - 1, '0')}\0`;
}

function tarHeader(entry) {
  const header = Buffer.alloc(512);
  if (Buffer.byteLength(entry.path) > 100) throw failure();
  header.write(entry.path, 0, 100, 'utf8');
  header.write(octal(entry.mode, 8), 100, 8, 'ascii');
  header.write(octal(0, 8), 108, 8, 'ascii');
  header.write(octal(0, 8), 116, 8, 'ascii');
  header.write(octal(entry.size, 12), 124, 12, 'ascii');
  header.write(octal(0, 12), 136, 12, 'ascii');
  header.fill(0x20, 148, 156);
  header.write('0', 156, 1, 'ascii');
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  const sum = header.reduce((total, byte) => total + byte, 0);
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  return header;
}

function buildTar(entries) {
  const blocks = [];
  for (const entry of entries) {
    blocks.push(tarHeader(entry), entry.bytes);
    const padding = (512 - entry.size % 512) % 512;
    if (padding) blocks.push(Buffer.alloc(padding));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

function deterministicGzip(bytes) {
  const compressed = Buffer.from(zlib.gzipSync(bytes, { level: 9, mtime: 0 }));
  if (compressed.length < 18 || compressed[0] !== 0x1f || compressed[1] !== 0x8b || compressed[2] !== 8) throw failure();
  compressed.fill(0, 4, 8);
  compressed[9] = 255;
  return compressed;
}

function artifact(value) {
  if (!exact(value, ['name', 'sha256', 'size']) || !NAME.test(value.name) || !SHA256.test(value.sha256)
    || !Number.isSafeInteger(value.size) || value.size < 1) throw failure('MANIFEST_INVALID');
  return value;
}

function compiler(value) {
  if (!exact(value, ['name', 'version', 'flags']) || typeof value.name !== 'string' || value.name.length < 1 || value.name.length > 64
    || typeof value.version !== 'string' || value.version.length < 1 || value.version.length > 128
    || !Array.isArray(value.flags) || value.flags.length < 1 || value.flags.length > 64
    || new Set(value.flags).size !== value.flags.length
    || value.flags.some((flag) => typeof flag !== 'string' || flag.length < 1 || flag.length > 256 || /[\u0000\r\n]/u.test(flag))) throw failure('MANIFEST_INVALID');
}

export function validateProjectReleaseManifest(value) {
  try {
    if (!exact(value, ['schemaVersion', 'managerVersion', 'sourceRevision', 'managerShimCompatibilityVersion',
      'payload', 'shims', 'targets', 'sbom', 'provenanceSubjects']) || value.schemaVersion !== 1
      || !VERSION.test(value.managerVersion) || !REVISION.test(value.sourceRevision)
      || !Number.isSafeInteger(value.managerShimCompatibilityVersion) || value.managerShimCompatibilityVersion < 1) throw failure('MANIFEST_INVALID');
    artifact(value.payload); artifact(value.sbom);
    if (!exact(value.shims, ['windows-x64', 'windows-arm64'])) throw failure('MANIFEST_INVALID');
    for (const target of ['windows-x64', 'windows-arm64']) {
      const shim = value.shims[target];
      if (!exact(shim, ['name', 'sha256', 'size', 'compiler'])) throw failure('MANIFEST_INVALID');
      artifact({ name: shim.name, sha256: shim.sha256, size: shim.size }); compiler(shim.compiler);
    }
    if (value.shims['windows-x64'].name === value.shims['windows-arm64'].name || !exact(value.targets, TARGETS)) throw failure('MANIFEST_INVALID');
    for (const target of TARGETS) {
      const mapping = value.targets[target];
      if (!exact(mapping, ['payload', 'shim']) || mapping.payload !== value.payload.name) throw failure('MANIFEST_INVALID');
      const expectedShim = target === 'windows-x64' ? value.shims['windows-x64'].name
        : target === 'windows-arm64' ? value.shims['windows-arm64'].name : null;
      if (mapping.shim !== expectedShim) throw failure('MANIFEST_INVALID');
    }
    const expectedSubjects = [value.payload, value.sbom, value.shims['windows-arm64'], value.shims['windows-x64']]
      .map(({ name, sha256 }) => ({ name, sha256 })).sort((left, right) => left.name.localeCompare(right.name, 'en'));
    if (!Array.isArray(value.provenanceSubjects) || value.provenanceSubjects.length !== expectedSubjects.length) throw failure('MANIFEST_INVALID');
    for (let index = 0; index < expectedSubjects.length; index += 1) {
      if (!exact(value.provenanceSubjects[index], ['name', 'sha256'])
        || value.provenanceSubjects[index].name !== expectedSubjects[index].name
        || value.provenanceSubjects[index].sha256 !== expectedSubjects[index].sha256) throw failure('MANIFEST_INVALID');
    }
    return freeze(structuredClone(value));
  } catch (error) {
    if (FAILURES.has(error) && error.code === 'MANIFEST_INVALID') throw error;
    throw failure('MANIFEST_INVALID');
  }
}

export async function buildManagerPackage({ root, managerVersion, sourceRevision, secretCanary } = {}) {
  try {
    if (typeof root !== 'string' || path.resolve(root) !== root || !VERSION.test(managerVersion)
      || !REVISION.test(sourceRevision) || secretCanary !== undefined && (typeof secretCanary !== 'string' || secretCanary.length === 0)) throw failure();
    const entries = await inventory(root, managerVersion, secretCanary);
    const archiveBytes = deterministicGzip(buildTar(entries));
    const publicInventory = entries.map(({ path: filePath, sha256, size, mode }) => freeze({ path: filePath, sha256, size, mode }));
    const artifactName = `claudex-manager-${managerVersion}.tar.gz`;
    const payloadDescriptor = freeze({ schemaVersion: 1, kind: 'manager-payload', managerVersion, sourceRevision,
      artifact: { name: artifactName, sha256: hash(archiveBytes), size: archiveBytes.length },
      inventorySha256: hash(Buffer.from(`${JSON.stringify(publicInventory)}\n`, 'utf8')) });
    const sbom = buildSpdxDocument({ managerVersion, sourceRevision, inventory: publicInventory });
    return freeze({ archiveBytes, inventory: publicInventory, payloadDescriptor,
      sbomBytes: sbom.bytes, sbomDescriptor: sbom.descriptor });
  } catch (error) {
    if (FAILURES.has(error) && error.code === 'PACKAGE_UNSAFE') throw error;
    throw failure();
  }
}

async function cli(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!['--root', '--out', '--version', '--source-revision'].includes(key) || value === undefined || Object.hasOwn(options, key)) throw failure();
    options[key] = value;
  }
  const root = path.resolve(options['--root'] ?? path.resolve(import.meta.dirname, '..'));
  const out = path.resolve(options['--out'] ?? path.join(root, 'dist'));
  const built = await buildManagerPackage({ root, managerVersion: options['--version'], sourceRevision: options['--source-revision'],
    secretCanary: process.env.CLAUDEX_SECRET_CANARY });
  await fs.mkdir(out, { recursive: true, mode: 0o700 });
  await fs.writeFile(path.join(out, built.payloadDescriptor.artifact.name), built.archiveBytes, { mode: 0o600 });
  await fs.writeFile(path.join(out, `${built.payloadDescriptor.artifact.name}.json`), `${JSON.stringify(built.payloadDescriptor)}\n`, { mode: 0o600 });
  await fs.writeFile(path.join(out, built.sbomDescriptor.name), built.sbomBytes, { mode: 0o600 });
  await fs.writeFile(path.join(out, `${built.sbomDescriptor.name}.descriptor.json`), `${JSON.stringify(built.sbomDescriptor)}\n`, { mode: 0o600 });
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  cli(process.argv.slice(2)).catch(() => { process.stderr.write('error[PACKAGE_UNSAFE]: Packaging failed safely.\n'); process.exitCode = 7; });
}
