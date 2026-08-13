#!/bin/sh
set -eu

PROJECT_ORIGIN='https://github.com/ramsaijanapana/claude_code_cliProxy'
manager_version=''
accept_yes=0
no_path=0
rollback_manager=0
seen_version=0
seen_yes=0
seen_no_path=0
seen_rollback=0

usage() {
  printf '%s\n' 'error[USAGE_ERROR]: Usage: install.sh [--version VERSION] [--yes] [--no-path] [--rollback-manager]' >&2
  exit 64
}

valid_version() (
  [ "${#1}" -le 32 ] || exit 1
  old_ifs=$IFS
  IFS=.
  set -- $1
  IFS=$old_ifs
  [ "$#" -eq 3 ] || exit 1
  for part in "$@"; do
    [ "${#part}" -le 9 ] || exit 1
    case "$part" in ''|*[!0-9]*|0[0-9]*) exit 1 ;; esac
  done
)

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$seen_version" -eq 0 ] && [ "$#" -ge 2 ] || usage
      valid_version "$2" || usage
      manager_version=$2
      seen_version=1
      shift 2
      ;;
    --yes)
      [ "$seen_yes" -eq 0 ] || usage
      accept_yes=1
      seen_yes=1
      shift
      ;;
    --no-path)
      [ "$seen_no_path" -eq 0 ] || usage
      no_path=1
      seen_no_path=1
      shift
      ;;
    --rollback-manager)
      [ "$seen_rollback" -eq 0 ] || usage
      rollback_manager=1
      seen_rollback=1
      shift
      ;;
    *) usage ;;
  esac
done

if [ "$rollback_manager" -eq 1 ] && { [ "$seen_version" -eq 1 ] || [ "$seen_yes" -eq 1 ] || [ "$seen_no_path" -eq 1 ]; }; then
  usage
fi

user_id=$(/usr/bin/id -u 2>/dev/null) || {
  printf '%s\n' 'error[PREREQUISITE_MISSING]: Unable to inspect the current user.' >&2
  exit 69
}
if [ "$user_id" = '0' ]; then
  printf '%s\n' 'error[SAFETY_REFUSAL]: Do not run the per-user bootstrap as root.' >&2
  exit 7
fi

node_command=$(command -v node 2>/dev/null || true)
case "$node_command" in /*) ;; *)
  printf '%s\n' 'error[PREREQUISITE_MISSING]: A supported absolute Node.js executable is required.' >&2
  exit 69
;; esac
node_version=$("$node_command" -p 'process.versions.node' 2>/dev/null || true)
valid_version "$node_version" || {
  printf '%s\n' 'error[PREREQUISITE_MISSING]: Node.js 22.20.0 or a supported newer line is required.' >&2
  exit 69
}
node_major=${node_version%%.*}
node_remainder=${node_version#*.}
node_minor=${node_remainder%%.*}
case "$node_major" in 22|24|26) ;; *)
  printf '%s\n' 'error[PREREQUISITE_MISSING]: Node.js 22, 24, or 26 is required.' >&2
  exit 69
;; esac
if [ "$node_major" -eq 22 ] && [ "$node_minor" -lt 20 ]; then
  printf '%s\n' 'error[PREREQUISITE_MISSING]: Node.js 22.20.0 or newer is required.' >&2
  exit 69
fi
node_path=$("$node_command" -p 'process.execPath' 2>/dev/null || true)
case "$node_path" in /*) ;; *)
  printf '%s\n' 'error[PREREQUISITE_MISSING]: Node.js did not report a safe absolute executable path.' >&2
  exit 69
;; esac

cldx_platform=$("$node_path" --input-type=module -e '
import fs from "node:fs";
import { execFileSync } from "node:child_process";
const atLeast = (actual, required) => {
  const parts = actual.split(".").map((part) => /^(0|[1-9]\d*)$/.test(part) ? Number(part) : NaN);
  if (parts.some((part) => !Number.isSafeInteger(part))) return false;
  for (let index = 0; index < required.length; index += 1) {
    const value = parts[index] ?? 0;
    if (value !== required[index]) return value > required[index];
  }
  return true;
};
if (process.platform === "darwin") {
  let version = "";
  try { version = execFileSync("/usr/bin/sw_vers", ["-productVersion"], { encoding: "utf8", timeout: 3000 }).trim(); }
  catch { process.exit(3); }
  if (!atLeast(version, [13])) process.exit(3);
  process.stdout.write("darwin");
} else if (process.platform === "linux") {
  const glibc = process.report?.getReport()?.header?.glibcVersionRuntime;
  if (typeof glibc !== "string" || glibc.length === 0) process.exit(3);
  let text;
  try { text = fs.readFileSync("/etc/os-release", "utf8"); } catch { process.exit(3); }
  const values = {};
  for (const line of text.split(/\r?\n/u)) {
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/u.exec(line);
    if (!match) continue;
    const quoted = /^("|'"'"')(.*)\1$/u.exec(match[2]);
    values[match[1]] = quoted ? quoted[2] : match[2];
  }
  const id = typeof values.ID === "string" ? values.ID.toLowerCase() : "";
  const version = values.VERSION_ID ?? "";
  if (id === "ubuntu" ? !atLeast(version, [20, 4]) : id === "debian" ? !atLeast(version, [10]) : true) process.exit(3);
  let kernel = "";
  try { kernel = `${fs.readFileSync("/proc/sys/kernel/osrelease", "utf8")}\n${fs.readFileSync("/proc/version", "utf8")}`.toLowerCase(); }
  catch { process.exit(3); }
  process.stdout.write(kernel.includes("microsoft") ? "linux-wsl" : "linux");
} else process.exit(3);
' 2>/dev/null || true)
case "$cldx_platform" in
  linux-wsl) cldx_platform='linux'; cldx_is_wsl=1 ;;
  linux|darwin) cldx_is_wsl=0 ;;
  *)
  printf '%s\n' 'error[PLATFORM_UNSUPPORTED]: Only supported native Linux, WSL, and macOS hosts are accepted.' >&2
  exit 69
  ;;
esac

cldx_arch=$("$node_path" -p 'process.arch' 2>/dev/null || true)
case "$cldx_arch" in x64|arm64) ;; *)
  printf '%s\n' 'error[PLATFORM_UNSUPPORTED]: Only x64 and arm64 runtimes are supported.' >&2
  exit 69
;; esac

case "${HOME-}" in /*) ;; *)
  printf '%s\n' 'error[SAFETY_REFUSAL]: HOME must be a safe absolute POSIX path.' >&2
  exit 7
;; esac
case "$HOME" in /|*'
'*|*''* )
  printf '%s\n' 'error[SAFETY_REFUSAL]: HOME cannot be a filesystem root or mounted Windows path.' >&2
  exit 7
;; esac
if [ "$cldx_is_wsl" -eq 1 ]; then
  case "$HOME" in /mnt/[A-Za-z]|/mnt/[A-Za-z]/*)
    printf '%s\n' 'error[SAFETY_REFUSAL]: WSL HOME cannot use a mounted Windows path.' >&2
    exit 7
  ;; esac
fi

if [ "$cldx_platform" = 'darwin' ]; then
  cldx_manager_root="$HOME/Library/Application Support/claudexctl"
  cldx_state_root="$cldx_manager_root/state"
else
  cldx_data_home=${XDG_DATA_HOME:-"$HOME/.local/share"}
  cldx_state_home=${XDG_STATE_HOME:-"$HOME/.local/state"}
  case "$cldx_data_home:$cldx_state_home" in *'
'*|*''*|*:/|/:*)
    printf '%s\n' 'error[SAFETY_REFUSAL]: XDG roots must be safe non-root POSIX paths.' >&2
    exit 7
  ;; esac
  case "$cldx_data_home:$cldx_state_home" in /*:/*) ;; *)
    printf '%s\n' 'error[SAFETY_REFUSAL]: XDG roots must be absolute.' >&2
    exit 7
  ;; esac
  if [ "$cldx_is_wsl" -eq 1 ]; then
    case "$cldx_data_home:$cldx_state_home" in /mnt/[A-Za-z]:*|/mnt/[A-Za-z]/*|*:/mnt/[A-Za-z]|*:/mnt/[A-Za-z]/*)
      printf '%s\n' 'error[SAFETY_REFUSAL]: WSL managed roots cannot use mounted Windows paths.' >&2
      exit 7
    ;; esac
  fi
  cldx_manager_root="$cldx_data_home/claudexctl"
  cldx_state_root="$cldx_state_home/claudexctl"
fi
cldx_user_bin="$HOME/.local/bin"
cldx_target="$cldx_platform-$cldx_arch"

export CLDX_PROJECT_ORIGIN="$PROJECT_ORIGIN"
export CLDX_MANAGER_VERSION="$manager_version"
export CLDX_ACCEPT_YES="$accept_yes"
export CLDX_NO_PATH="$no_path"
export CLDX_ROLLBACK_MANAGER="$rollback_manager"
export CLDX_PLATFORM="$cldx_platform"
export CLDX_TARGET="$cldx_target"
export CLDX_MANAGER_ROOT="$cldx_manager_root"
export CLDX_STATE_ROOT="$cldx_state_root"
export CLDX_USER_BIN="$cldx_user_bin"

set +e
"$node_path" --input-type=module - <<'NODE'
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import zlib from 'node:zlib';
import { spawnSync } from 'node:child_process';

const VERSION = /^\d+\.\d+\.\d+$/u;
const REVISION = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u;
const TARGETS = ['windows-x64', 'windows-arm64', 'darwin-x64', 'darwin-arm64', 'linux-x64', 'linux-arm64'];
const MAX_MANIFEST = 1024 * 1024;
const MAX_PAYLOAD = 32 * 1024 * 1024;
const MAX_EXPANDED = 64 * 1024 * 1024;
const MAX_FILE = 8 * 1024 * 1024;

class BootstrapFailure extends Error {
  constructor(code = 'SAFETY_REFUSAL', exitCode = 7) { super('Bootstrap failed safely.'); this.code = code; this.exitCode = exitCode; }
}
const fail = (code, exitCode) => { throw new BootstrapFailure(code, exitCode); };
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const digest = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const quote = (value) => `'${value.replaceAll("'", `'"'"'`)}'`;

function artifact(value) {
  if (!exact(value, ['name', 'sha256', 'size']) || !NAME.test(value.name) || !SHA256.test(value.sha256)
    || !Number.isSafeInteger(value.size) || value.size < 1 || value.size > MAX_PAYLOAD) fail();
  return value;
}

function compiler(value) {
  if (!exact(value, ['name', 'version', 'flags']) || typeof value.name !== 'string' || value.name.length < 1
    || value.name.length > 64 || typeof value.version !== 'string' || value.version.length < 1 || value.version.length > 128
    || !Array.isArray(value.flags) || value.flags.length < 1 || value.flags.length > 64
    || new Set(value.flags).size !== value.flags.length
    || value.flags.some((flag) => typeof flag !== 'string' || flag.length < 1 || flag.length > 256
      || /[\u0000\r\n]/u.test(flag))) fail();
}

function checkedManifest(value, requestedVersion, target) {
  if (!exact(value, ['schemaVersion', 'managerVersion', 'sourceRevision', 'managerShimCompatibilityVersion',
    'payload', 'shims', 'targets', 'sbom', 'provenanceSubjects']) || value.schemaVersion !== 1
    || !VERSION.test(value.managerVersion) || requestedVersion && value.managerVersion !== requestedVersion
    || !REVISION.test(value.sourceRevision) || !Number.isSafeInteger(value.managerShimCompatibilityVersion)
    || value.managerShimCompatibilityVersion < 1) fail('CHECKSUM_MISMATCH');
  artifact(value.payload); artifact(value.sbom);
  if (value.payload.name !== `claudex-manager-${value.managerVersion}.tar.gz`
    || value.sbom.name !== `claudex-manager-${value.managerVersion}.spdx.json`
    || !exact(value.shims, ['windows-x64', 'windows-arm64']) || !exact(value.targets, TARGETS)) fail('CHECKSUM_MISMATCH');
  for (const windowsTarget of ['windows-x64', 'windows-arm64']) {
    const shim = value.shims[windowsTarget];
    if (!exact(shim, ['name', 'sha256', 'size', 'compiler'])) fail('CHECKSUM_MISMATCH');
    artifact({ name: shim.name, sha256: shim.sha256, size: shim.size }); compiler(shim.compiler);
    if (shim.name !== `claudex-${windowsTarget}.exe`) fail('CHECKSUM_MISMATCH');
  }
  for (const candidate of TARGETS) {
    const mapping = value.targets[candidate];
    if (!exact(mapping, ['payload', 'shim']) || mapping.payload !== value.payload.name) fail('CHECKSUM_MISMATCH');
    const expected = candidate === 'windows-x64' ? value.shims['windows-x64'].name
      : candidate === 'windows-arm64' ? value.shims['windows-arm64'].name : null;
    if (mapping.shim !== expected) fail('CHECKSUM_MISMATCH');
  }
  if (!Object.hasOwn(value.targets, target) || value.targets[target].shim !== null) fail('PLATFORM_UNSUPPORTED', 69);
  const subjects = [value.payload, value.sbom, value.shims['windows-arm64'], value.shims['windows-x64']]
    .map(({ name, sha256 }) => ({ name, sha256 })).sort((left, right) => left.name.localeCompare(right.name, 'en'));
  if (!Array.isArray(value.provenanceSubjects) || value.provenanceSubjects.length !== subjects.length) fail('CHECKSUM_MISMATCH');
  for (let index = 0; index < subjects.length; index += 1) {
    const actual = value.provenanceSubjects[index];
    if (!exact(actual, ['name', 'sha256']) || actual.name !== subjects[index].name || actual.sha256 !== subjects[index].sha256) {
      fail('CHECKSUM_MISMATCH');
    }
  }
  return value;
}

function allowedDownload(url, projectOrigin) {
  if (url.username || url.password || url.hash) return false;
  if (url.origin === projectOrigin.origin) {
    const prefix = projectOrigin.pathname.endsWith('/') ? projectOrigin.pathname : `${projectOrigin.pathname}/`;
    return url.protocol === projectOrigin.protocol && !url.search && url.pathname.startsWith(prefix);
  }
  if (url.port && url.port !== '443') return false;
  return projectOrigin.protocol === 'https:' && url.protocol === 'https:'
    && ['objects.githubusercontent.com', 'release-assets.githubusercontent.com'].includes(url.hostname);
}

function download(input, maximum, projectOrigin, redirects = 0) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(input); } catch { reject(new BootstrapFailure('NETWORK_FAILURE', 5)); return; }
    if (!allowedDownload(url, projectOrigin) || redirects > 5) { reject(new BootstrapFailure('NETWORK_FAILURE', 5)); return; }
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.get(url, { headers: { 'user-agent': 'claudex-bootstrap/1', accept: 'application/octet-stream' } }, (response) => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
        const location = response.headers.location;
        response.resume();
        if (typeof location !== 'string') { reject(new BootstrapFailure('NETWORK_FAILURE', 5)); return; }
        download(new URL(location, url).href, maximum, projectOrigin, redirects + 1).then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) { response.resume(); reject(new BootstrapFailure('NETWORK_FAILURE', 5)); return; }
      const declared = response.headers['content-length'];
      if (declared !== undefined && (!/^\d+$/u.test(declared) || Number(declared) > maximum)) {
        response.destroy(); reject(new BootstrapFailure('NETWORK_FAILURE', 5)); return;
      }
      const chunks = []; let total = 0;
      response.on('data', (chunk) => {
        total += chunk.length;
        if (total > maximum) response.destroy(new BootstrapFailure('NETWORK_FAILURE', 5));
        else chunks.push(chunk);
      });
      response.on('end', () => resolve(Buffer.concat(chunks)));
      response.on('error', (error) => reject(error instanceof BootstrapFailure
        ? error : new BootstrapFailure('NETWORK_FAILURE', 5)));
    });
    request.setTimeout(30_000, () => request.destroy(new BootstrapFailure('NETWORK_FAILURE', 5)));
    request.on('error', (error) => reject(error instanceof BootstrapFailure
      ? error : new BootstrapFailure('NETWORK_FAILURE', 5)));
  });
}

function octal(header, start, length) {
  const raw = header.subarray(start, start + length).toString('ascii').replace(/[\0 ]+$/u, '');
  if (!/^[0-7]+$/u.test(raw)) fail('ARCHIVE_UNSAFE');
  const value = Number.parseInt(raw, 8);
  if (!Number.isSafeInteger(value)) fail('ARCHIVE_UNSAFE');
  return value;
}

function crc32(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit += 1) value = (value & 1) ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return (value ^ 0xffffffff) >>> 0;
}

function safeArchivePath(value, prior) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 100 || value.startsWith('/') || value.includes('\\')
    || /[\u0000-\u001f\u007f]/u.test(value) || value.normalize('NFC') !== value
    || value.split('/').some((part) => part === '' || part === '.' || part === '..') || value <= prior) fail('ARCHIVE_UNSAFE');
  return value;
}

function parseArchive(compressed) {
  if (compressed.length < 18 || compressed[0] !== 0x1f || compressed[1] !== 0x8b || compressed[2] !== 8
    || compressed[3] !== 0 || compressed.readUInt32LE(4) !== 0) fail('ARCHIVE_UNSAFE');
  let inflated;
  try { inflated = zlib.inflateRawSync(compressed.subarray(10), { info: true, maxOutputLength: MAX_EXPANDED }); }
  catch { fail('ARCHIVE_UNSAFE'); }
  const compressedBytes = inflated.engine.bytesWritten;
  const trailerOffset = 10 + compressedBytes;
  const data = inflated.buffer;
  if (trailerOffset !== compressed.length - 8 || compressed.readUInt32LE(trailerOffset) !== crc32(data)
    || compressed.readUInt32LE(trailerOffset + 4) !== (data.length >>> 0)
    || data.length > Math.max(1, compressedBytes) * 100) fail('ARCHIVE_UNSAFE');
  const entries = []; let offset = 0; let prior = ''; let total = 0;
  while (offset + 512 <= data.length) {
    const header = data.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    if (entries.length >= 2_048 || header.subarray(257, 263).toString('latin1') !== 'ustar\0'
      || header.subarray(263, 265).toString('ascii') !== '00' || !header.subarray(157, 257).every((byte) => byte === 0)
      || !header.subarray(265).every((byte) => byte === 0)) fail('ARCHIVE_UNSAFE');
    const storedChecksum = octal(header, 148, 8);
    const checksumHeader = Buffer.from(header); checksumHeader.fill(0x20, 148, 156);
    if (checksumHeader.reduce((sum, byte) => sum + byte, 0) !== storedChecksum) fail('ARCHIVE_UNSAFE');
    const name = safeArchivePath(header.subarray(0, 100).toString('utf8').replace(/\0.*$/u, ''), prior);
    prior = name;
    const type = header[156];
    const mode = octal(header, 100, 8); const size = octal(header, 124, 12);
    if (![0, 0x30].includes(type) || ![0o644, 0o755].includes(mode) || octal(header, 108, 8) !== 0
      || octal(header, 116, 8) !== 0 || octal(header, 136, 12) !== 0 || size > MAX_FILE) fail('ARCHIVE_UNSAFE');
    total += size;
    const end = offset + 512 + size;
    if (total > MAX_EXPANDED || end > data.length) fail('ARCHIVE_UNSAFE');
    entries.push({ path: name, mode, size, sha256: digest(data.subarray(offset + 512, end)),
      bytes: Buffer.from(data.subarray(offset + 512, end)) });
    const nextOffset = offset + 512 + Math.ceil(size / 512) * 512;
    if (nextOffset > data.length || !data.subarray(end, nextOffset).every((byte) => byte === 0)) fail('ARCHIVE_UNSAFE');
    offset = nextOffset;
  }
  if (entries.length < 1 || data.length - offset < 1024 || !data.subarray(offset).every((byte) => byte === 0)) fail('ARCHIVE_UNSAFE');
  for (const required of ['LICENSE', 'bin/claude-agy', 'bin/claudex', 'bin/claudexctl', 'bin/claudexctl.js', 'package.json']) {
    if (!entries.some((entry) => entry.path === required)) fail('ARCHIVE_UNSAFE');
  }
  return entries;
}

async function inspectDirectory(target, allowedModes = [0o700], requireCurrentOwner = true) {
  const metadata = await fs.lstat(target);
  const currentUser = typeof process.getuid === 'function' ? process.getuid() : undefined;
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.nlink < 1
    || !allowedModes.includes(metadata.mode & 0o777) || requireCurrentOwner && metadata.uid !== currentUser) fail();
  return metadata;
}

async function ensureDirectory(target, createMode = 0o700, allowedModes = [createMode]) {
  const resolved = path.resolve(target);
  if (resolved !== target || resolved === path.parse(resolved).root) fail();
  const root = path.parse(resolved).root;
  const parts = path.relative(root, resolved).split(path.sep);
  let current = root;
  for (let index = 0; index < parts.length; index += 1) {
    current = path.join(current, parts[index]);
    const final = index === parts.length - 1;
    let metadata;
    try { metadata = await fs.lstat(current); }
    catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      await fs.mkdir(current, { mode: final ? createMode : 0o700 });
      metadata = await fs.lstat(current);
    }
    const currentUser = typeof process.getuid === 'function' ? process.getuid() : undefined;
    const mode = metadata.mode & 0o777;
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.nlink < 1
      || metadata.uid !== 0 && metadata.uid !== currentUser || !final && (mode & 0o022) !== 0
      || final && (metadata.uid !== currentUser || !allowedModes.includes(mode))) fail();
  }
}

async function ensurePrivateDirectory(target) {
  await ensureDirectory(target, 0o700, [0o700]);
}

async function extract(entries, destination) {
  await ensurePrivateDirectory(destination);
  for (const entry of entries) {
    const target = path.join(destination, ...entry.path.split('/'));
    if (target !== path.resolve(target) || !target.startsWith(`${destination}${path.sep}`)) fail('ARCHIVE_UNSAFE');
    await ensurePrivateDirectory(path.dirname(target));
    await fs.writeFile(target, entry.bytes, { flag: 'wx', mode: entry.mode });
    await fs.chmod(target, entry.mode);
    const metadata = await fs.lstat(target);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== entry.mode
      || metadata.size !== entry.size || digest(await fs.readFile(target)) !== entry.sha256) fail('ARCHIVE_UNSAFE');
  }
}

function markerFor(manifest, entries) {
  return { schemaVersion: 1, managerVersion: manifest.managerVersion, sourceRevision: manifest.sourceRevision,
    payloadSha256: manifest.payload.sha256,
    files: entries.map(({ path: filePath, mode, size, sha256 }) => ({ path: filePath, mode, size, sha256 })) };
}

async function writeExclusiveJson(target, value) {
  await fs.writeFile(target, `${JSON.stringify(value)}\n`, { flag: 'wx', mode: 0o600 });
  await fs.chmod(target, 0o600);
}

async function validateRelease(directory, expected = undefined) {
  await inspectDirectory(directory);
  const markerPath = path.join(directory, '.claudex-release.json');
  const markerMetadata = await fs.lstat(markerPath);
  if (!markerMetadata.isFile() || markerMetadata.isSymbolicLink() || markerMetadata.nlink !== 1
    || (markerMetadata.mode & 0o777) !== 0o600 || markerMetadata.uid !== process.getuid()) fail();
  let marker;
  try { marker = JSON.parse(await fs.readFile(markerPath, 'utf8')); } catch { fail(); }
  if (!exact(marker, ['schemaVersion', 'managerVersion', 'sourceRevision', 'payloadSha256', 'files']) || marker.schemaVersion !== 1
    || !VERSION.test(marker.managerVersion) || !REVISION.test(marker.sourceRevision) || !SHA256.test(marker.payloadSha256)
    || !Array.isArray(marker.files) || marker.files.length < 1 || marker.files.length > 10_000) fail();
  if (expected && (marker.managerVersion !== expected.managerVersion || marker.sourceRevision !== expected.sourceRevision
    || marker.payloadSha256 !== expected.payload.sha256)) fail();
  let prior = '';
  for (const entry of marker.files) {
    if (!exact(entry, ['path', 'mode', 'size', 'sha256']) || safeArchivePath(entry.path, prior) !== entry.path
      || ![0o644, 0o755].includes(entry.mode) || !Number.isSafeInteger(entry.size) || entry.size < 0 || !SHA256.test(entry.sha256)) fail();
    prior = entry.path;
    const target = path.join(directory, ...entry.path.split('/'));
    const metadata = await fs.lstat(target);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || metadata.size !== entry.size
      || metadata.uid !== process.getuid() || (metadata.mode & 0o777) !== entry.mode
      || digest(await fs.readFile(target)) !== entry.sha256) fail();
  }
  const actual = [];
  async function walk(current, prefix = '') {
    const children = await fs.readdir(current, { withFileTypes: true });
    children.sort((left, right) => left.name.localeCompare(right.name, 'en'));
    for (const child of children) {
      const relative = prefix ? `${prefix}/${child.name}` : child.name;
      if (child.isSymbolicLink() || !child.isDirectory() && !child.isFile()) fail();
      if (child.isDirectory()) {
        await inspectDirectory(path.join(current, child.name));
        await walk(path.join(current, child.name), relative);
      } else actual.push(relative);
    }
  }
  await walk(directory);
  const expectedFiles = ['.claudex-release.json', ...marker.files.map(({ path: filePath }) => filePath)].sort();
  if (JSON.stringify(actual.sort()) !== JSON.stringify(expectedFiles)) fail();
  return marker;
}

function launcherBytes(nodePath, managerPath, profile) {
  const fixed = [nodePath, managerPath, ...profile].map(quote).join(' ');
  return Buffer.from(`#!/bin/sh\nexec ${fixed} "$@"\n`, 'utf8');
}

async function installLauncher(target, bytes) {
  try {
    const metadata = await fs.lstat(target);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o755
      || metadata.uid !== process.getuid() || digest(await fs.readFile(target)) !== digest(bytes)) fail();
    return false;
  } catch (error) { if (error?.code !== 'ENOENT') throw error; }
  const temporary = `${target}.${crypto.randomUUID()}.tmp`;
  try {
    await fs.writeFile(temporary, bytes, { flag: 'wx', mode: 0o755 });
    await fs.chmod(temporary, 0o755);
    await fs.link(temporary, target);
  } finally { await fs.rm(temporary, { force: true }); }
  return true;
}

async function removeOwnedLauncher(target, bytes) {
  const metadata = await fs.lstat(target);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o755
    || metadata.uid !== process.getuid() || digest(await fs.readFile(target)) !== digest(bytes)) fail();
  await fs.unlink(target);
}

async function captureLaunchers(stage) {
  const capture = path.join(stage, 'capture');
  await ensurePrivateDirectory(capture);
  const captureManager = path.join(capture, 'capture.mjs');
  const captureOutput = path.join(capture, 'capture.jsonl');
  const source = "import fs from 'node:fs'; fs.appendFileSync(process.env.CLDX_CAPTURE_FILE, JSON.stringify(process.argv.slice(2)) + '\\n');\n";
  await fs.writeFile(captureManager, source, { flag: 'wx', mode: 0o600 });
  const profiles = [['claudexctl', []], ['claudex', ['launcher', 'claudex']], ['claude-agy', ['launcher', 'claude-agy']]];
  const hostile = ['', 'two words', 'quote"value', "single'value", '$()', '%PATH%', '--flag', 'line\nbreak'];
  for (const [name, profile] of profiles) {
    const target = path.join(capture, name);
    await fs.writeFile(target, launcherBytes(process.execPath, captureManager, profile), { flag: 'wx', mode: 0o755 });
    await fs.chmod(target, 0o755);
    const result = spawnSync(target, hostile, { env: { CLDX_CAPTURE_FILE: captureOutput }, shell: false,
      encoding: 'utf8', timeout: 10_000, maxBuffer: 64 * 1024 });
    if (result.error || result.status !== 0 || result.signal !== null || result.stdout !== '' || result.stderr !== '') fail();
  }
  const rows = (await fs.readFile(captureOutput, 'utf8')).trim().split('\n').map(JSON.parse);
  if (rows.length !== 3 || JSON.stringify(rows) !== JSON.stringify([
    hostile, ['launcher', 'claudex', ...hostile], ['launcher', 'claude-agy', ...hostile]
  ])) fail();
  await fs.rm(capture, { recursive: true });
}

function safeEnvironment() {
  const result = {};
  for (const key of ['HOME', 'PATH', 'XDG_DATA_HOME', 'XDG_CONFIG_HOME', 'XDG_STATE_HOME', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TERM']) {
    const value = process.env[key];
    if (typeof value === 'string' && value.length > 0 && !/[\u0000\r\n]/u.test(value)) result[key] = value;
  }
  return result;
}

async function selfTestRelease(directory, version) {
  const packageJson = JSON.parse(await fs.readFile(path.join(directory, 'package.json'), 'utf8'));
  if (!packageJson || packageJson.name !== 'claudexctl' || packageJson.version !== version || packageJson.type !== 'module'
    || packageJson.dependencies || packageJson.optionalDependencies || packageJson.peerDependencies) fail();
  const manager = path.join(directory, 'bin', 'claudexctl.js');
  const syntax = spawnSync(process.execPath, ['--check', manager], { encoding: 'utf8', shell: false,
    timeout: 10_000, maxBuffer: 64 * 1024, env: safeEnvironment() });
  if (syntax.error || syntax.status !== 0 || syntax.signal !== null || syntax.stdout !== '' || syntax.stderr !== '') fail();
  const help = spawnSync(process.execPath, [manager, '--help'], { encoding: 'utf8', shell: false,
    timeout: 10_000, maxBuffer: 256 * 1024, env: safeEnvironment() });
  if (help.error || help.status !== 0 || help.signal !== null || help.stderr !== '' || !help.stdout.includes('claudexctl setup')) fail();
}

async function pointerTarget(root, name, optional = false) {
  const pointer = path.join(root, name);
  let metadata;
  try { metadata = await fs.lstat(pointer); } catch (error) {
    if (optional && error?.code === 'ENOENT') return null;
    throw error;
  }
  if (!metadata.isSymbolicLink()) fail();
  if (metadata.uid !== process.getuid()) fail();
  const target = await fs.readlink(pointer);
  if (!/^releases\/[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u.test(target)) fail();
  await validateRelease(path.join(root, ...target.split('/')));
  return target;
}

async function setPointer(root, name, target) {
  if (!/^releases\/[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u.test(target)) fail();
  const pointer = path.join(root, name);
  try { const metadata = await fs.lstat(pointer); if (!metadata.isSymbolicLink()) fail(); }
  catch (error) { if (error?.code !== 'ENOENT') throw error; }
  const temporary = path.join(root, `.${name}-${crypto.randomUUID()}.tmp`);
  try { await fs.symlink(target, temporary); await fs.rename(temporary, pointer); }
  finally { await fs.rm(temporary, { force: true }); }
}

async function removePointer(root, name, expected) {
  const actual = await pointerTarget(root, name, true);
  if (actual === null) return;
  if (actual !== expected) fail();
  await fs.unlink(path.join(root, name));
}

async function writeJournal(stateRoot, value) {
  const target = path.join(stateRoot, 'manager-journal.json');
  const temporary = path.join(stateRoot, `.manager-journal-${crypto.randomUUID()}.tmp`);
  try {
    await writeExclusiveJson(temporary, value);
    await fs.link(temporary, target);
  } finally { await fs.rm(temporary, { force: true }); }
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function moveAndRemoveLock(lock, stateRoot, expected, allowedChildren) {
  const quarantine = path.join(stateRoot, `.manager-lock-${crypto.randomUUID()}.quarantine`);
  await fs.rename(lock, quarantine);
  const moved = await fs.lstat(quarantine, { bigint: true });
  const children = (await fs.readdir(quarantine)).sort();
  if (!moved.isDirectory() || moved.isSymbolicLink() || !sameIdentity(moved, expected)
    || JSON.stringify(children) !== JSON.stringify([...allowedChildren].sort())) fail();
  await fs.rm(quarantine, { recursive: true });
}

async function acquireBootstrapLock(stateRoot) {
  const lock = path.join(stateRoot, 'manager-bootstrap.lock');
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      await fs.mkdir(lock, { mode: 0o700 });
      const identity = await fs.lstat(lock, { bigint: true });
      if (!identity.isDirectory() || identity.isSymbolicLink() || (identity.mode & 0o777n) !== 0o700n) fail();
      const owner = { schemaVersion: 1, pid: process.pid, createdAtMs: Date.now() };
      await writeExclusiveJson(path.join(lock, 'owner.json'), owner);
      let released = false;
      return async () => {
        if (released) return;
        released = true;
        const current = await fs.lstat(lock, { bigint: true });
        const stored = JSON.parse(await fs.readFile(path.join(lock, 'owner.json'), 'utf8'));
        if (!sameIdentity(current, identity) || !exact(stored, ['schemaVersion', 'pid', 'createdAtMs'])
          || stored.schemaVersion !== 1 || stored.pid !== process.pid || stored.createdAtMs !== owner.createdAtMs) fail();
        await moveAndRemoveLock(lock, stateRoot, identity, ['owner.json']);
      };
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      const identity = await fs.lstat(lock, { bigint: true });
      if (!identity.isDirectory() || identity.isSymbolicLink() || (identity.mode & 0o777n) !== 0o700n) fail();
      let owner;
      try { owner = JSON.parse(await fs.readFile(path.join(lock, 'owner.json'), 'utf8')); }
      catch (readError) {
        const children = await fs.readdir(lock);
        const oldEnough = Date.now() - Number(identity.mtimeMs) > 300_000;
        if (readError?.code !== 'ENOENT' || children.length !== 0 || !oldEnough) fail('LOCK_BUSY', 6);
        await moveAndRemoveLock(lock, stateRoot, identity, []);
        continue;
      }
      if (!exact(owner, ['schemaVersion', 'pid', 'createdAtMs']) || owner.schemaVersion !== 1
        || !Number.isSafeInteger(owner.pid) || owner.pid < 1 || !Number.isSafeInteger(owner.createdAtMs)
        || owner.createdAtMs < 0 || owner.createdAtMs > Date.now()) fail();
      let alive = true;
      try { process.kill(owner.pid, 0); } catch (killError) { if (killError?.code === 'ESRCH') alive = false; }
      if (alive) fail('LOCK_BUSY', 6);
      await moveAndRemoveLock(lock, stateRoot, identity, ['owner.json']);
    }
  }
  fail('LOCK_BUSY', 6);
}

async function restorePointer(root, name, target) {
  if (target === null) {
    const actual = await pointerTarget(root, name, true);
    if (actual !== null) await removePointer(root, name, actual);
  } else await setPointer(root, name, target);
}

async function recover(managerRoot, stateRoot) {
  const journalPath = path.join(stateRoot, 'manager-journal.json');
  let journal;
  try { journal = JSON.parse(await fs.readFile(journalPath, 'utf8')); }
  catch (error) { if (error?.code === 'ENOENT') return; fail(); }
  if (!exact(journal, ['schemaVersion', 'operation', 'oldCurrent', 'oldPrevious', 'newCurrent']) || journal.schemaVersion !== 1
    || !['activate', 'rollback'].includes(journal.operation)
    || ![journal.oldCurrent, journal.oldPrevious, journal.newCurrent].every((value) => value === null
      || /^releases\/[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u.test(value))) fail();
  await restorePointer(managerRoot, 'current', journal.oldCurrent);
  await restorePointer(managerRoot, 'previous', journal.oldPrevious);
  await fs.unlink(journalPath);
}

async function activate(managerRoot, stateRoot, userBin, target, setupArgs) {
  const current = await pointerTarget(managerRoot, 'current', true);
  const previous = await pointerTarget(managerRoot, 'previous', true);
  if (current === target) {
    const result = spawnSync(path.join(userBin, 'claudexctl'), setupArgs, { stdio: 'inherit', shell: false,
      timeout: 120_000, env: safeEnvironment() });
    if (result.error || result.status !== 0 || result.signal !== null) fail();
    return;
  }
  const journal = { schemaVersion: 1, operation: 'activate', oldCurrent: current, oldPrevious: previous, newCurrent: target };
  await writeJournal(stateRoot, journal);
  try {
    if (current === null) await restorePointer(managerRoot, 'previous', null);
    else await setPointer(managerRoot, 'previous', current);
    await setPointer(managerRoot, 'current', target);
    const result = spawnSync(path.join(userBin, 'claudexctl'), setupArgs, { stdio: 'inherit', shell: false,
      timeout: 120_000, env: safeEnvironment() });
    if (result.error || result.status !== 0 || result.signal !== null) fail();
    await fs.unlink(path.join(stateRoot, 'manager-journal.json'));
  } catch (error) {
    await restorePointer(managerRoot, 'current', current);
    await restorePointer(managerRoot, 'previous', previous);
    await fs.rm(path.join(stateRoot, 'manager-journal.json'), { force: true });
    throw error;
  }
}

async function rollback(managerRoot, stateRoot) {
  const current = await pointerTarget(managerRoot, 'current', true);
  const previous = await pointerTarget(managerRoot, 'previous', true);
  if (current === null || previous === null || current === previous) fail('ROLLBACK_UNAVAILABLE', 8);
  await writeJournal(stateRoot, { schemaVersion: 1, operation: 'rollback', oldCurrent: current,
    oldPrevious: previous, newCurrent: previous });
  try {
    await setPointer(managerRoot, 'current', previous);
    const marker = await validateRelease(path.join(managerRoot, ...previous.split('/')));
    await selfTestRelease(path.join(managerRoot, ...previous.split('/')), marker.managerVersion);
    await removePointer(managerRoot, 'previous', previous);
    await fs.unlink(path.join(stateRoot, 'manager-journal.json'));
  } catch (error) {
    await restorePointer(managerRoot, 'current', current);
    await restorePointer(managerRoot, 'previous', previous);
    await fs.rm(path.join(stateRoot, 'manager-journal.json'), { force: true });
    throw error;
  }
}

async function installLaunchers(managerRoot, userBin) {
  await ensureDirectory(userBin, 0o755, [0o700, 0o755]);
  const manager = path.join(managerRoot, 'current', 'bin', 'claudexctl.js');
  const created = [];
  try {
    for (const [name, profile] of [['claudexctl', []], ['claudex', ['launcher', 'claudex']],
      ['claude-agy', ['launcher', 'claude-agy']]]) {
      const target = path.join(userBin, name); const bytes = launcherBytes(process.execPath, manager, profile);
      if (await installLauncher(target, bytes)) created.push({ target, bytes });
    }
    return created;
  } catch (error) {
    for (const launcher of created.reverse()) await removeOwnedLauncher(launcher.target, launcher.bytes);
    throw error;
  }
}

async function removeCreatedLaunchers(created) {
  for (const launcher of [...created].reverse()) await removeOwnedLauncher(launcher.target, launcher.bytes);
}

async function main() {
  const projectOrigin = new URL(process.env.CLDX_PROJECT_ORIGIN);
  const releaseBase = projectOrigin.href.endsWith('/') ? projectOrigin.href : `${projectOrigin.href}/`;
  const requestedVersion = process.env.CLDX_MANAGER_VERSION;
  const managerRoot = process.env.CLDX_MANAGER_ROOT;
  const stateRoot = process.env.CLDX_STATE_ROOT;
  const userBin = process.env.CLDX_USER_BIN;
  const target = process.env.CLDX_TARGET;
  if (!['https:', 'http:'].includes(projectOrigin.protocol) || projectOrigin.pathname.includes('..')
    || projectOrigin.username || projectOrigin.password || projectOrigin.search || projectOrigin.hash
    || !path.isAbsolute(managerRoot) || !path.isAbsolute(stateRoot) || !path.isAbsolute(userBin)
    || !['linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64'].includes(target)) fail();
  await ensurePrivateDirectory(managerRoot);
  await ensurePrivateDirectory(path.join(managerRoot, 'releases'));
  await ensurePrivateDirectory(path.join(managerRoot, 'staging'));
  await ensurePrivateDirectory(stateRoot);
  const releaseLock = await acquireBootstrapLock(stateRoot);
  try {
    await recover(managerRoot, stateRoot);
    if (process.env.CLDX_ROLLBACK_MANAGER === '1') {
      const createdLaunchers = await installLaunchers(managerRoot, userBin);
      try { await rollback(managerRoot, stateRoot); }
      catch (error) { await removeCreatedLaunchers(createdLaunchers); throw error; }
      return;
    }

  const manifestUrl = requestedVersion
    ? `${releaseBase}releases/download/v${requestedVersion}/project-manifest.json`
    : `${releaseBase}releases/latest/download/project-manifest.json`;
  const manifestBytes = await download(manifestUrl, MAX_MANIFEST, projectOrigin);
  let manifest;
  try { manifest = checkedManifest(JSON.parse(manifestBytes.toString('utf8')), requestedVersion, target); }
  catch (error) { if (error instanceof BootstrapFailure) throw error; fail('CHECKSUM_MISMATCH'); }
  const payloadUrl = `${releaseBase}releases/download/v${manifest.managerVersion}/${manifest.payload.name}`;
  const payload = await download(payloadUrl, MAX_PAYLOAD, projectOrigin);
  if (payload.length !== manifest.payload.size || digest(payload) !== manifest.payload.sha256) fail('CHECKSUM_MISMATCH');
  const entries = parseArchive(payload);
  const releaseId = `${manifest.managerVersion}-${manifest.payload.sha256}`;
  const releaseTarget = `releases/${releaseId}`;
  const releaseDirectory = path.join(managerRoot, 'releases', releaseId);
  const staging = await fs.mkdtemp(path.join(managerRoot, 'staging', 'candidate-'));
  await fs.chmod(staging, 0o700);
  try {
    await extract(entries, staging);
    await writeExclusiveJson(path.join(staging, '.claudex-release.json'), markerFor(manifest, entries));
    await selfTestRelease(staging, manifest.managerVersion);
    await captureLaunchers(staging);
    try {
      await fs.rename(staging, releaseDirectory);
    } catch (error) {
      if (error?.code !== 'EEXIST' && error?.code !== 'ENOTEMPTY') throw error;
      await validateRelease(releaseDirectory, manifest);
    }
    await validateRelease(releaseDirectory, manifest);
  } finally {
    try {
      const metadata = await fs.lstat(staging);
      if (metadata.isDirectory() && !metadata.isSymbolicLink()) await fs.rm(staging, { recursive: true });
    } catch (error) { if (error?.code !== 'ENOENT') throw error; }
  }
  const createdLaunchers = await installLaunchers(managerRoot, userBin);
  const setupArgs = ['setup'];
  if (process.env.CLDX_ACCEPT_YES === '1') setupArgs.push('--yes');
  if (process.env.CLDX_NO_PATH === '1') setupArgs.push('--no-path');
    try { await activate(managerRoot, stateRoot, userBin, releaseTarget, setupArgs); }
    catch (error) { await removeCreatedLaunchers(createdLaunchers); throw error; }
  } finally { await releaseLock(); }
}

try { await main(); }
catch (error) {
  const code = error instanceof BootstrapFailure ? error.code : 'SAFETY_REFUSAL';
  const exitCode = error instanceof BootstrapFailure ? error.exitCode : 7;
  process.stderr.write(`error[${code}]: The manager bootstrap failed safely.\n`);
  process.exitCode = exitCode;
}
NODE
bootstrap_status=$?
set -e
exit "$bootstrap_status"
