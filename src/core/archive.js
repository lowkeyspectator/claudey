import { spawn as spawnChild } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateRawSync } from 'node:zlib';

import { ClaudexError } from './errors.js';
import { assertWindowsDacl, runWindowsSecurityHelper } from '../platform/windows-helpers.js';

export const ARCHIVE_LIMITS = Object.freeze({
  archiveBytes: 268435456,
  entries: 2048,
  expandedBytes: 536870912,
  entryBytes: 268435456,
  expansionRatio: 100,
  extractionDeadlineMs: 120000,
  outputBytes: 65536,
  pathBytes: 4096,
  componentBytes: 255
});

const LIMIT_KEYS = Object.freeze(Object.keys(ARCHIVE_LIMITS));
const ZIP_EOCD_BYTES = 22;
const ZIP_LOCAL_HEADER_BYTES = 30;
const ZIP_CENTRAL_HEADER_BYTES = 46;
const TAR_BLOCK_BYTES = 512;
const ZIP_ALLOWED_FLAGS = 0x0800;
const FIXED_POWERSHELL_PATH = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const WINDOWS_HELPER_BOOTSTRAP = String.raw`$ErrorActionPreference = 'Stop'
$powershellSha256 = $env:CLAUDEX_ARCHIVE_POWERSHELL_SHA256
$helperPath = $env:CLAUDEX_ARCHIVE_HELPER_PATH
$helperSha256 = $env:CLAUDEX_ARCHIVE_HELPER_SHA256
$requestPath = $env:CLAUDEX_ARCHIVE_REQUEST_PATH
$requestSha256 = $env:CLAUDEX_ARCHIVE_REQUEST_SHA256
$destinationVolume = $env:CLAUDEX_ARCHIVE_DESTINATION_VOLUME
$destinationFileId = $env:CLAUDEX_ARCHIVE_DESTINATION_FILE_ID
if ($powershellSha256 -notmatch '^[a-f0-9]{64}$' -or $helperSha256 -notmatch '^[a-f0-9]{64}$' -or $requestSha256 -notmatch '^[a-f0-9]{64}$' -or
    $destinationVolume -notmatch '^(0|[1-9][0-9]*)$' -or $destinationFileId -notmatch '^(0|[1-9][0-9]*)$') { exit 1 }

$selfStream = $null
$stream = $null
try {
    $selfPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $fixedSelf = [IO.Path]::Combine($env:SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    if (-not $selfPath.Equals($fixedSelf, [StringComparison]::OrdinalIgnoreCase)) { throw 'PowerShell path.' }
    $acl = Get-Acl -LiteralPath $selfPath
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -eq $currentSid) { throw 'PowerShell owner.' }
    $unsafeRights = [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $untrustedSids = @($currentSid, 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')
    foreach ($rule in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $rule.IdentityReference.Value -in $untrustedSids -and ($rule.FileSystemRights -band $unsafeRights) -ne 0) {
            throw 'PowerShell ACL.'
        }
    }
    $selfStream = [IO.File]::Open($selfPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $selfSha = [Security.Cryptography.SHA256]::Create()
    try { $actualSelf = ([BitConverter]::ToString($selfSha.ComputeHash($selfStream))).Replace('-', '').ToLowerInvariant() } finally { $selfSha.Dispose() }
    if ($actualSelf -ne $powershellSha256) { exit 1 }
    $stream = [IO.File]::Open($helperPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $actual = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
    if ($actual -ne $helperSha256) { exit 1 }
    $stream.Position = 0
    $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false), $true, 4096, $true)
    try { $scriptText = $reader.ReadToEnd() } finally { $reader.Dispose() }
    & ([ScriptBlock]::Create($scriptText)) -RequestPath $requestPath -ExpectedRequestSha256 $requestSha256 -ExpectedDestinationVolume $destinationVolume -ExpectedDestinationFileId $destinationFileId
} catch { exit 1 } finally { if ($null -ne $stream) { $stream.Dispose() }; if ($null -ne $selfStream) { $selfStream.Dispose() } }`;
const WINDOWS_HELPER_BOOTSTRAP_ENCODED = Buffer.from(WINDOWS_HELPER_BOOTSTRAP, 'utf16le').toString('base64');
const WINDOWS_CANDIDATE_PIN = String.raw`$ErrorActionPreference = 'Stop'
$CandidatePath = $env:CLAUDEX_CANDIDATE_PATH
$ExpectedVolume = $env:CLAUDEX_CANDIDATE_VOLUME
$ExpectedFileId = $env:CLAUDEX_CANDIDATE_FILE_ID
$ExpectedSize = $env:CLAUDEX_CANDIDATE_SIZE
$ExpectedSha256 = $env:CLAUDEX_CANDIDATE_SHA256
$ExpectedPowerShellSha256 = $env:CLAUDEX_CANDIDATE_POWERSHELL_SHA256
Add-Type @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class ClaudexCandidateIdentity {
  [StructLayout(LayoutKind.Sequential)] public struct Info {
    public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation;
    public System.Runtime.InteropServices.ComTypes.FILETIME Access; public System.Runtime.InteropServices.ComTypes.FILETIME Write;
    public uint Volume; public uint SizeHigh; public uint SizeLow; public uint Links; public uint IndexHigh; public uint IndexLow;
  }
  [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
}
'@

$selfStream = $null
$stream = $null
try {
  if ($ExpectedPowerShellSha256 -notmatch '^[a-f0-9]{64}$') { throw 'PowerShell digest.' }
  $selfPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
  $fixedSelf = [IO.Path]::Combine($env:SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
  if (-not $selfPath.Equals($fixedSelf, [StringComparison]::OrdinalIgnoreCase)) { throw 'PowerShell path.' }
  $acl = Get-Acl -LiteralPath $selfPath
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($ownerSid -eq $currentSid) { throw 'PowerShell owner.' }
  $unsafeRights = [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor
      [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
      [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::Delete -bor
      [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  $untrustedSids = @($currentSid, 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')
  foreach ($rule in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
      $rule.IdentityReference.Value -in $untrustedSids -and ($rule.FileSystemRights -band $unsafeRights) -ne 0) {
      throw 'PowerShell ACL.'
    }
  }
  $selfStream = [IO.File]::Open($selfPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  $selfSha = [Security.Cryptography.SHA256]::Create()
  try { $actualSelf = ([BitConverter]::ToString($selfSha.ComputeHash($selfStream))).Replace('-', '').ToLowerInvariant() } finally { $selfSha.Dispose() }
  if ($actualSelf -ne $ExpectedPowerShellSha256) { throw 'PowerShell digest.' }
  if ($ExpectedVolume -notmatch '^(0|[1-9][0-9]*)$' -or $ExpectedFileId -notmatch '^(0|[1-9][0-9]*)$' -or
      $ExpectedSize -notmatch '^(0|[1-9][0-9]*)$' -or $ExpectedSha256 -notmatch '^[a-f0-9]{64}$') { throw 'Input.' }
  $stream = [IO.File]::Open($CandidatePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  $info = New-Object ClaudexCandidateIdentity+Info
  if (-not [ClaudexCandidateIdentity]::GetFileInformationByHandle($stream.SafeFileHandle, [ref]$info)) { throw 'Identity.' }
  $fileId = ([uint64]$info.IndexHigh -shl 32) -bor [uint64]$info.IndexLow
  if ([string]$info.Volume -ne $ExpectedVolume -or [string]$fileId -ne $ExpectedFileId -or [string]$stream.Length -ne $ExpectedSize) { throw 'Identity.' }
  $sha = [Security.Cryptography.SHA256]::Create()
  try { $actual = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
  if ($actual -ne $ExpectedSha256) { throw 'Digest.' }
  [Console]::Out.WriteLine('CLAUDEX_CANDIDATE_PIN_READY'); [Console]::Out.Flush()
  if ([Console]::In.ReadLine() -ne 'release') { throw 'Protocol.' }
} catch { [Console]::Error.Write('Candidate pin refused.'); exit 1 } finally { if ($null -ne $stream) { $stream.Dispose() }; if ($null -ne $selfStream) { $selfStream.Dispose() } }`;
const WINDOWS_CANDIDATE_PIN_ENCODED = Buffer.from(WINDOWS_CANDIDATE_PIN, 'utf16le').toString('base64');
export const ARCHIVE_HELPER_PATH = fileURLToPath(new URL('../../scripts/windows/archive-helper.ps1', import.meta.url));
const FIXED_POSIX_TAR_PATHS = new Set(['/usr/bin/tar', '/bin/tar']);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const validatedPlans = new WeakSet();
const extractedCandidates = new WeakMap();

function unsafe(message = 'The release archive is unsafe.', cause) {
  return new ClaudexError('ARCHIVE_UNSAFE', message, cause ? { cause } : undefined);
}

function checkedInteger(value, label, { positive = false } = {}) {
  if (!Number.isSafeInteger(value) || value < 0 || (positive && value === 0)) {
    throw unsafe(`The archive ${label} is invalid.`);
  }
  return value;
}

function checkedAdd(left, right, label) {
  checkedInteger(left, label);
  checkedInteger(right, label);
  if (left > Number.MAX_SAFE_INTEGER - right) throw unsafe(`The archive ${label} overflowed.`);
  return left + right;
}

function checkedMultiply(left, right, label) {
  checkedInteger(left, label);
  checkedInteger(right, label);
  if (left !== 0 && right > Math.floor(Number.MAX_SAFE_INTEGER / left)) throw unsafe(`The archive ${label} overflowed.`);
  return left * right;
}

function normalizeLimits(input) {
  if (input !== undefined && (!input || typeof input !== 'object' || Array.isArray(input))) {
    throw unsafe('The archive limits are invalid.');
  }
  if (input) {
    for (const key of Object.keys(input)) if (!LIMIT_KEYS.includes(key)) throw unsafe('The archive limits contain an unknown field.');
  }
  const limits = { ...ARCHIVE_LIMITS, ...input };
  for (const key of LIMIT_KEYS) {
    checkedInteger(limits[key], `${key} limit`, { positive: true });
    if (limits[key] > ARCHIVE_LIMITS[key]) {
      throw unsafe(`The archive ${key} limit cannot exceed its fixed ceiling.`);
    }
  }
  return Object.freeze(limits);
}

function exactKeys(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw unsafe(`The ${label} is malformed.`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw unsafe(`The ${label} has unknown or missing fields.`);
  }
}

function sameHostPath(left, right) {
  const normalizedLeft = path.normalize(left);
  const normalizedRight = path.normalize(right);
  return process.platform === 'win32'
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

function sameIdentity(stats, identity) {
  return stats.dev === identity.dev && stats.ino === identity.ino;
}

function exactIdentity(stats) {
  return { dev: String(stats.dev), ino: String(stats.ino) };
}

function sameExactIdentity(stats, expected) {
  return String(stats.dev) === expected.dev && String(stats.ino) === expected.ino;
}
function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sameDigest(left, right) {
  if (!/^[a-f0-9]{64}$/.test(left) || !/^[a-f0-9]{64}$/.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function decodeUtf8(bytes, label) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (cause) {
    throw unsafe(`The archive ${label} is not valid UTF-8.`, cause);
  }
}
function windowsCollisionSegment(segment) {
  return segment.normalize('NFC').toUpperCase().toLowerCase().replace(/[. ]+$/u, '').replaceAll('\u03c2', '\u03c3');
}


function archivePathPolicy(rawPath, type, targetPlatform, limits) {
  if (typeof rawPath !== 'string' || rawPath.length === 0 || Buffer.byteLength(rawPath, 'utf8') > limits.pathBytes
    || /[\u0000-\u001f\u007f]/u.test(rawPath)) {
    throw unsafe('An archive entry path is invalid.');
  }
  if (rawPath.startsWith('/') || rawPath.startsWith('\\') || /^[a-zA-Z]:/.test(rawPath) || rawPath.includes(':')) {
    throw unsafe('An archive entry path is absolute or drive-qualified.');
  }
  if (rawPath.includes('//')) throw unsafe('An archive entry path contains a separator alias.');
  const hasTrailingSlash = /[\\/]$/.test(rawPath);
  if ((type === 'directory') !== hasTrailingSlash) throw unsafe('An archive entry path has inconsistent type syntax.');
  const separated = rawPath.replaceAll('\\', '/');
  const rawSegments = separated.split('/').filter((segment, index, all) => !(index === all.length - 1 && segment === ''));
  if (rawSegments.length === 0 || rawSegments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw unsafe('An archive entry path traverses or aliases a destination.');
  }
  for (const segment of rawSegments) {
    if (Buffer.byteLength(segment, 'utf8') > limits.componentBytes) throw unsafe('An archive entry path component is too long.');
  }
  const normalizedSegments = rawSegments.map((segment) => segment.normalize('NFC'));
  const canonical = normalizedSegments.join('/');
  const collisionSegments = normalizedSegments.map((segment) => {
    if (targetPlatform !== 'win32') return segment;
    const folded = windowsCollisionSegment(segment);
    if (folded.length === 0 || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(folded)) {
      throw unsafe('An archive entry path is reserved on Windows.');
    }
    return folded;
  });
  return { canonical, collisionKey: collisionSegments.join('/'), segments: normalizedSegments };
}

function entryModePolicy(mode, type, targetPlatform) {
  if (targetPlatform === 'win32') return null;
  if (!Number.isSafeInteger(mode) || mode < 0 || (mode & ~0o777) !== 0) throw unsafe('An archive entry mode is unsafe.');
  if (type === 'directory') {
    if (mode !== 0o755) throw unsafe('An archive directory mode is unsafe.');
    return mode;
  }
  if (mode !== 0o644 && mode !== 0o755) throw unsafe('An archive file mode is unsafe.');
  return mode;
}

function checkAggregateLimits(entries, compressedBytes, limits) {
  if (entries.length > limits.entries) throw unsafe('The archive contains too many entries.');
  let expandedBytes = 0;
  for (const entry of entries) {
    checkedInteger(entry.size, 'entry size');
    if (entry.size > limits.entryBytes) throw unsafe('An archive entry exceeds the expanded size limit.');
    expandedBytes = checkedAdd(expandedBytes, entry.size, 'expanded size');
    if (expandedBytes > limits.expandedBytes) throw unsafe('The archive exceeds the expanded size limit.');
  }
  checkedInteger(compressedBytes, 'compressed payload size');
  if (compressedBytes === 0 && expandedBytes !== 0) throw unsafe('The archive has an infinite expansion ratio.');
  if (compressedBytes !== 0 && expandedBytes > checkedMultiply(compressedBytes, limits.expansionRatio, 'expansion ratio')) {
    throw unsafe('The archive exceeds the expansion ratio limit.');
  }
  return expandedBytes;
}
export function testArchiveLimitPolicy(entries, compressedBytes, overrides, archiveBytes = compressedBytes) {
  const limits = normalizeLimits(overrides);
  checkedInteger(archiveBytes, 'archive byte count');
  if (archiveBytes > limits.archiveBytes) throw unsafe('The archive compressed byte ceiling was exceeded.');
  return Object.freeze({
    entryCount: entries.length,
    expandedBytes: checkAggregateLimits(entries, compressedBytes, limits)
  });
}

function addPlannedEntry(state, rawEntry) {
  const normalized = archivePathPolicy(rawEntry.rawPath, rawEntry.type, state.targetPlatform, state.limits);
  if (state.destinations.has(normalized.collisionKey)) throw unsafe('Archive entry destinations collide.');
  state.destinations.set(normalized.collisionKey, rawEntry.type);
  for (let index = 1; index < normalized.segments.length; index += 1) {
    const ancestor = normalized.segments.slice(0, index).map((segment) => state.targetPlatform === 'win32'
      ? windowsCollisionSegment(segment)
      : segment).join('/');
    if (state.destinations.get(ancestor) === 'file') throw unsafe('An archive file overlaps a descendant destination.');
  }
  if (rawEntry.type === 'file') {
    const prefix = `${normalized.collisionKey}/`;
    for (const key of state.destinations.keys()) if (key.startsWith(prefix)) throw unsafe('An archive file overlaps a descendant destination.');
  }
  const entry = {
    path: normalized.canonical,
    type: rawEntry.type,
    size: rawEntry.size,
    sha256: rawEntry.type === 'file' ? rawEntry.sha256 : null,
    mode: entryModePolicy(rawEntry.mode, rawEntry.type, state.targetPlatform)
  };
  state.entries.push(entry);
}

function zipType(versionMadeBy, attributes, rawName) {
  const creator = versionMadeBy >>> 8;
  const unixMode = (attributes >>> 16) & 0xffff;
  const dosAttributes = attributes & 0xffff;
  const dosDirectory = (dosAttributes & 0x10) !== 0;
  if (creator === 3) {
    const fileType = unixMode & 0xf000;
    const type = fileType === 0x4000 ? 'directory' : fileType === 0x8000 ? 'file' : null;
    if (!type) throw unsafe('A ZIP entry has a special filesystem type.');
    const allowed = type === 'directory' ? [0x10, 0x30] : [0, 0x20];
    if (!allowed.includes(dosAttributes)) throw unsafe('A ZIP entry has unsafe DOS attributes.');
    if ((type === 'directory') !== rawName.endsWith('/')) throw unsafe('A ZIP entry type disagrees with its path syntax.');
    return type;
  }
  const allowedDosAttributes = dosDirectory ? 0x10 : 0x20;
  if (unixMode !== 0 || attributes !== allowedDosAttributes) throw unsafe('A ZIP entry has unsafe external attributes.');
  if (dosDirectory !== rawName.endsWith('/')) throw unsafe('A ZIP entry type disagrees with its path syntax.');
  return dosDirectory || rawName.endsWith('/') ? 'directory' : 'file';
}

function parseZip(bytes, state) {
  if (bytes.length < ZIP_EOCD_BYTES) throw unsafe('The ZIP end record is missing.');
  const eocdOffset = bytes.length - ZIP_EOCD_BYTES;
  if (bytes.readUInt32LE(eocdOffset) !== 0x06054b50 || bytes.readUInt16LE(eocdOffset + 20) !== 0
    || bytes.readUInt16LE(eocdOffset + 4) !== 0 || bytes.readUInt16LE(eocdOffset + 6) !== 0) {
    throw unsafe('The ZIP end record is malformed.');
  }
  const diskEntries = bytes.readUInt16LE(eocdOffset + 8);
  const entries = bytes.readUInt16LE(eocdOffset + 10);
  const centralSize = bytes.readUInt32LE(eocdOffset + 12);
  const centralOffset = bytes.readUInt32LE(eocdOffset + 16);
  if (diskEntries !== entries || entries === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff
    || entries > state.limits.entries || centralOffset > eocdOffset || centralSize !== eocdOffset - centralOffset) {
    throw unsafe('The ZIP central directory is inconsistent.');
  }
  const records = [];
  let cursor = centralOffset;
  for (let index = 0; index < entries; index += 1) {
    if (cursor > eocdOffset - ZIP_CENTRAL_HEADER_BYTES || bytes.readUInt32LE(cursor) !== 0x02014b50) {
      throw unsafe('A ZIP central record is malformed.');
    }
    const versionMadeBy = bytes.readUInt16LE(cursor + 4);
    const flags = bytes.readUInt16LE(cursor + 8);
    const method = bytes.readUInt16LE(cursor + 10);
    const crc = bytes.readUInt32LE(cursor + 16);
    const compressedSize = bytes.readUInt32LE(cursor + 20);
    const size = bytes.readUInt32LE(cursor + 24);
    const nameLength = bytes.readUInt16LE(cursor + 28);
    const extraLength = bytes.readUInt16LE(cursor + 30);
    const commentLength = bytes.readUInt16LE(cursor + 32);
    const disk = bytes.readUInt16LE(cursor + 34);
    const attributes = bytes.readUInt32LE(cursor + 38);
    const localOffset = bytes.readUInt32LE(cursor + 42);
    const end = checkedAdd(cursor, ZIP_CENTRAL_HEADER_BYTES + nameLength + extraLength + commentLength, 'ZIP record extent');
    if (end > eocdOffset || nameLength === 0 || extraLength !== 0 || commentLength !== 0 || disk !== 0
      || compressedSize === 0xffffffff || size === 0xffffffff || localOffset === 0xffffffff
      || (flags & ~ZIP_ALLOWED_FLAGS) !== 0 || ![0, 8].includes(method)) {
      throw unsafe('A ZIP central record uses unsafe metadata.');
    }
    const nameBytes = bytes.subarray(cursor + ZIP_CENTRAL_HEADER_BYTES, cursor + ZIP_CENTRAL_HEADER_BYTES + nameLength);
    if ((flags & 0x0800) === 0 && nameBytes.some((byte) => byte > 0x7f)) throw unsafe('A ZIP filename encoding is unsupported.');
    const rawPath = (flags & 0x0800) !== 0 ? decodeUtf8(nameBytes, 'ZIP filename') : nameBytes.toString('ascii');
    records.push({ versionMadeBy, flags, method, crc, compressedSize, size, nameBytes, rawPath, attributes, localOffset });
    cursor = end;
  }
  if (cursor !== eocdOffset) throw unsafe('The ZIP central directory has unreviewed bytes.');

  const offsets = new Set();
  const ranges = [];
  let compressedBytes = 0;
  for (const record of records) {
    if (offsets.has(record.localOffset) || record.localOffset > centralOffset - ZIP_LOCAL_HEADER_BYTES
      || bytes.readUInt32LE(record.localOffset) !== 0x04034b50) throw unsafe('A ZIP local record is missing or duplicated.');
    offsets.add(record.localOffset);
    const flags = bytes.readUInt16LE(record.localOffset + 6);
    const method = bytes.readUInt16LE(record.localOffset + 8);
    const crc = bytes.readUInt32LE(record.localOffset + 14);
    const compressedSize = bytes.readUInt32LE(record.localOffset + 18);
    const size = bytes.readUInt32LE(record.localOffset + 22);
    const nameLength = bytes.readUInt16LE(record.localOffset + 26);
    const extraLength = bytes.readUInt16LE(record.localOffset + 28);
    const nameStart = record.localOffset + ZIP_LOCAL_HEADER_BYTES;
    const dataStart = checkedAdd(nameStart, nameLength + extraLength, 'ZIP local header extent');
    const dataEnd = checkedAdd(dataStart, record.compressedSize, 'ZIP payload extent');
    if (dataEnd > centralOffset || extraLength !== 0 || flags !== record.flags || method !== record.method || crc !== record.crc
      || compressedSize !== record.compressedSize || size !== record.size || nameLength !== record.nameBytes.length
      || !bytes.subarray(nameStart, nameStart + nameLength).equals(record.nameBytes)) {
      throw unsafe('ZIP central and local metadata disagree.');
    }
    const type = zipType(record.versionMadeBy, record.attributes, record.rawPath);
    const compressed = bytes.subarray(dataStart, dataEnd);
    let content;
    try {
      content = record.method === 0 ? Buffer.from(compressed) : inflateRawSync(compressed, { maxOutputLength: state.limits.entryBytes + 1 });
    } catch (cause) {
      throw unsafe('A ZIP payload does not match its reviewed metadata.', cause);
    }
    if (content.length !== record.size || (record.method === 0 && record.compressedSize !== record.size)
      || crc32(content) !== record.crc || (type === 'directory' && (record.size !== 0 || record.compressedSize !== 0))) {
      throw unsafe('A ZIP payload does not match its reviewed metadata.');
    }
    compressedBytes = checkedAdd(compressedBytes, record.compressedSize, 'compressed payload size');
    ranges.push({ start: record.localOffset, end: dataEnd });
    addPlannedEntry(state, {
      rawPath: record.rawPath,
      type,
      size: record.size,
      sha256: type === 'file' ? digest(content) : null,
      mode: type === 'directory' ? 0o755 : 0o644
    });
  }
  ranges.sort((left, right) => left.start - right.start);
  let covered = 0;
  for (const range of ranges) {
    if (range.start !== covered || range.end < range.start) throw unsafe('ZIP local records overlap or leave unreviewed bytes.');
    covered = range.end;
  }
  if (covered !== centralOffset) throw unsafe('ZIP local records do not exactly cover the payload area.');
  return compressedBytes;
}

function crc32(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit += 1) value = (value & 1) ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
  }
  return (value ^ 0xffffffff) >>> 0;
}

function parseTarOctal(field, label) {
  if (field[0] & 0x80) throw unsafe(`The TAR ${label} encoding is unsupported.`);
  const text = field.toString('ascii').replace(/[\0 ]+$/u, '');
  if (!/^[0-7]+$/.test(text)) throw unsafe(`The TAR ${label} is malformed.`);
  const value = Number.parseInt(text, 8);
  return checkedInteger(value, `TAR ${label}`);
}

function tarChecksum(block) {
  let sum = 0;
  for (let index = 0; index < TAR_BLOCK_BYTES; index += 1) sum += index >= 148 && index < 156 ? 0x20 : block[index];
  return sum;
}

function parsePax(bytes) {
  const values = new Map();
  let offset = 0;
  while (offset < bytes.length) {
    const space = bytes.indexOf(0x20, offset);
    if (space <= offset) throw unsafe('A PAX record length is malformed.');
    const lengthText = bytes.subarray(offset, space).toString('ascii');
    if (!/^[1-9]\d*$/.test(lengthText)) throw unsafe('A PAX record length is malformed.');
    const length = checkedInteger(Number(lengthText), 'PAX record length', { positive: true });
    const end = checkedAdd(offset, length, 'PAX record extent');
    if (end > bytes.length) throw unsafe('A PAX record length is inconsistent.');
    const recordBytes = bytes.subarray(offset, end);
    const record = decodeUtf8(recordBytes, 'PAX record');
    const prefix = lengthText + ' ';
    if (!record.startsWith(prefix) || !record.endsWith('\n')) throw unsafe('A PAX record is malformed.');
    const equals = record.indexOf('=', prefix.length);
    if (equals < 0) throw unsafe('A PAX record is malformed.');
    const key = record.slice(prefix.length, equals);
    const value = record.slice(equals + 1, -1);
    if (!['path', 'size'].includes(key) || values.has(key) || value.length === 0) throw unsafe('A PAX record uses unsupported or duplicate metadata.');
    values.set(key, value);
    offset = end;
  }
  if (values.has('size')) {
    const value = values.get('size');
    if (!/^(0|[1-9]\d*)$/.test(value)) throw unsafe('A PAX size is malformed.');
    values.set('size', checkedInteger(Number(value), 'PAX size'));
  }
  return values;
}

function parseGzip(bytes, maxOutputLength) {
  if (bytes.length < 18 || bytes[0] !== 0x1f || bytes[1] !== 0x8b || bytes[2] !== 8 || bytes[3] !== 0) {
    throw unsafe('The GZIP header is invalid or unsupported.');
  }
  let result;
  try {
    result = inflateRawSync(bytes.subarray(10), { info: true, maxOutputLength });
  } catch (cause) {
    throw unsafe('The GZIP member is malformed.', cause);
  }
  const compressedBytes = result.engine.bytesWritten;
  const trailerOffset = 10 + compressedBytes;
  if (trailerOffset !== bytes.length - 8) throw unsafe('The GZIP archive has trailing or concatenated data.');
  const payload = result.buffer;
  if (bytes.readUInt32LE(trailerOffset) !== crc32(payload) || bytes.readUInt32LE(trailerOffset + 4) !== (payload.length >>> 0)) {
    throw unsafe('The GZIP trailer is inconsistent.');
  }
  return { payload, compressedBytes };
}

function isZeroBlock(block) {
  return block.length === TAR_BLOCK_BYTES && block.every((byte) => byte === 0);
}

function tarString(field) {
  const nul = field.indexOf(0);
  return decodeUtf8(nul < 0 ? field : field.subarray(0, nul), 'TAR path');
}

function parseTarGz(bytes, state) {
  const maximumTarBytes = checkedAdd(ARCHIVE_LIMITS.expandedBytes, 4 * 1024 * 1024, 'TAR parser limit');
  const { payload, compressedBytes } = parseGzip(bytes, maximumTarBytes);
  const rawEntries = [];
  let cursor = 0;
  let pendingPax;
  let endBlocks = 0;
  while (cursor < payload.length) {
    if (cursor > payload.length - TAR_BLOCK_BYTES) throw unsafe('The TAR stream is truncated.');
    const block = payload.subarray(cursor, cursor + TAR_BLOCK_BYTES);
    if (isZeroBlock(block)) {
      endBlocks += 1;
      cursor += TAR_BLOCK_BYTES;
      if (endBlocks >= 2) break;
      continue;
    }
    if (endBlocks !== 0) throw unsafe('The TAR end marker is malformed.');
    const expectedChecksum = parseTarOctal(block.subarray(148, 156), 'checksum');
    if (expectedChecksum !== tarChecksum(block)) throw unsafe('A TAR header checksum is invalid.');
    if (!block.subarray(257, 263).equals(Buffer.from('ustar\0'))
      || !block.subarray(263, 265).equals(Buffer.from('00'))
      || block.subarray(157, 257).some((byte) => byte !== 0)
      || block.subarray(265, 345).some((byte) => byte !== 0)
      || block.subarray(500, 512).some((byte) => byte !== 0)) {
      throw unsafe('A TAR header uses unsupported schema fields.');
    }
    const rawName = tarString(block.subarray(0, 100));
    const prefix = tarString(block.subarray(345, 500));
    const headerPath = prefix ? `${prefix}/${rawName}` : rawName;
    const headerSize = parseTarOctal(block.subarray(124, 136), 'size');
    const mode = parseTarOctal(block.subarray(100, 108), 'mode');
    const typeFlag = String.fromCharCode(block[156] || 0x30);
    const effectiveSize = pendingPax?.has('size') ? pendingPax.get('size') : headerSize;
    if (pendingPax?.has('size') && effectiveSize !== headerSize) throw unsafe('PAX and TAR sizes disagree.');
    const dataStart = cursor + TAR_BLOCK_BYTES;
    const paddedSize = checkedMultiply(Math.ceil(effectiveSize / TAR_BLOCK_BYTES), TAR_BLOCK_BYTES, 'TAR payload extent');
    const dataEnd = checkedAdd(dataStart, paddedSize, 'TAR payload extent');
    if (dataEnd > payload.length) throw unsafe('A TAR payload is truncated.');
    const content = payload.subarray(dataStart, dataStart + effectiveSize);
    cursor = dataEnd;
    if (typeFlag === 'x') {
      if (pendingPax || headerSize === 0) throw unsafe('PAX metadata is ambiguous.');
      pendingPax = parsePax(content);
      rawEntries.push({ type: 'metadata', size: headerSize });
      continue;
    }
    if (!['0', '5'].includes(typeFlag)) throw unsafe('A TAR entry has an unsafe or unsupported type.');
    const type = typeFlag === '5' ? 'directory' : 'file';
    const effectivePath = pendingPax?.get('path') ?? headerPath;
    if (type === 'directory' && effectiveSize !== 0) throw unsafe('A TAR directory has payload bytes.');
    const rawEntry = {
      rawPath: effectivePath,
      type,
      size: effectiveSize,
      sha256: type === 'file' ? digest(content) : null,
      mode
    };
    rawEntries.push(rawEntry);
    addPlannedEntry(state, rawEntry);
    pendingPax = undefined;
  }
  if (endBlocks < 2 || pendingPax) throw unsafe('The TAR stream has no complete end marker.');
  while (cursor < payload.length) {
    if (cursor > payload.length - TAR_BLOCK_BYTES || !isZeroBlock(payload.subarray(cursor, cursor + TAR_BLOCK_BYTES))) {
      throw unsafe('The TAR stream has trailing data.');
    }
    cursor += TAR_BLOCK_BYTES;
  }
  checkAggregateLimits(rawEntries, compressedBytes, state.limits);
  return compressedBytes;
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

async function verifiedArchiveBytes(descriptor, limits, adapter) {
  exactKeys(descriptor, ['path', 'name', 'bytes', 'sha256', 'kind'], 'verified archive descriptor');
  if (typeof descriptor.path !== 'string' || !path.isAbsolute(descriptor.path) || /[\0\r\n]/.test(descriptor.path)
    || typeof descriptor.name !== 'string' || descriptor.name !== path.basename(descriptor.path)
    || !['zip', 'tar.gz'].includes(descriptor.kind) || !Number.isSafeInteger(descriptor.bytes) || descriptor.bytes < 0
    || descriptor.bytes > limits.archiveBytes || !/^[a-f0-9]{64}$/.test(descriptor.sha256)) {
    throw unsafe('The verified archive descriptor is invalid.');
  }
  const fsApi = adapter.fsApi ?? fs;
  const declaredPath = path.resolve(descriptor.path);
  let before;
  let canonical;
  let bytes;
  try {
    before = await fsApi.lstat(declaredPath);
    if (!before.isFile?.() || before.isSymbolicLink?.() || before.isReparsePoint === true || before.size !== descriptor.bytes) {
      throw unsafe('The verified archive changed type or size.');
    }
    canonical = await fsApi.realpath(declaredPath);
    if (!sameHostPath(canonical, declaredPath)) throw unsafe('The verified archive changed canonical identity.');
    if (adapter.archiveIdentity && !sameIdentity(before, adapter.archiveIdentity)) throw unsafe('The verified archive identity changed.');
    bytes = await fsApi.readFile(declaredPath);
    const after = await fsApi.lstat(declaredPath);
    if (!sameIdentity(after, before) || after.size !== before.size || bytes.length !== descriptor.bytes) {
      throw unsafe('The verified archive changed while being read.');
    }
  } catch (cause) {
    if (cause instanceof ClaudexError) throw cause;
    throw unsafe('The verified archive could not be safely rechecked.', cause);
  }
  if (!sameDigest(digest(bytes), descriptor.sha256)) throw unsafe('The verified archive digest changed.');
  return { bytes, canonicalPath: canonical, identity: { dev: before.dev, ino: before.ino }, fsApi };
}

async function canonicalStagingRoot(adapter, archiveStats) {
  const fsApi = adapter.fsApi ?? fs;
  if (typeof adapter.stagingRoot !== 'string' || !path.isAbsolute(adapter.stagingRoot) || /[\0\r\n]/.test(adapter.stagingRoot)) {
    throw unsafe('The archive staging root is invalid.');
  }
  try {
    const declared = path.resolve(adapter.stagingRoot);
    const stats = await fsApi.lstat(declared);
    const canonical = await fsApi.realpath(declared);
    if (!stats.isDirectory?.() || stats.isSymbolicLink?.() || stats.isReparsePoint === true || !sameHostPath(declared, canonical)
      || stats.dev !== archiveStats.dev) throw unsafe('The archive staging root is unsafe or on another filesystem.');
    return { canonical, identity: { dev: stats.dev, ino: stats.ino } };
  } catch (cause) {
    if (cause instanceof ClaudexError) throw cause;
    throw unsafe('The archive staging root could not be verified.', cause);
  }
}

/**
 * Recheck a Task 5 verified-archive descriptor and parse its metadata without
 * invoking an extractor or executing archive content.
 */
export async function validateArchive(descriptor, expectedExecutable, limitOverrides, adapter = {}) {
  const limits = normalizeLimits(limitOverrides);
  if (typeof expectedExecutable !== 'string' || expectedExecutable.length === 0 || expectedExecutable !== path.basename(expectedExecutable)
    || /[\\/:\0\r\n]/.test(expectedExecutable)) throw unsafe('The expected archive executable name is invalid.');
  if (!adapter || typeof adapter !== 'object' || Array.isArray(adapter)
    || !['win32', 'linux', 'darwin'].includes(adapter.targetPlatform)) throw unsafe('The archive target platform is invalid.');
  const verified = await verifiedArchiveBytes(descriptor, limits, adapter);
  const staging = await canonicalStagingRoot(adapter, verified.identity);
  const stagingRoot = staging.canonical;
  const state = {
    targetPlatform: adapter.targetPlatform,
    stagingRoot,
    limits,
    entries: [],
    destinations: new Map()
  };
  let compressedBytes;
  if (descriptor.kind === 'zip') compressedBytes = parseZip(verified.bytes, state);
  else compressedBytes = parseTarGz(verified.bytes, state);
  const expandedBytes = checkAggregateLimits(state.entries, compressedBytes, limits);
  state.entries.sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  const candidates = state.entries.filter((entry) => entry.type === 'file' && path.posix.basename(entry.path) === expectedExecutable);
  if (candidates.length !== 1) throw unsafe('The archive does not contain exactly one expected executable.');
  if (adapter.targetPlatform !== 'win32' && candidates[0].mode !== 0o755) throw unsafe('The archive executable mode is unsafe.');
  const plan = {
    schemaVersion: 1,
    archivePath: verified.canonicalPath,
    archiveName: descriptor.name,
    archiveBytes: descriptor.bytes,
    archiveSha256: descriptor.sha256,
    archiveIdentity: verified.identity,
    kind: descriptor.kind,
    targetPlatform: adapter.targetPlatform,
    stagingRoot,
    stagingRootIdentity: staging.identity,
    expectedExecutable,
    compressedBytes,
    expandedBytes,
    entries: state.entries,
    candidate: { ...candidates[0] }
  };
  deepFreeze(plan);
  validatedPlans.add(plan);
  return plan;
}
function capability(message, cause, details) {
  return new ClaudexError('CAPABILITY_UNSUPPORTED', message, { cause, details });
}

function prerequisite(message, cause) {
  return new ClaudexError('PREREQUISITE_MISSING', message, cause ? { cause } : undefined);
}

function safety(message, cause) {
  return new ClaudexError('SAFETY_REFUSAL', message, cause ? { cause } : undefined);
}

function helperEntry(entry) {
  return { path: entry.path, type: entry.type, size: entry.size, sha256: entry.sha256 };
}

function assertHelperExactKeys(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw capability('The archive helper schema is invalid.');
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw capability('The archive helper schema has unknown or missing fields.');
  }
}

function assertHelperEntry(entry) {
  assertHelperExactKeys(entry, ['path', 'type', 'size', 'sha256']);
  if (typeof entry.path !== 'string' || !['file', 'directory'].includes(entry.type)
    || !Number.isSafeInteger(entry.size) || entry.size < 0
    || (entry.type === 'file' ? !/^[a-f0-9]{64}$/.test(entry.sha256) : entry.sha256 !== null)) {
    throw capability('The archive helper returned invalid entry metadata.');
  }
}

export function buildArchiveHelperRequest({ requestId, archivePath, destination, archiveSha256, entries } = {}) {
  const request = { schemaVersion: 1, requestId, operation: 'extractZip', archivePath, destination, archiveSha256, entries };
  if (!UUID_PATTERN.test(requestId) || typeof archivePath !== 'string' || !path.win32.isAbsolute(archivePath)
    || typeof destination !== 'string' || !path.win32.isAbsolute(destination) || !/^[a-f0-9]{64}$/.test(archiveSha256)
    || !Array.isArray(entries) || entries.length > ARCHIVE_LIMITS.entries || /[\0\r\n]/.test(archivePath + destination)) {
    throw safety('The archive helper request is invalid.');
  }
  for (const entry of entries) assertHelperEntry(entry);
  return JSON.stringify(request);
}

export function parseArchiveHelperResponse(stdout, { requestId } = {}) {
  if (typeof stdout !== 'string' || stdout.trim() === '' || stdout.trim().split(/\r?\n/u).length !== 1) {
    throw capability('The archive helper must write exactly one JSON response.');
  }
  let response;
  try {
    response = JSON.parse(stdout.trim());
  } catch (cause) {
    throw capability('The archive helper response is not valid JSON.', cause);
  }
  if (response?.ok === true) {
    assertHelperExactKeys(response, ['ok', 'schemaVersion', 'requestId', 'result']);
    assertHelperExactKeys(response.result, ['canonicalDestination', 'entryCount', 'expandedBytes', 'entries']);
    if (response.schemaVersion !== 1 || response.requestId !== requestId || !UUID_PATTERN.test(response.requestId)
      || typeof response.result.canonicalDestination !== 'string' || !path.win32.isAbsolute(response.result.canonicalDestination)
      || !Number.isSafeInteger(response.result.entryCount) || response.result.entryCount < 0
      || !Number.isSafeInteger(response.result.expandedBytes) || response.result.expandedBytes < 0
      || !Array.isArray(response.result.entries) || response.result.entries.length !== response.result.entryCount) {
      throw capability('The archive helper response schema is invalid.');
    }
    for (const entry of response.result.entries) assertHelperEntry(entry);
    return response;
  }
  if (response?.ok === false) {
    assertHelperExactKeys(response, ['ok', 'schemaVersion', 'requestId', 'code', 'message']);
    if (response.schemaVersion !== 1 || response.requestId !== requestId || typeof response.code !== 'string' || typeof response.message !== 'string') {
      throw capability('The archive helper error schema is invalid.');
    }
    return response;
  }
  throw capability('The archive helper response envelope is invalid.');
}

function boundedText(value, maxOutputBytes, stream) {
    let terminalDeadline;
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > maxOutputBytes) {
    throw capability('The archive extractor ' + stream + ' exceeded its permitted output.');
  }
}

function defaultRunProcess(command, args, {
  shell, timeoutMs, maxOutputBytes, terminationGraceMs = 250, terminationDeadlineMs = 2000,
  spawnChildApi = spawnChild, env
}) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawnChildApi(command, args, { shell, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, env });
    } catch (cause) {
      reject(prerequisite('The required archive extractor could not be started.', cause));
      return;
    }
    let stdout = '';
    let stderr = '';
    let termination;
    let settled = false;
    let escalation;
    let terminalDeadline;
    let timer;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(escalation);
      clearTimeout(terminalDeadline);
      callback(value);
    };
    const terminate = (message) => {
      if (termination) return;
      termination = message;
      child.kill();
      escalation = setTimeout(() => {
        child.kill('SIGKILL');
        terminalDeadline = setTimeout(() => finish(reject, capability('The archive extractor exit could not be confirmed.', undefined, { exitUnconfirmed: true })), terminationDeadlineMs);
      }, terminationGraceMs);
    };
    timer = setTimeout(() => terminate('The archive extractor timed out.'), timeoutMs);
    const append = (stream, chunk) => {
      if (termination) return;
      if (stream === 'stdout') stdout += chunk;
      else stderr += chunk;
      if (Buffer.byteLength(stream === 'stdout' ? stdout : stderr, 'utf8') > maxOutputBytes) {
        terminate('The archive extractor ' + stream + ' exceeded its permitted output.');
      }
    };
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => append('stdout', chunk));
    child.stderr.on('data', (chunk) => append('stderr', chunk));
    child.once('error', (cause) => finish(reject, prerequisite('The required archive extractor failed to start.', cause)));
    child.once('close', (code) => termination
      ? finish(reject, capability(termination))
      : finish(resolve, { code, stdout, stderr }));
  });
}

export function testRunArchiveProcess(command, args, options) {
  return defaultRunProcess(command, args, { shell: false, ...options });
}

async function runProcess(command, args, options, adapter) {
  let result;
  try {
    result = await (adapter.runProcess ?? defaultRunProcess)(command, args, options);
  } catch (cause) {
    if (cause instanceof ClaudexError) throw cause;
    if (cause?.code === 'PREREQUISITE_MISSING') throw prerequisite('The required archive extractor is unavailable.', cause);
    throw capability('The archive extractor failed safely.', cause);
  }
  boundedText(result?.stdout, options.maxOutputBytes, 'stdout');
  boundedText(result?.stderr, options.maxOutputBytes, 'stderr');
  return result;
}

async function verifyFixedAncestorChain(exactPath, fsApi) {
  const normalized = path.normalize(exactPath);
  const root = path.parse(normalized).root;
  let current = root;
  for (const segment of normalized.slice(root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    const stats = await fsApi.lstat(current);
    if (stats.isSymbolicLink?.() || stats.isReparsePoint === true) {
      throw capability('A fixed archive extractor ancestor is unsafe.');
    }
  }
}

async function verifyFixedFile(exactPath, fsApi, missingMessage) {
  try {
    await verifyFixedAncestorChain(exactPath, fsApi);
    const stats = await fsApi.lstat(exactPath);
    const canonical = await fsApi.realpath(exactPath);
    if (!stats.isFile?.() || stats.isSymbolicLink?.() || stats.isReparsePoint === true || !sameHostPath(canonical, exactPath)) {
      throw capability('A fixed archive extractor path is unsafe.');
    }
    return canonical;
  } catch (cause) {
    if (cause instanceof ClaudexError) throw cause;
    if (cause?.code === 'ENOENT') throw prerequisite(missingMessage, cause);
    throw capability('A fixed archive extractor path could not be verified.', cause);
  }
}

function identity(stats) {
  return { dev: stats.dev, ino: stats.ino };
}

async function assertExactDirectory(target, expectedIdentity, fsApi, { mode, parent, enforceMode = process.platform !== 'win32' } = {}) {
  const stats = await fsApi.lstat(target);
  const canonical = await fsApi.realpath(target);
  if (!stats.isDirectory?.() || stats.isSymbolicLink?.() || stats.isReparsePoint === true || !sameHostPath(canonical, target)
    || (expectedIdentity && !sameIdentity(stats, expectedIdentity)) || (parent && stats.dev !== parent.dev)
    || (mode !== undefined && enforceMode && (stats.mode & 0o777) !== mode)) {
    throw safety('Archive staging changed identity or protection.');
  }
  return stats;
}

async function assertExactNativeDirectory(target, expectedExactIdentity, fsApi, options) {
  const stats = await assertExactDirectory(target, undefined, fsApi, options);
  const exactStats = await fsApi.lstat(target, { bigint: true });
  if (!sameExactIdentity(exactStats, expectedExactIdentity)) {
    throw safety('Archive staging changed native filesystem identity.');
  }
  return stats;
}
async function assertExactFile(target, expectedIdentity, fsApi) {
  try {
    const stats = await fsApi.lstat(target);
    const canonical = await fsApi.realpath(target);
    if (!stats.isFile?.() || stats.isSymbolicLink?.() || stats.isReparsePoint === true
      || !sameHostPath(canonical, target) || (expectedIdentity && !sameIdentity(stats, expectedIdentity))) {
      throw safety('A protected archive file changed identity.');
    }
    return stats;
  } catch (cause) {
    if (cause instanceof ClaudexError) throw cause;
    throw safety('A protected archive file could not be rechecked.', cause);
  }
}
async function assertExactNativeFile(target, expectedExactIdentity, fsApi) {
  const stats = await assertExactFile(target, undefined, fsApi);
  const exactStats = await fsApi.lstat(target, { bigint: true });
  if (!sameExactIdentity(exactStats, expectedExactIdentity)) {
    throw safety('A protected archive file changed native filesystem identity.');
  }
  return stats;
}

async function fixedExactFileDigest(target, expectedExactIdentity, fsApi) {
  const before = await assertExactNativeFile(target, expectedExactIdentity, fsApi);
  if (!Number.isSafeInteger(before.size) || before.size <= 0 || before.size > 16777216) {
    throw safety('A protected archive file has an unsafe size.');
  }
  const bytes = await fsApi.readFile(target);
  const after = await assertExactNativeFile(target, expectedExactIdentity, fsApi);
  if (after.size !== before.size || bytes.length !== before.size) {
    throw safety('A protected archive file changed while being pinned.');
  }
  return digest(bytes);
}

async function fixedFileDigest(target, expectedIdentity, fsApi) {
  const before = await assertExactFile(target, expectedIdentity, fsApi);
  if (!Number.isSafeInteger(before.size) || before.size <= 0 || before.size > 16777216) {
    throw capability('A fixed archive extractor has an unsafe size.');
  }
  const bytes = await fsApi.readFile(target);
  const after = await assertExactFile(target, expectedIdentity ?? identity(before), fsApi);
  if (!sameIdentity(before, after) || bytes.length !== before.size) {
    throw capability('A fixed archive extractor changed while being pinned.');
  }
  return digest(bytes);
}
async function recheckArchive(plan, fsApi) {
  try {
    const before = await fsApi.lstat(plan.archivePath);
    const canonical = await fsApi.realpath(plan.archivePath);
    if (!before.isFile?.() || before.isSymbolicLink?.() || before.isReparsePoint === true
      || !sameHostPath(canonical, plan.archivePath) || !sameIdentity(before, plan.archiveIdentity)
      || before.size !== plan.archiveBytes) throw unsafe('The verified archive changed before extraction.');
    const bytes = await fsApi.readFile(plan.archivePath);
    const after = await fsApi.lstat(plan.archivePath);
    if (!sameIdentity(before, after) || bytes.length !== plan.archiveBytes || !sameDigest(digest(bytes), plan.archiveSha256)) {
      throw unsafe('The verified archive changed before extraction.');
    }
  } catch (cause) {
    if (cause instanceof ClaudexError) throw cause;
    throw unsafe('The verified archive could not be rechecked before extraction.', cause);
  }
}

async function createStaging(plan, stagingDir, fsApi, adapter) {
  if (typeof stagingDir !== 'string' || !path.isAbsolute(stagingDir) || /[\0\r\n]/.test(stagingDir)) {
    throw safety('Archive staging must be an absolute safe path.');
  }
  const target = path.resolve(stagingDir);
  if (!sameHostPath(path.dirname(target), plan.stagingRoot) || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(path.basename(target))) {
    throw safety('Archive staging is outside its managed root.');
  }
  const rootStats = await assertExactDirectory(plan.stagingRoot, plan.stagingRootIdentity, fsApi);
  let createdIdentity;
  try {
    await fsApi.mkdir(target, { recursive: false, mode: 0o700 });
    await fsApi.chmod?.(target, 0o700);
    const created = await assertExactDirectory(target, undefined, fsApi, { mode: 0o700, parent: rootStats, enforceMode: plan.targetPlatform !== 'win32' });
    createdIdentity = identity(created);
    if (plan.targetPlatform === 'win32') {
      if (adapter.protectStaging) await adapter.protectStaging(target);
      else {
        if (typeof adapter.currentUserSid !== 'string') throw safety('Windows archive staging protection requires the current user SID.');
        const response = await runWindowsSecurityHelper({ request: {
          requestId: randomUUID(), operation: 'protect', path: target,
          expectedType: 'directory', currentUserSid: adapter.currentUserSid
        } }, adapter.windowsSecurityDeps);
        assertWindowsDacl(response.result, { expectedType: 'directory', currentUserSid: adapter.currentUserSid });
      }
    }
    const stats = await assertExactDirectory(target, createdIdentity, fsApi, { mode: 0o700, parent: rootStats, enforceMode: plan.targetPlatform !== 'win32' });
    const nativeStats = await fsApi.lstat(target, { bigint: true });
    return {
      target, identity: identity(stats), rootStats,
      nativeIdentity: { volume: String(nativeStats.dev), fileId: String(nativeStats.ino) }
    };
  } catch (cause) {
    if (createdIdentity) {
      try {
        await assertExactDirectory(target, createdIdentity, fsApi, { parent: rootStats });
      } catch {
        throw safety('Archive staging creation cleanup failed closed.', cause);
      }
      const retained = safety('Archive staging protection failed; owned state was retained.', cause);
      retained.details = { stagingRetained: true };
      throw retained;
    }
    throw safety('Archive staging could not be created exclusively.', cause);
  }
}
async function defaultPrivateRequest(input, adapter) {
  const fsApi = adapter.fsApi ?? fs;
  const directoryPath = await fsApi.mkdtemp(path.join(os.tmpdir(), 'claudexctl-archive-request-'));
  const requestPath = path.join(directoryPath, 'request.json');
  let directoryIdentity;
  let requestIdentity;
  let handle;
  try {
    await fsApi.chmod?.(directoryPath, 0o700);
    directoryIdentity = identity(await assertExactDirectory(directoryPath, undefined, fsApi, { mode: 0o700 }));
    if (process.platform === 'win32') {
      if (typeof adapter.currentUserSid !== 'string') throw safety('Windows archive extraction requires a current user SID.');
      await runWindowsSecurityHelper({ request: {
        requestId: randomUUID(), operation: 'protect', path: directoryPath, expectedType: 'directory', currentUserSid: adapter.currentUserSid
      } }, adapter.windowsSecurityDeps);
    }
    handle = await fsApi.open(requestPath, 'wx', 0o600);
    await handle.writeFile(input, 'utf8');
    await handle.sync?.();
    await handle.close();
    handle = undefined;
    await fsApi.chmod?.(requestPath, 0o600);
    if (process.platform === 'win32') await runWindowsSecurityHelper({ request: {
      requestId: randomUUID(), operation: 'protect', path: requestPath, expectedType: 'file', currentUserSid: adapter.currentUserSid
    } }, adapter.windowsSecurityDeps);
    const requestStats = await fsApi.lstat(requestPath);
    if (!requestStats.isFile?.() || requestStats.isSymbolicLink?.() || requestStats.isReparsePoint === true) {
      throw safety('The archive request file is unsafe.');
    }
    requestIdentity = identity(requestStats);
  } catch (cause) {
    await handle?.close().catch(() => {});
    await fsApi.rm(directoryPath, { recursive: true, force: true }).catch(() => {});
    throw cause;
  }
  return {
    requestPath,
    async cleanup() {
      const requestStats = await fsApi.lstat(requestPath);
      const directoryStats = await fsApi.lstat(directoryPath);
      if (!sameIdentity(requestStats, requestIdentity) || !sameIdentity(directoryStats, directoryIdentity)
        || requestStats.isSymbolicLink?.() || directoryStats.isSymbolicLink?.()) {
        throw safety('The archive request storage changed before cleanup.');
      }
      await fsApi.rm(requestPath);
      await fsApi.rmdir(directoryPath);
    }
  };
}

function sameWindowsPath(left, right) {
  return path.win32.normalize(left).toLowerCase() === path.win32.normalize(right).toLowerCase();
}

function compareHelperResult(result, plan, stagingDir) {
  if (!sameWindowsPath(result.canonicalDestination, stagingDir) || result.entryCount !== plan.entries.length
    || result.expandedBytes !== plan.expandedBytes) throw unsafe('The archive helper result differs from the validated plan.');
  const expected = plan.entries.map(helperEntry);
  const observed = [...result.entries].sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  if (JSON.stringify(observed) !== JSON.stringify(expected)) {
    throw unsafe('The archive helper entries differ from the validated plan.');
  }
}

async function runWindowsExtraction(plan, staging, adapter) {
  const fsApi = adapter.fsApi ?? fs;
  const tools = adapter.verifyWindowsTools
    ? await adapter.verifyWindowsTools()
    : {
        powershellPath: await verifyFixedFile(FIXED_POWERSHELL_PATH, fsApi, 'Fixed System32 PowerShell is missing.'),
        helperPath: await verifyFixedFile(ARCHIVE_HELPER_PATH, fsApi, 'The bundled archive helper is missing.')
      };
  if (tools.powershellPath !== FIXED_POWERSHELL_PATH || tools.helperPath !== ARCHIVE_HELPER_PATH) {
    throw capability('The Windows archive extractor identity is invalid.');
  }
  await verifyFixedAncestorChain(tools.powershellPath, fsApi);
  await verifyFixedAncestorChain(tools.helperPath, fsApi);
  const toolIdentities = {
    powershell: identity(await assertExactFile(tools.powershellPath, undefined, fsApi)),
    helper: identity(await assertExactFile(tools.helperPath, undefined, fsApi))
  };
  const toolDigests = {
    powershell: await fixedFileDigest(tools.powershellPath, toolIdentities.powershell, fsApi),
    helper: await fixedFileDigest(tools.helperPath, toolIdentities.helper, fsApi)
  };
  const requestId = randomUUID();
  const input = buildArchiveHelperRequest({
    requestId,
    archivePath: plan.archivePath,
    destination: staging.target,
    archiveSha256: plan.archiveSha256,
    entries: plan.entries.map(helperEntry)
  });
  const requestSha256 = digest(Buffer.from(input, 'utf8'));
  const storage = await (adapter.createPrivateRequest ?? ((value) => defaultPrivateRequest(value, adapter)))(input);
  let response;
  let operationError;
  let requestIdentity;
  try {
    if (!storage || typeof storage.requestPath !== 'string' || !path.isAbsolute(storage.requestPath) || typeof storage.cleanup !== 'function') {
      throw safety('The archive helper request storage is invalid.');
    }
    await assertExactFile(storage.requestPath, undefined, fsApi);
    requestIdentity = exactIdentity(await fsApi.lstat(storage.requestPath, { bigint: true }));
    await adapter.beforeExtractorSpawn?.({ plan, stagingDir: staging.target, requestPath: storage.requestPath, tools });
    if (!sameDigest(await fixedFileDigest(tools.powershellPath, toolIdentities.powershell, fsApi), toolDigests.powershell)
      || !sameDigest(await fixedFileDigest(tools.helperPath, toolIdentities.helper, fsApi), toolDigests.helper)) {
      throw capability('A fixed archive extractor changed after identity pinning.');
    }
    await recheckArchive(plan, fsApi);
    await assertExactDirectory(staging.target, staging.identity, fsApi, { mode: 0o700, parent: staging.rootStats, enforceMode: plan.targetPlatform !== 'win32' });
    await assertExactNativeFile(storage.requestPath, requestIdentity, fsApi);
    await adapter.beforeLaunchIdentityValidation?.({
      plan, stagingDir: staging.target, requestPath: storage.requestPath, tools, toolIdentities, requestSha256
    });
    if (!sameDigest(await fixedFileDigest(tools.powershellPath, toolIdentities.powershell, fsApi), toolDigests.powershell)
      || !sameDigest(await fixedFileDigest(tools.helperPath, toolIdentities.helper, fsApi), toolDigests.helper)) {
      throw capability('A fixed archive extractor changed after identity pinning.');
    }
    await recheckArchive(plan, fsApi);
    await assertExactDirectory(staging.target, staging.identity, fsApi, { mode: 0o700, parent: staging.rootStats, enforceMode: plan.targetPlatform !== 'win32' });
    await assertExactNativeFile(storage.requestPath, requestIdentity, fsApi);
    const helperEnvironment = {
      ...process.env,
      CLAUDEX_ARCHIVE_POWERSHELL_SHA256: toolDigests.powershell,
      CLAUDEX_ARCHIVE_HELPER_PATH: tools.helperPath,
      CLAUDEX_ARCHIVE_HELPER_SHA256: toolDigests.helper,
      CLAUDEX_ARCHIVE_REQUEST_PATH: storage.requestPath,
      CLAUDEX_ARCHIVE_REQUEST_SHA256: requestSha256,
      CLAUDEX_ARCHIVE_DESTINATION_VOLUME: staging.nativeIdentity.volume,
      CLAUDEX_ARCHIVE_DESTINATION_FILE_ID: staging.nativeIdentity.fileId
    };
    await adapter.afterLaunchIdentityPinBeforeProcessCreate?.({
      plan, stagingDir: staging.target, requestPath: storage.requestPath, tools, toolIdentities,
      requestSha256, helperEnvironment
    });
    if (!sameDigest(await fixedFileDigest(tools.powershellPath, toolIdentities.powershell, fsApi), toolDigests.powershell)
      || !sameDigest(await fixedFileDigest(tools.helperPath, toolIdentities.helper, fsApi), toolDigests.helper)
      || !sameDigest(await fixedExactFileDigest(storage.requestPath, requestIdentity, fsApi), requestSha256)) {
      throw capability('A fixed archive launch input changed at the process boundary.');
    }
    await recheckArchive(plan, fsApi);
    await assertExactNativeDirectory(staging.target, {
      dev: staging.nativeIdentity.volume, ino: staging.nativeIdentity.fileId
    }, fsApi, { mode: 0o700, parent: staging.rootStats, enforceMode: false });
    const result = await runProcess(tools.powershellPath, [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-EncodedCommand', WINDOWS_HELPER_BOOTSTRAP_ENCODED
    ], {
      shell: false, timeoutMs: ARCHIVE_LIMITS.extractionDeadlineMs,
      maxOutputBytes: ARCHIVE_LIMITS.outputBytes, env: helperEnvironment
    }, adapter);
    response = parseArchiveHelperResponse(result.stdout, { requestId });
    if (result.code !== 0 || response.ok === false) throw capability('The Windows archive helper refused extraction.');
    compareHelperResult(response.result, plan, staging.target);
  } catch (cause) {
    operationError = cause;
  }
  if (operationError?.details?.exitUnconfirmed) {
    operationError.details = { ...operationError.details, requestStorageRetained: true };
    throw operationError;
  }
  try {
    if (requestIdentity) await assertExactNativeFile(storage.requestPath, requestIdentity, fsApi);
    await storage?.cleanup?.();
  } catch (cause) {
    throw safety('The archive helper request cleanup failed closed.', cause);
  }
  if (operationError) throw operationError;
}
async function runPosixExtraction(plan, stagingDir, adapter) {
  const requested = adapter.tarPath ?? '/usr/bin/tar';
  if (!FIXED_POSIX_TAR_PATHS.has(requested)) throw capability('The POSIX archive extractor path is not fixed.');
  const tarPath = adapter.verifyTarPath
    ? await adapter.verifyTarPath(requested)
    : await verifyFixedFile(requested, adapter.fsApi ?? fs, 'A fixed system tar executable is missing.');
  if (tarPath !== requested) throw capability('The POSIX archive extractor identity changed.');
  const result = await runProcess(tarPath, [
    '-xzf', plan.archivePath, '-C', stagingDir, '--no-same-owner', '--no-same-permissions'
  ], { shell: false, timeoutMs: ARCHIVE_LIMITS.extractionDeadlineMs, maxOutputBytes: ARCHIVE_LIMITS.outputBytes }, adapter);
  if (result.code !== 0 || result.stdout !== '') throw capability('The POSIX archive extractor returned an invalid result.');
}
async function pinWindowsCandidate(record, candidate) {
  await verifyFixedFile(FIXED_POWERSHELL_PATH, fs, 'Fixed System32 PowerShell is missing.');
  const powershellIdentity = identity(await assertExactFile(FIXED_POWERSHELL_PATH, undefined, fs));
  const powershellSha256 = await fixedFileDigest(FIXED_POWERSHELL_PATH, powershellIdentity, fs);
  const child = spawnChild(FIXED_POWERSHELL_PATH, [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-EncodedCommand', WINDOWS_CANDIDATE_PIN_ENCODED
  ], {
    shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      CLAUDEX_CANDIDATE_POWERSHELL_SHA256: powershellSha256,
      CLAUDEX_CANDIDATE_PATH: record.path,
      CLAUDEX_CANDIDATE_VOLUME: record.identity.dev,
      CLAUDEX_CANDIDATE_FILE_ID: record.identity.ino,
      CLAUDEX_CANDIDATE_SIZE: String(candidate.size),
      CLAUDEX_CANDIDATE_SHA256: candidate.sha256
    }
  });
  let stdout = '';
  let stderr = '';
  let ready = false;
  let closed;
  const closePromise = new Promise((resolve) => { closed = resolve; });
  child.once('close', (code) => closed(code));
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => { if (stdout.length < 256) stdout += chunk; });
  child.stderr.on('data', (chunk) => { if (stderr.length < 256) stderr += chunk; });
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(safety('The native candidate pin timed out.')), 5000);
      const inspect = () => {
        if (stdout === 'CLAUDEX_CANDIDATE_PIN_READY\r\n' || stdout === 'CLAUDEX_CANDIDATE_PIN_READY\n') {
          ready = true;
          clearTimeout(timer);
          resolve();
        } else if (Buffer.byteLength(stdout, 'utf8') > 128 || Buffer.byteLength(stderr, 'utf8') > 128) {
          clearTimeout(timer);
          reject(safety('The native candidate pin returned invalid output.'));
        }
      };
      child.stdout.on('data', inspect);
      child.stderr.on('data', inspect);
      child.once('error', (cause) => {
        clearTimeout(timer);
        reject(safety('The native candidate pin could not start.', cause));
      });
      child.once('close', () => {
        if (!ready) {
          clearTimeout(timer);
          reject(safety('The native candidate pin refused the candidate.'));
        }
      });
    });
  } catch (cause) {
    child.kill();
    throw cause;
  }
  return async () => {
    child.stdin.end('release\n');
    let releaseTimer;
    const deadline = new Promise((resolve) => { releaseTimer = setTimeout(() => resolve(null), 5000); });
    const code = await Promise.race([closePromise, deadline]);
    clearTimeout(releaseTimer);
    if (code !== 0) { child.kill(); throw safety('The native candidate pin did not release cleanly.'); }
  };
}

async function walkExtractedTree(plan, staging, adapter) {
  const fsApi = adapter.fsApi ?? fs;
  await assertExactDirectory(plan.stagingRoot, plan.stagingRootIdentity, fsApi);
  await assertExactDirectory(staging.target, staging.identity, fsApi, { mode: 0o700, parent: staging.rootStats, enforceMode: plan.targetPlatform !== 'win32' });
  const actual = [];
  async function visit(directory, relativeDirectory = '') {
    const children = await fsApi.readdir(directory, { withFileTypes: true });
    for (const child of children) {
      const relative = relativeDirectory ? relativeDirectory + '/' + child.name : child.name;
      const target = path.join(directory, child.name);
      const before = await fsApi.lstat(target);
      const canonical = await fsApi.realpath(target);
      if (before.isSymbolicLink?.() || before.isReparsePoint === true || !sameHostPath(canonical, target)) {
        throw unsafe('The extracted tree contains a link or reparse point.');
      }
      if (before.isDirectory?.()) {
        actual.push({
          path: relative, destination: target, type: 'directory', size: 0, sha256: null,
          mode: plan.targetPlatform === 'win32' ? null : before.mode & 0o777, identity: identity(before)
        });
        await visit(target, relative);
      } else if (before.isFile?.()) {
        if (before.nlink > 1 || (plan.targetPlatform !== 'win32' && Number.isSafeInteger(before.blocks) && before.size > 0 && before.blocks * 512 < before.size)) {
          throw unsafe('The extracted tree contains a linked or sparse file.');
        }
        const bytes = await fsApi.readFile(target);
        const after = await fsApi.lstat(target);
        if (!sameIdentity(before, after) || after.size !== bytes.length || after.isSymbolicLink?.() || after.isReparsePoint === true) {
          throw unsafe('An extracted file changed while being verified.');
        }
        actual.push({
          path: relative, destination: target, type: 'file', size: bytes.length, sha256: digest(bytes),
          mode: plan.targetPlatform === 'win32' ? null : after.mode & 0o777, identity: identity(after)
        });
      } else {
        throw unsafe('The extracted tree contains an unsupported filesystem type.');
      }
    }
  }
  await visit(staging.target);
  actual.sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  if (actual.length !== plan.entries.length) throw unsafe('The extracted tree differs from the validated plan.');
  for (let index = 0; index < actual.length; index += 1) {
    const observed = actual[index];
    const expected = plan.entries[index];
    const expectedDestination = path.join(staging.target, ...expected.path.split('/'));
    if (observed.path !== expected.path || observed.type !== expected.type || observed.size !== expected.size
      || observed.sha256 !== expected.sha256 || (process.platform !== 'win32' && observed.mode !== expected.mode)
      || !sameHostPath(observed.destination, expectedDestination)) {
      throw unsafe('The extracted tree differs from the validated plan.');
    }
  }
  await assertExactDirectory(staging.target, staging.identity, fsApi, { mode: 0o700, parent: staging.rootStats, enforceMode: plan.targetPlatform !== 'win32' });
  const candidate = actual.filter((entry) => entry.type === 'file' && path.posix.basename(entry.path) === plan.expectedExecutable);
  if (candidate.length !== 1 || candidate[0].path !== plan.candidate.path || candidate[0].size !== plan.candidate.size
    || candidate[0].sha256 !== plan.candidate.sha256 || (process.platform !== 'win32' && candidate[0].mode !== plan.candidate.mode)) {
    throw unsafe('The extracted candidate identity differs from the validated plan.');
  }
  await adapter.beforeFinalHandoff?.({ plan, stagingDir: staging.target });
  const finalPaths = [];
  async function collect(directory, relativeDirectory = '') {
    for (const child of await fsApi.readdir(directory, { withFileTypes: true })) {
      const relative = relativeDirectory ? relativeDirectory + '/' + child.name : child.name;
      finalPaths.push(relative);
      if (child.isDirectory()) await collect(path.join(directory, child.name), relative);
    }
  }
  await collect(staging.target);
  finalPaths.sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  if (JSON.stringify(finalPaths) !== JSON.stringify(actual.map((entry) => entry.path))) {
    throw unsafe('The extracted tree changed before handoff.');
  }
  for (const observed of actual) {
    const stats = await fsApi.lstat(observed.destination);
    const canonical = await fsApi.realpath(observed.destination);
    if (!sameIdentity(stats, observed.identity) || stats.isSymbolicLink?.() || stats.isReparsePoint === true
      || !sameHostPath(canonical, observed.destination)) throw unsafe('The extracted tree changed before handoff.');
    if (observed.type === 'file') {
      const bytes = await fsApi.readFile(observed.destination);
      if (bytes.length !== observed.size || digest(bytes) !== observed.sha256) {
        throw unsafe('The extracted candidate changed before handoff.');
      }
    }
  }
  const candidatePath = candidate[0].destination;
  const candidateIdentity = candidate[0].identity;
  const handleFlags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let handle;
  let candidateExactIdentity;
  try {
    const beforePath = await fsApi.lstat(candidatePath);
    const beforeCanonical = await fsApi.realpath(candidatePath);
    if (!sameIdentity(beforePath, candidateIdentity) || beforePath.isSymbolicLink?.() || beforePath.isReparsePoint === true
      || !sameHostPath(beforeCanonical, candidatePath)) throw unsafe('The extracted candidate changed before handle verification.');
    handle = await fsApi.open(candidatePath, handleFlags);
    const before = await handle.stat();
    const exactBefore = await handle.stat({ bigint: true });
    candidateExactIdentity = exactIdentity(exactBefore);
    if (!before.isFile?.() || before.nlink > 1 || !sameIdentity(before, candidateIdentity)) {
      throw unsafe('The extracted candidate handle has an unexpected identity.');
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (!sameIdentity(before, after) || after.size !== bytes.length || bytes.length !== candidate[0].size
      || !sameDigest(digest(bytes), candidate[0].sha256)) throw unsafe('The extracted candidate changed during handle verification.');
    await adapter.afterCandidateReadBeforeReturn?.({ plan, stagingDir: staging.target, candidatePath });
    const finalPath = await fsApi.lstat(candidatePath);
    const finalCanonical = await fsApi.realpath(candidatePath);
    if (!sameIdentity(finalPath, after) || finalPath.isSymbolicLink?.() || finalPath.isReparsePoint === true
      || !sameHostPath(finalCanonical, candidatePath)) throw unsafe('The extracted candidate pathname changed before return.');
  } finally {
    await handle?.close();
  }
  const descriptor = {
    size: candidate[0].size,
    sha256: candidate[0].sha256,
    mode: plan.candidate.mode
  };
  const record = deepFreeze({ path: candidatePath, identity: candidateExactIdentity });
  deepFreeze(descriptor);
  extractedCandidates.set(descriptor, record);
  return descriptor;
}

async function readExactHandle(handle, expectedSize) {
  if (!Number.isSafeInteger(expectedSize) || expectedSize < 0) throw unsafe('The candidate size is invalid.');
  const bytes = Buffer.alloc(expectedSize);
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset !== bytes.length) throw unsafe('The candidate handle returned truncated bytes.');
  return bytes;
}

export async function withValidatedExtractedCandidate(candidate, consumer, adapter = {}) {
  const record = extractedCandidates.get(candidate);
  if (!record || !Object.isFrozen(candidate) || typeof consumer !== 'function') {
    throw safety('Candidate use requires the original immutable extracted descriptor and a scoped consumer.');
  }
  const fsApi = adapter.fsApi ?? fs;
  let handle;
  let releasePin;
  try {
    const pathStats = await fsApi.lstat(record.path, { bigint: true });
    const canonical = await fsApi.realpath(record.path);
    if (!sameExactIdentity(pathStats, record.identity) || pathStats.isSymbolicLink?.() || pathStats.isReparsePoint === true
      || !sameHostPath(canonical, record.path)) throw unsafe('The extracted candidate changed before scoped use.');
    handle = await fsApi.open(record.path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    if (process.platform === 'win32') releasePin = await pinWindowsCandidate(record, candidate);
    const before = await handle.stat();
    const exactBefore = await handle.stat({ bigint: true });
    const bytes = await readExactHandle(handle, candidate.size);
    const after = await handle.stat();
    if (!before.isFile?.() || before.nlink > 1 || !sameExactIdentity(exactBefore, record.identity) || !sameIdentity(before, after)
      || after.size !== bytes.length || !sameDigest(digest(bytes), candidate.sha256)) {
      throw unsafe('The extracted candidate changed before scoped use.');
    }
    await adapter.beforeCandidateConsumer?.({ candidatePath: record.path });
    const finalPath = await fsApi.lstat(record.path, { bigint: true });
    const finalCanonical = await fsApi.realpath(record.path);
    if (!sameExactIdentity(finalPath, record.identity) || finalPath.isSymbolicLink?.() || finalPath.isReparsePoint === true
      || !sameHostPath(finalCanonical, record.path)) throw unsafe('The extracted candidate pathname changed before scoped use.');
    const scope = Object.freeze({ path: record.path, handle, identity: record.identity });
    const result = await consumer(scope);
    const callbackAfter = await handle.stat();
    const callbackExact = await handle.stat({ bigint: true });
    const callbackPath = await fsApi.lstat(record.path, { bigint: true });
    if (!sameIdentity(after, callbackAfter) || !sameExactIdentity(callbackExact, record.identity)
      || !sameExactIdentity(callbackPath, record.identity)) throw unsafe('The extracted candidate changed during scoped use.');
    return result;
  } catch (cause) {
    if (cause instanceof ClaudexError) throw cause;
    throw unsafe('The extracted candidate could not be used through a pinned scope.', cause);
  } finally {
    await handle?.close();
    await releasePin?.();
  }
}

export async function revalidateExtractedCandidate(candidate, adapter = {}) {
  await withValidatedExtractedCandidate(candidate, async () => undefined, adapter);
  return candidate;
}

async function cleanupOwnedStaging(staging, plan, fsApi, adapter) {
  if (!staging?.identity) return undefined;
  const stagingExactIdentity = { dev: staging.nativeIdentity.volume, ino: staging.nativeIdentity.fileId };
  await assertExactDirectory(plan.stagingRoot, plan.stagingRootIdentity, fsApi);
  await assertExactNativeDirectory(staging.target, stagingExactIdentity, fsApi, { parent: staging.rootStats });
  await adapter.afterRetainedStagingValidation?.({ plan, stagingDir: staging.target, identity: stagingExactIdentity });
  await assertExactDirectory(plan.stagingRoot, plan.stagingRootIdentity, fsApi);
  await assertExactNativeDirectory(staging.target, stagingExactIdentity, fsApi, { parent: staging.rootStats });
  return deepFreeze({ retained: true, retainedPath: staging.target, retainedIdentity: stagingExactIdentity });
}
/** Extract an in-memory branded immutable plan and verify every materialized path. */
export async function extractValidatedArchive(plan, stagingDir, adapter = {}) {
  if (!validatedPlans.has(plan) || !Object.isFrozen(plan) || !Object.isFrozen(plan.entries)
    || adapter.targetPlatform !== plan.targetPlatform) {
    throw safety('Archive extraction requires the original immutable validated plan.');
  }
  const fsApi = adapter.fsApi ?? fs;
  let staging;
  try {
    await recheckArchive(plan, fsApi);
    staging = await createStaging(plan, stagingDir, fsApi, adapter);
    await adapter.beforeExtractor?.({ plan, stagingDir: staging.target });
    await assertExactDirectory(plan.stagingRoot, plan.stagingRootIdentity, fsApi);
    await assertExactDirectory(staging.target, staging.identity, fsApi, { mode: 0o700, parent: staging.rootStats, enforceMode: plan.targetPlatform !== 'win32' });
    await recheckArchive(plan, fsApi);
    if (plan.kind === 'zip') await runWindowsExtraction(plan, staging, adapter);
    else await runPosixExtraction(plan, staging.target, adapter);
    await adapter.beforePostWalk?.({ plan, stagingDir: staging.target });
    return await walkExtractedTree(plan, staging, adapter);
  } catch (cause) {
    if (cause instanceof ClaudexError && cause.details?.exitUnconfirmed) {
      cause.details = { ...cause.details, stagingRetained: true };
      throw cause;
    }
    let cleanup;
    try {
      cleanup = await cleanupOwnedStaging(staging, plan, fsApi, adapter);
    } catch (cleanupCause) {
      throw safety('Archive staging cleanup failed closed.', cleanupCause);
    }
    const retention = cleanup?.retained ? {
      stagingRetained: true,
      retainedStagingPath: cleanup.retainedPath,
      retainedStagingIdentity: cleanup.retainedIdentity
    } : {};
    if (cause instanceof ClaudexError) {
      if (cleanup?.retained) cause.details = { ...cause.details, ...retention };
      throw cause;
    }
    const wrapped = unsafe('Archive extraction failed safely.', cause);
    if (cleanup?.retained) wrapped.details = { ...wrapped.details, ...retention };
    throw wrapped;
  }
}
