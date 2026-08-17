param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ProjectOrigin = 'https://github.com/ramsaijanapana/claudey'
$ManagerVersion = ''
$AcceptYes = $false
$DisablePath = $false
$Rollback = $false
$Seen = @{}
$RawArguments = @($args)

function Write-Failure([string]$Code, [string]$Message, [int]$Status) {
  [Console]::Error.WriteLine("error[$Code]: $Message")
  exit $Status
}

function Write-Usage {
  Write-Failure 'USAGE_ERROR' 'Usage: install.ps1 [-Version VERSION] [-Yes] [-NoPath] [-RollbackManager]' 64
}

for ($Index = 0; $Index -lt $RawArguments.Count; $Index += 1) {
  $Argument = [string]$RawArguments[$Index]
  if ($Seen.ContainsKey($Argument)) { Write-Usage }
  switch -CaseSensitive ($Argument) {
    '-Version' {
      if ($Index + 1 -ge $RawArguments.Count) { Write-Usage }
      $CandidateVersion = [string]$RawArguments[$Index + 1]
      if ($CandidateVersion -notmatch '^(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})$' -or
          $CandidateVersion.Length -gt 32) { Write-Usage }
      $ManagerVersion = $CandidateVersion
      $Seen[$Argument] = $true
      $Index += 1
    }
    '-Yes' { $AcceptYes = $true; $Seen[$Argument] = $true }
    '-NoPath' { $DisablePath = $true; $Seen[$Argument] = $true }
    '-RollbackManager' { $Rollback = $true; $Seen[$Argument] = $true }
    default { Write-Usage }
  }
}
if ($Rollback -and ($ManagerVersion -ne '' -or $AcceptYes -or $DisablePath)) { Write-Usage }

function Assert-SafeAbsolutePath([string]$Value, [string]$Label) {
  if ([string]::IsNullOrWhiteSpace($Value) -or $Value.IndexOf([char]0) -ge 0 -or $Value.Contains("`r") -or
      $Value.Contains("`n") -or $Value.StartsWith('\\')) {
    Write-Failure 'SAFETY_REFUSAL' "$Label must be a safe local absolute path." 7
  }
  $Full = [IO.Path]::GetFullPath($Value)
  if (-not [IO.Path]::IsPathRooted($Full) -or $Full -eq [IO.Path]::GetPathRoot($Full)) {
    Write-Failure 'SAFETY_REFUSAL' "$Label must be a non-root absolute path." 7
  }
  if (-not [string]::Equals($Value.TrimEnd([char]'\'), $Full.TrimEnd([char]'\'), [StringComparison]::OrdinalIgnoreCase)) {
    Write-Failure 'SAFETY_REFUSAL' "$Label must already be canonical." 7
  }
  return $Full
}

function Assert-NoReparseChain([string]$Target) {
  $Current = [IO.Path]::GetFullPath($Target)
  while ($true) {
    if (Test-Path -LiteralPath $Current) {
      $Item = Get-Item -LiteralPath $Current -Force
      if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Write-Failure 'SAFETY_REFUSAL' 'Managed paths cannot resolve through reparse points.' 7
      }
    }
    $Parent = [IO.Directory]::GetParent($Current)
    if ($null -eq $Parent) { break }
    $Current = $Parent.FullName
  }
}

function Protect-Directory([string]$Target, [Security.Principal.SecurityIdentifier]$UserSid) {
  Assert-NoReparseChain $Target
  [IO.Directory]::CreateDirectory($Target) | Out-Null
  Assert-NoReparseChain $Target
  $Security = New-Object Security.AccessControl.DirectorySecurity
  $Security.SetAccessRuleProtection($true, $false)
  $Inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [Security.AccessControl.InheritanceFlags]::ObjectInherit
  $Propagation = [Security.AccessControl.PropagationFlags]::None
  $Allow = [Security.AccessControl.AccessControlType]::Allow
  $FullControl = [Security.AccessControl.FileSystemRights]::FullControl
  $Required = @(
    $UserSid,
    (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')),
    (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544'))
  )
  foreach ($Sid in $Required) {
    $Rule = New-Object Security.AccessControl.FileSystemAccessRule($Sid, $FullControl, $Inheritance, $Propagation, $Allow)
    $Security.AddAccessRule($Rule) | Out-Null
  }
  (New-Object IO.DirectoryInfo($Target)).SetAccessControl($Security)
  $Actual = Get-Acl -LiteralPath $Target
  if (-not $Actual.AreAccessRulesProtected) {
    Write-Failure 'SAFETY_REFUSAL' 'A managed directory DACL is not protected.' 7
  }
  $Rules = @($Actual.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
  if ($Rules.Count -ne 3) { Write-Failure 'SAFETY_REFUSAL' 'A managed directory DACL is not exact.' 7 }
  $RequiredText = @($Required | ForEach-Object { $_.Value } | Sort-Object)
  $ActualText = @($Rules | ForEach-Object { $_.IdentityReference.Value } | Sort-Object)
  if (($RequiredText -join ',') -ne ($ActualText -join ',')) {
    Write-Failure 'SAFETY_REFUSAL' 'A managed directory DACL has an unexpected principal.' 7
  }
  foreach ($Rule in $Rules) {
    if ($Rule.AccessControlType -ne $Allow -or ($Rule.FileSystemRights -band $FullControl) -ne $FullControl -or
        $Rule.InheritanceFlags -ne $Inheritance -or $Rule.PropagationFlags -ne $Propagation) {
      Write-Failure 'SAFETY_REFUSAL' 'A managed directory DACL has unsafe rights or inheritance.' 7
    }
  }
}

function Acquire-BootstrapLock([string]$Target) {
  $Share = [IO.FileShare]::None
  try {
    $Stream = New-Object IO.FileStream($Target, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, $Share)
  } catch [IO.IOException] {
    try {
      $Stream = New-Object IO.FileStream($Target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, $Share)
    } catch [IO.IOException] {
      Write-Failure 'LOCK_BUSY' 'Another manager bootstrap owns the installation lock.' 6
    }
    if ($Stream.Length -lt 2 -or $Stream.Length -gt 4096) {
      $Stream.Dispose(); Write-Failure 'SAFETY_REFUSAL' 'The manager bootstrap lock is malformed.' 7
    }
    $Bytes = New-Object byte[] ([int]$Stream.Length)
    if ($Stream.Read($Bytes, 0, $Bytes.Length) -ne $Bytes.Length) {
      $Stream.Dispose(); Write-Failure 'SAFETY_REFUSAL' 'The manager bootstrap lock could not be read.' 7
    }
    try { $Prior = ([Text.UTF8Encoding]::new($false, $true)).GetString($Bytes) | ConvertFrom-Json }
    catch { $Stream.Dispose(); Write-Failure 'SAFETY_REFUSAL' 'The manager bootstrap lock is malformed.' 7 }
    $PriorNames = @($Prior.PSObject.Properties.Name | Sort-Object)
    if (($PriorNames -join ',') -ne 'createdAtMs,pid,schemaVersion' -or $Prior.schemaVersion -ne 1 -or
        $Prior.pid -isnot [int] -or $Prior.pid -lt 1 -or $Prior.createdAtMs -isnot [long] -or
        $Prior.createdAtMs -lt 0 -or $Prior.createdAtMs -gt [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) {
      $Stream.Dispose(); Write-Failure 'SAFETY_REFUSAL' 'The manager bootstrap lock is malformed.' 7
    }
    $Stream.SetLength(0)
  }
  $Owner = @{ schemaVersion = 1; pid = [Diagnostics.Process]::GetCurrentProcess().Id; createdAtMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() }
  $OwnerBytes = [Text.UTF8Encoding]::new($false).GetBytes((($Owner | ConvertTo-Json -Compress) + "`n"))
  $Stream.Position = 0
  $Stream.Write($OwnerBytes, 0, $OwnerBytes.Length)
  $Stream.Flush($true)
  return $Stream
}

function Test-LegacyManagedInstall([string]$Root) {
  if (-not (Test-Path -LiteralPath $Root)) { return $false }
  foreach ($Marker in @((Join-Path $Root 'installation.json'), (Join-Path $Root 'token'), (Join-Path $Root 'current.json'))) {
    if (Test-Path -LiteralPath $Marker -PathType Leaf) { return $true }
  }
  $Auth = Join-Path $Root 'auth'
  if (Test-Path -LiteralPath $Auth -PathType Container) {
    if (@(Get-ChildItem -LiteralPath $Auth -Filter '*.json' -File -Force -ErrorAction SilentlyContinue).Count -gt 0) {
      return $true
    }
  }
  $Releases = Join-Path $Root 'releases'
  if (Test-Path -LiteralPath $Releases -PathType Container) {
    if (@(Get-ChildItem -LiteralPath $Releases -Force -ErrorAction SilentlyContinue).Count -gt 0) { return $true }
  }
  return $false
}

function Move-LegacyProductRoot([string]$Parent, [string]$CurrentLeaf) {
  $Current = Join-Path $Parent $CurrentLeaf
  $Found = @()
  foreach ($Leaf in @('claudexctl', 'claudex', 'claudey')) {
    $Legacy = Join-Path $Parent $Leaf
    if (Test-LegacyManagedInstall $Legacy) { $Found += $Legacy }
  }
  $CurrentHasInstall = Test-LegacyManagedInstall $Current
  if ($CurrentHasInstall -and $Found.Count -gt 0) {
    Write-Failure 'SAFETY_REFUSAL' 'Legacy and current Claudey roots both contain an installation.' 7
  }
  if ($CurrentHasInstall -or $Found.Count -eq 0) { return }
  if ($Found.Count -gt 1) {
    Write-Failure 'SAFETY_REFUSAL' 'Multiple legacy Claudey roots contain an installation.' 7
  }
  if (Test-Path -LiteralPath $Current) {
    if (@(Get-ChildItem -LiteralPath $Current -Force -ErrorAction SilentlyContinue).Count -gt 0) {
      Write-Failure 'SAFETY_REFUSAL' 'The current Claudey root is not vacant for brand migration.' 7
    }
    Remove-Item -LiteralPath $Current -Force
  }
  Rename-Item -LiteralPath $Found[0] -NewName $CurrentLeaf
}

function Remove-StaleBrandLaunchers([string]$Directory) {
  if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { return }
  foreach ($Name in @('claudey', 'claudeyctl', 'claude-codex', 'claude-agy', 'claude-grok', 'claudex', 'claudexctl')) {
    foreach ($Extension in @('.bat', '.ps1', ('.' + 'c' + 'md'))) {
      $Target = Join-Path $Directory ($Name + $Extension)
      if (-not (Test-Path -LiteralPath $Target -PathType Leaf)) { continue }
      $Text = [IO.File]::ReadAllText($Target)
      if ($Name -in @('claudex', 'claudexctl') -or $Text -match 'claudexctl\.js|claudex\.js|launcher claudex') {
        Remove-Item -LiteralPath $Target -Force
      }
    }
  }
}

function Update-LegacyUserPath([string]$LocalAppData, [string]$CurrentBin) {
  $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if ($null -eq $UserPath) { $UserPath = '' }
  $Entries = @()
  if ($UserPath.Length -gt 0) { $Entries = $UserPath.Split(';') }
  $Retire = @{}
  foreach ($Leaf in @('claudexctl', 'claudex', 'claudey')) {
    $Retire[(Join-Path $LocalAppData "$Leaf\bin").TrimEnd([char]'\').ToLowerInvariant()] = $true
  }
  $Kept = New-Object System.Collections.Generic.List[string]
  $HaveCurrent = $false
  $CurrentNorm = $CurrentBin.TrimEnd([char]'\').ToLowerInvariant()
  foreach ($Entry in $Entries) {
    $Norm = $Entry.TrimEnd([char]'\').ToLowerInvariant()
    if ($Retire.ContainsKey($Norm)) { continue }
    if ($Norm -eq $CurrentNorm) {
      if ($HaveCurrent) { continue }
      $HaveCurrent = $true
    }
    [void]$Kept.Add($Entry)
  }
  if (-not $HaveCurrent) { [void]$Kept.Add($CurrentBin) }
  $After = [string]::Join(';', $Kept)
  if ($After -ne $UserPath) {
    [Environment]::SetEnvironmentVariable('Path', $After, 'User')
  }
  $ProcessEntries = New-Object System.Collections.Generic.List[string]
  foreach ($Entry in @($env:Path.Split(';'))) {
    $Norm = $Entry.TrimEnd([char]'\').ToLowerInvariant()
    if ($Retire.ContainsKey($Norm)) { continue }
    [void]$ProcessEntries.Add($Entry)
  }
  if (-not (@($ProcessEntries | ForEach-Object { $_.TrimEnd([char]'\').ToLowerInvariant() }) -contains $CurrentNorm)) {
    $ProcessEntries.Insert(0, $CurrentBin)
  }
  $env:Path = [string]::Join(';', $ProcessEntries)
}

$LockStream = $null
$NodePin = $null
$DirectoryPins = @()
try {
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Failure 'PLATFORM_UNSUPPORTED' 'The Windows bootstrap runs only on native Windows.' 69
  }
  $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $NodeCommand = Get-Command 'node.exe' -CommandType Application -ErrorAction SilentlyContinue
  if ($null -eq $NodeCommand) {
    Write-Failure 'PREREQUISITE_MISSING' 'A supported Node.js executable is required.' 69
  }
  $NodePath = [IO.Path]::GetFullPath($NodeCommand.Source)
  Assert-NoReparseChain $NodePath
  $NodePin = [IO.File]::Open($NodePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  $NodeVersion = [string](& $NodePath '-p' 'process.versions.node' 2>$null)
  $NodeVersion = $NodeVersion.Trim()
  if ($LASTEXITCODE -ne 0 -or $NodeVersion -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
    Write-Failure 'PREREQUISITE_MISSING' 'Node.js 22.20.0 or a supported newer line is required.' 69
  }
  $NodeMajor = [int]$Matches[1]; $NodeMinor = [int]$Matches[2]
  if ($NodeMajor -notin @(22, 24, 26)) {
    Write-Failure 'PREREQUISITE_MISSING' 'Node.js 22, 24, or 26 is required.' 69
  }
  if ($NodeMajor -eq 22 -and $NodeMinor -lt 20) {
    Write-Failure 'PREREQUISITE_MISSING' 'Node.js 22.20.0 or newer is required.' 69
  }
  $ReportedNode = ([string](& $NodePath '-p' 'process.execPath' 2>$null)).Trim()
  $RuntimePlatform = ([string](& $NodePath '-p' 'process.platform' 2>$null)).Trim()
  $RuntimeArch = ([string](& $NodePath '-p' 'process.arch' 2>$null)).Trim()
  if ($LASTEXITCODE -ne 0 -or $RuntimePlatform -ne 'win32' -or $RuntimeArch -notin @('x64', 'arm64') -or
      -not [string]::Equals([IO.Path]::GetFullPath($ReportedNode), $NodePath, [StringComparison]::OrdinalIgnoreCase)) {
    Write-Failure 'PLATFORM_UNSUPPORTED' 'The Node.js runtime must be native Windows x64 or ARM64.' 69
  }
  $LocalAppData = Assert-SafeAbsolutePath ([Environment]::GetEnvironmentVariable('LOCALAPPDATA')) 'LOCALAPPDATA'
  $AppData = Assert-SafeAbsolutePath ([Environment]::GetEnvironmentVariable('APPDATA')) 'APPDATA'
  Assert-NoReparseChain $LocalAppData
  Assert-NoReparseChain $AppData
  Move-LegacyProductRoot $LocalAppData 'claudeyctl'
  Move-LegacyProductRoot $AppData 'claudeyctl'
  $ManagerRoot = Join-Path $LocalAppData 'claudeyctl'
  $ReleaseRoot = Join-Path $ManagerRoot 'releases'
  $StagingRoot = Join-Path $ManagerRoot 'staging'
  $StateRoot = Join-Path $ManagerRoot 'state'
  $UserBin = Join-Path $ManagerRoot 'bin'
  foreach ($Directory in @($ManagerRoot, $ReleaseRoot, $StagingRoot, $StateRoot, $UserBin)) {
    Protect-Directory $Directory $Identity.User
  }
  $UserProfile = [Environment]::GetEnvironmentVariable('USERPROFILE')
  if ($UserProfile) { Remove-StaleBrandLaunchers (Join-Path $UserProfile '.local\bin') }
  Remove-StaleBrandLaunchers $UserBin
  Update-LegacyUserPath $LocalAppData $UserBin
  $PinSource = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class ClaudeyBootstrapDirectoryPin {
  [StructLayout(LayoutKind.Sequential)]
  private struct FileAttributeTagInfo { public uint FileAttributes; public uint ReparseTag; }

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
    uint creation, uint flags, IntPtr template);

  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass,
    out FileAttributeTagInfo info, uint size);

  public static SafeFileHandle Open(string path) {
    const uint ShareReadWrite = 0x00000001u | 0x00000002u;
    const uint OpenExisting = 3u;
    const uint BackupSemanticsOpenReparse = 0x02000000u | 0x00200000u;
    SafeFileHandle handle = CreateFileW(path, 0u, ShareReadWrite, IntPtr.Zero, OpenExisting,
      BackupSemanticsOpenReparse, IntPtr.Zero);
    if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
    FileAttributeTagInfo info;
    if (!GetFileInformationByHandleEx(handle, 9, out info, (uint)Marshal.SizeOf(typeof(FileAttributeTagInfo)))
        || (info.FileAttributes & 0x00000010u) == 0u || (info.FileAttributes & 0x00000400u) != 0u) {
      int error = Marshal.GetLastWin32Error(); handle.Dispose();
      throw new Win32Exception(error == 0 ? 5 : error);
    }
    return handle;
  }
}
'@
  Add-Type -TypeDefinition $PinSource -Language CSharp
  foreach ($Directory in @($LocalAppData, $ManagerRoot, $ReleaseRoot, $StagingRoot, $StateRoot, $UserBin)) {
    $DirectoryPins += [ClaudeyBootstrapDirectoryPin]::Open($Directory)
  }
  $LockStream = Acquire-BootstrapLock (Join-Path $StateRoot 'manager-bootstrap.lock')

  $env:CLDY_PROJECT_ORIGIN = $ProjectOrigin
  $env:CLDY_MANAGER_VERSION = $ManagerVersion
  $env:CLDY_TARGET = "windows-$RuntimeArch"
  $env:CLDY_MANAGER_ROOT = $ManagerRoot
  $env:CLDY_RELEASE_ROOT = $ReleaseRoot
  $env:CLDY_STAGING_ROOT = $StagingRoot
  $env:CLDY_STATE_ROOT = $StateRoot
  $env:CLDY_USER_BIN = $UserBin
  $env:CLDY_NODE_PATH = $NodePath
  $env:CLDY_PROJECT_DIR = $PSScriptRoot

  $NodeProgram = @'
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
const RELEASE_TARGET = /^releases\/[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u;
const TARGETS = ['windows-x64', 'windows-arm64', 'darwin-x64', 'darwin-arm64', 'linux-x64', 'linux-arm64'];
const LAUNCHERS = ['claudeyctl.exe', 'claude-codex.exe', 'claude-agy.exe', 'claude-grok.exe', 'claudey.exe'];
const MAX_MANIFEST = 1024 * 1024;
const MAX_PAYLOAD = 32 * 1024 * 1024;
const MAX_SHIM = 8 * 1024 * 1024;
const MAX_EXPANDED = 64 * 1024 * 1024;
const MAX_FILE = 8 * 1024 * 1024;
const UTF8 = new TextDecoder('utf-8', { fatal: true });
const failures = new WeakSet();

class BootstrapFailure extends Error {
  constructor(code = 'SAFETY_REFUSAL', exitCode = 7) {
    super('The manager bootstrap failed safely.'); this.code = code; this.exitCode = exitCode; failures.add(this);
  }
}
const fail = (code, exitCode) => { throw new BootstrapFailure(code, exitCode); };
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const digest = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

function artifact(value, maximum = MAX_PAYLOAD) {
  if (!exact(value, ['name', 'sha256', 'size']) || !NAME.test(value.name) || !SHA256.test(value.sha256)
    || !Number.isSafeInteger(value.size) || value.size < 1 || value.size > maximum) fail('CHECKSUM_MISMATCH');
  return value;
}

function compiler(value) {
  if (!exact(value, ['name', 'version', 'flags']) || typeof value.name !== 'string' || value.name.length < 1
    || value.name.length > 64 || typeof value.version !== 'string' || value.version.length < 1 || value.version.length > 128
    || !Array.isArray(value.flags) || value.flags.length < 1 || value.flags.length > 64
    || new Set(value.flags).size !== value.flags.length
    || value.flags.some((flag) => typeof flag !== 'string' || flag.length < 1 || flag.length > 256
      || /[\u0000\r\n]/u.test(flag))) fail('CHECKSUM_MISMATCH');
}

function checkedManifest(value, requestedVersion, target) {
  if (!exact(value, ['schemaVersion', 'managerVersion', 'sourceRevision', 'managerShimCompatibilityVersion',
    'payload', 'shims', 'targets', 'sbom', 'provenanceSubjects']) || value.schemaVersion !== 1
    || !VERSION.test(value.managerVersion) || requestedVersion && value.managerVersion !== requestedVersion
    || !REVISION.test(value.sourceRevision) || !Number.isSafeInteger(value.managerShimCompatibilityVersion)
    || value.managerShimCompatibilityVersion < 1 || value.managerShimCompatibilityVersion > 0xffffffff) fail('CHECKSUM_MISMATCH');
  artifact(value.payload); artifact(value.sbom);
  if (value.payload.name !== `claudey-manager-${value.managerVersion}.tar.gz`
    || value.sbom.name !== `claudey-manager-${value.managerVersion}.spdx.json`
    || !exact(value.shims, ['windows-x64', 'windows-arm64']) || !exact(value.targets, TARGETS)) fail('CHECKSUM_MISMATCH');
  for (const windowsTarget of ['windows-x64', 'windows-arm64']) {
    const shim = value.shims[windowsTarget];
    if (!exact(shim, ['name', 'sha256', 'size', 'compiler'])) fail('CHECKSUM_MISMATCH');
    artifact({ name: shim.name, sha256: shim.sha256, size: shim.size }, MAX_SHIM); compiler(shim.compiler);
    if (shim.name !== `claudey-${windowsTarget}.exe`) fail('CHECKSUM_MISMATCH');
  }
  for (const candidate of TARGETS) {
    const mapping = value.targets[candidate];
    if (!exact(mapping, ['payload', 'shim']) || mapping.payload !== value.payload.name) fail('CHECKSUM_MISMATCH');
    const expected = candidate === 'windows-x64' ? value.shims['windows-x64'].name
      : candidate === 'windows-arm64' ? value.shims['windows-arm64'].name : null;
    if (mapping.shim !== expected) fail('CHECKSUM_MISMATCH');
  }
  if (!['windows-x64', 'windows-arm64'].includes(target) || value.targets[target].shim !== value.shims[target].name) {
    fail('PLATFORM_UNSUPPORTED', 69);
  }
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
    const request = transport.get(url, { headers: { 'user-agent': 'claudey-bootstrap/1', accept: 'application/octet-stream' } }, (response) => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
        const location = response.headers.location; response.resume();
        if (typeof location !== 'string') { reject(new BootstrapFailure('NETWORK_FAILURE', 5)); return; }
        download(new URL(location, url).href, maximum, projectOrigin, redirects + 1).then(resolve, reject); return;
      }
      if (response.statusCode !== 200) { response.resume(); reject(new BootstrapFailure('NETWORK_FAILURE', 5)); return; }
      const declared = response.headers['content-length'];
      if (declared !== undefined && (!/^\d+$/u.test(declared) || Number(declared) > maximum)) {
        response.destroy(); reject(new BootstrapFailure('NETWORK_FAILURE', 5)); return;
      }
      const chunks = []; let total = 0;
      response.on('data', (chunk) => {
        total += chunk.length;
        if (total > maximum) response.destroy(new BootstrapFailure('NETWORK_FAILURE', 5)); else chunks.push(chunk);
      });
      response.on('end', () => resolve(Buffer.concat(chunks)));
      response.on('error', (error) => reject(failures.has(error) ? error : new BootstrapFailure('NETWORK_FAILURE', 5)));
    });
    request.setTimeout(30_000, () => request.destroy(new BootstrapFailure('NETWORK_FAILURE', 5)));
    request.on('error', (error) => reject(failures.has(error) ? error : new BootstrapFailure('NETWORK_FAILURE', 5)));
  });
}

function octal(header, start, length) {
  const raw = header.subarray(start, start + length).toString('ascii').replace(/[\0 ]+$/u, '');
  if (!/^[0-7]+$/u.test(raw)) fail('ARCHIVE_UNSAFE');
  const value = Number.parseInt(raw, 8); if (!Number.isSafeInteger(value)) fail('ARCHIVE_UNSAFE'); return value;
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
    || compressed[3] !== 0 || compressed.readUInt32LE(4) !== 0 || compressed[8] !== 2 || compressed[9] !== 255) fail('ARCHIVE_UNSAFE');
  let inflated;
  try { inflated = zlib.inflateRawSync(compressed.subarray(10), { info: true, maxOutputLength: MAX_EXPANDED }); }
  catch { fail('ARCHIVE_UNSAFE'); }
  const compressedBytes = inflated.engine.bytesWritten; const trailerOffset = 10 + compressedBytes; const data = inflated.buffer;
  if (trailerOffset !== compressed.length - 8 || compressed.readUInt32LE(trailerOffset) !== crc32(data)
    || compressed.readUInt32LE(trailerOffset + 4) !== (data.length >>> 0)
    || data.length > Math.max(1, compressedBytes) * 100) fail('ARCHIVE_UNSAFE');
  const entries = []; let offset = 0; let prior = ''; let total = 0;
  while (offset + 512 <= data.length) {
    const header = data.subarray(offset, offset + 512); if (header.every((byte) => byte === 0)) break;
    if (entries.length >= 2_048 || header.subarray(257, 263).toString('latin1') !== 'ustar\0'
      || header.subarray(263, 265).toString('ascii') !== '00' || !header.subarray(157, 257).every((byte) => byte === 0)
      || !header.subarray(265).every((byte) => byte === 0)) fail('ARCHIVE_UNSAFE');
    const storedChecksum = octal(header, 148, 8); const checksumHeader = Buffer.from(header); checksumHeader.fill(0x20, 148, 156);
    if (checksumHeader.reduce((sum, byte) => sum + byte, 0) !== storedChecksum) fail('ARCHIVE_UNSAFE');
    const nameField = header.subarray(0, 100); const nameEnd = nameField.indexOf(0);
    if (nameEnd === 0 || nameEnd >= 0 && !nameField.subarray(nameEnd).every((byte) => byte === 0)) fail('ARCHIVE_UNSAFE');
    let decodedName;
    try { decodedName = UTF8.decode(nameEnd < 0 ? nameField : nameField.subarray(0, nameEnd)); }
    catch { fail('ARCHIVE_UNSAFE'); }
    const name = safeArchivePath(decodedName, prior); prior = name;
    const type = header[156]; const mode = octal(header, 100, 8); const size = octal(header, 124, 12);
    if (![0, 0x30].includes(type) || ![0o644, 0o755].includes(mode) || octal(header, 108, 8) !== 0
      || octal(header, 116, 8) !== 0 || octal(header, 136, 12) !== 0 || size > MAX_FILE) fail('ARCHIVE_UNSAFE');
    total += size; const end = offset + 512 + size;
    if (total > MAX_EXPANDED || end > data.length) fail('ARCHIVE_UNSAFE');
    entries.push({ path: name, mode, size, sha256: digest(data.subarray(offset + 512, end)),
      bytes: Buffer.from(data.subarray(offset + 512, end)) });
    const nextOffset = offset + 512 + Math.ceil(size / 512) * 512;
    if (nextOffset > data.length || !data.subarray(end, nextOffset).every((byte) => byte === 0)) fail('ARCHIVE_UNSAFE');
    offset = nextOffset;
  }
  if (entries.length < 1 || data.length - offset < 1024 || !data.subarray(offset).every((byte) => byte === 0)) fail('ARCHIVE_UNSAFE');
  for (const required of ['LICENSE', 'bin/claude-agy', 'bin/claude-grok', 'bin/claudey', 'bin/claude-codex', 'bin/claudeyctl', 'bin/claudeyctl.js', 'package.json']) {
    if (!entries.some((entry) => entry.path === required)) fail('ARCHIVE_UNSAFE');
  }
  return entries;
}

async function inspectDirectory(target) {
  const metadata = await fs.lstat(target);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.nlink < 1) fail();
  return metadata;
}

async function ensureDirectory(target) {
  try { await fs.mkdir(target); }
  catch (error) { if (error?.code !== 'EEXIST') throw error; }
  await inspectDirectory(target);
}

async function ensureParents(root, relative) {
  let current = root;
  for (const part of relative.split('/').slice(0, -1)) { current = path.join(current, part); await ensureDirectory(current); }
}

async function writeExclusive(target, bytes) {
  await fs.writeFile(target, bytes, { flag: 'wx' });
  const metadata = await fs.lstat(target);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || metadata.size !== bytes.length
    || digest(await fs.readFile(target)) !== digest(bytes)) fail();
}

async function atomicWrite(target, bytes) {
  const temporary = `${target}.${crypto.randomUUID()}.tmp`;
  try {
    await writeExclusive(temporary, bytes);
    let attempts = 0;
    while (attempts < 10) {
      try {
        await fs.rename(temporary, target);
        return;
      } catch (error) {
        if (error?.code !== 'EPERM' && error?.code !== 'EBUSY' && error?.code !== 'EEXIST') throw error;
        attempts += 1;
        if (attempts >= 10) {
          try { await fs.copyFile(temporary, target); await fs.unlink(temporary); return; }
          catch { throw error; }
        }
        await new Promise((r) => setTimeout(r, 100));
      }
    }
  } finally { await fs.rm(temporary, { force: true }); }
}

async function atomicJson(target, value) { await atomicWrite(target, Buffer.from(`${JSON.stringify(value)}\n`, 'utf8')); }

async function extract(entries, destination) {
  await inspectDirectory(destination);
  for (const entry of entries) {
    const target = path.join(destination, ...entry.path.split('/'));
    if (target !== path.resolve(target) || !target.startsWith(`${destination}${path.sep}`)) fail('ARCHIVE_UNSAFE');
    await ensureParents(destination, entry.path); await writeExclusive(target, entry.bytes);
  }
}

function markerFor(manifest, entries, shim) {
  return { schemaVersion: 1, managerVersion: manifest.managerVersion, sourceRevision: manifest.sourceRevision,
    payloadSha256: manifest.payload.sha256, managerShimCompatibilityVersion: manifest.managerShimCompatibilityVersion,
    shim: { name: shim.name, sha256: shim.sha256, size: shim.size },
    files: entries.map(({ path: filePath, mode, size, sha256 }) => ({ path: filePath, mode, size, sha256 })) };
}

async function readRegular(target, maximum = MAX_FILE) {
  const before = await fs.lstat(target, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(maximum)) fail();
  const handle = await fs.open(target, 'r');
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || opened.dev !== before.dev || opened.ino !== before.ino
      || opened.size !== before.size || opened.mtimeNs !== before.mtimeNs) fail();
    const bytes = await handle.readFile(); const after = await handle.stat({ bigint: true });
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size || after.mtimeNs !== opened.mtimeNs
      || BigInt(bytes.length) !== opened.size) fail();
    return bytes;
  } finally { await handle.close(); }
}

async function validateRelease(directory, expected) {
  await inspectDirectory(directory);
  let marker;
  try { marker = JSON.parse((await readRegular(path.join(directory, '.claudey-release.json'), MAX_MANIFEST)).toString('utf8')); }
  catch { fail(); }
  if (!exact(marker, ['schemaVersion', 'managerVersion', 'sourceRevision', 'payloadSha256',
    'managerShimCompatibilityVersion', 'shim', 'files']) || marker.schemaVersion !== 1 || !VERSION.test(marker.managerVersion)
    || !REVISION.test(marker.sourceRevision) || !SHA256.test(marker.payloadSha256)
    || !Number.isSafeInteger(marker.managerShimCompatibilityVersion) || marker.managerShimCompatibilityVersion < 1
    || !exact(marker.shim, ['name', 'sha256', 'size'])) fail();
  artifact(marker.shim, MAX_SHIM);
  if (expected && (marker.managerVersion !== expected.managerVersion || marker.sourceRevision !== expected.sourceRevision
    || marker.payloadSha256 !== expected.payload.sha256 || marker.managerShimCompatibilityVersion !== expected.managerShimCompatibilityVersion
    || marker.shim.name !== expected.shim.name || marker.shim.sha256 !== expected.shim.sha256 || marker.shim.size !== expected.shim.size)) fail();
  if (!Array.isArray(marker.files) || marker.files.length < 1 || marker.files.length > 10_000) fail();
  let prior = '';
  for (const entry of marker.files) {
    if (!exact(entry, ['path', 'mode', 'size', 'sha256']) || safeArchivePath(entry.path, prior) !== entry.path
      || ![0o644, 0o755].includes(entry.mode) || !Number.isSafeInteger(entry.size) || entry.size < 0 || !SHA256.test(entry.sha256)) fail();
    prior = entry.path;
    const bytes = await readRegular(path.join(directory, ...entry.path.split('/')), MAX_FILE);
    if (bytes.length !== entry.size || digest(bytes) !== entry.sha256) fail();
  }
  const shimBytes = await readRegular(path.join(directory, '.claudey-shim.exe'), MAX_SHIM);
  if (shimBytes.length !== marker.shim.size || digest(shimBytes) !== marker.shim.sha256) fail();
  const actual = [];
  async function walk(current, prefix = '') {
    const children = await fs.readdir(current, { withFileTypes: true });
    children.sort((left, right) => left.name.localeCompare(right.name, 'en'));
    for (const child of children) {
      const relative = prefix ? `${prefix}/${child.name}` : child.name;
      if (child.isSymbolicLink() || !child.isDirectory() && !child.isFile()) fail();
      if (child.isDirectory()) { await inspectDirectory(path.join(current, child.name)); await walk(path.join(current, child.name), relative); }
      else actual.push(relative);
    }
  }
  await walk(directory);
  const expectedFiles = ['.claudey-release.json', '.claudey-shim.exe', ...marker.files.map(({ path: filePath }) => filePath)].sort();
  if (JSON.stringify(actual.sort()) !== JSON.stringify(expectedFiles)) fail();
  return marker;
}

function safeEnvironment(extra = {}) {
  const result = {};
  for (const key of ['APPDATA', 'LOCALAPPDATA', 'PATH', 'SystemRoot', 'SYSTEMROOT', 'TEMP', 'TMP', 'USERPROFILE', 'WINDIR']) {
    const value = process.env[key]; if (typeof value === 'string' && value.length > 0 && !/[\u0000\r\n]/u.test(value)) result[key] = value;
  }
  return { ...result, ...extra };
}

async function selfTestRelease(directory, version) {
  let packageJson;
  try { packageJson = JSON.parse((await readRegular(path.join(directory, 'package.json'))).toString('utf8')); } catch { fail(); }
  if (!packageJson || packageJson.name !== 'claudeyctl' || packageJson.version !== version || packageJson.type !== 'module'
    || packageJson.dependencies || packageJson.optionalDependencies || packageJson.peerDependencies) fail();
  const manager = path.join(directory, 'bin', 'claudeyctl.js');
  const syntax = spawnSync(process.execPath, ['--check', manager], { encoding: 'utf8', shell: false,
    windowsHide: true, timeout: 10_000, maxBuffer: 64 * 1024, env: safeEnvironment() });
  if (syntax.error || syntax.status !== 0 || syntax.signal !== null || syntax.stdout !== '' || syntax.stderr !== '') fail();
  const help = spawnSync(process.execPath, [manager, '--help'], { encoding: 'utf8', shell: false,
    windowsHide: true, timeout: 10_000, maxBuffer: 256 * 1024, env: safeEnvironment() });
  if (help.error || help.status !== 0 || help.signal !== null || help.stderr !== '' || !help.stdout.includes('claudeyctl setup')) fail();
}

function launcherMetadata(nodePath, managerPath, compatibility, key, installationId) {
  if (!path.win32.isAbsolute(nodePath) || !path.win32.isAbsolute(managerPath) || /[\u0000\r\n]/u.test(`${nodePath}${managerPath}`)
    || key.length !== 32 || installationId.length !== 16 || !Number.isSafeInteger(compatibility)
    || compatibility < 1 || compatibility > 0xffffffff) fail();
  const nodeBytes = Buffer.from(nodePath, 'utf16le'); const managerBytes = Buffer.from(managerPath, 'utf16le');
  if (nodeBytes.length / 2 < 4 || nodeBytes.length / 2 > 4096 || managerBytes.length / 2 < 4 || managerBytes.length / 2 > 4096) fail();
  const prefix = Buffer.alloc(40); prefix.write('CLDYL001', 0, 8, 'ascii'); prefix.writeUInt32LE(1, 8);
  prefix.writeUInt32LE(compatibility, 12); prefix.writeUInt32LE(nodeBytes.length / 2, 16);
  prefix.writeUInt32LE(managerBytes.length / 2, 20); installationId.copy(prefix, 24);
  const strings = Buffer.concat([nodeBytes, managerBytes]);
  const tag = crypto.createHmac('sha256', key).update(prefix).update(strings).digest();
  return Buffer.concat([prefix, tag, strings]);
}

const LOADER_SOURCE = `import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
const exact=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...k].sort().join(',');
const regular=(p,m)=>{const s=fs.lstatSync(p,{bigint:true});if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1n||s.size<1n||s.size>BigInt(m))throw 0;const b=fs.readFileSync(p);const a=fs.lstatSync(p,{bigint:true});if(a.dev!==s.dev||a.ino!==s.ino||a.size!==s.size||a.mtimeNs!==s.mtimeNs||BigInt(b.length)!==s.size)throw 0;return b;};
try{const root=path.resolve(import.meta.dirname);const pointer=JSON.parse(regular(path.join(root,'current.json'),1048576).toString('utf8'));if(!exact(pointer,['schemaVersion','target'])||pointer.schemaVersion!==1||!/^releases\\/[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u.test(pointer.target))throw 0;const release=path.join(root,...pointer.target.split('/'));if(!release.startsWith(root+path.sep))throw 0;const marker=JSON.parse(regular(path.join(release,'.claudey-release.json'),1048576).toString('utf8'));if(!exact(marker,['schemaVersion','managerVersion','sourceRevision','payloadSha256','managerShimCompatibilityVersion','shim','files'])||!Array.isArray(marker.files))throw 0;const entry=marker.files.find((v)=>v&&v.path==='bin/claudeyctl.js');if(!exact(entry,['path','mode','size','sha256'])||!Number.isSafeInteger(entry.size)||!/^[0-9a-f]{64}$/u.test(entry.sha256))throw 0;const manager=path.join(release,'bin','claudeyctl.js');const bytes=regular(manager,8388608);if(bytes.length!==entry.size||crypto.createHash('sha256').update(bytes).digest('hex')!==entry.sha256)throw 0;const env={};for(const key of ['APPDATA','LOCALAPPDATA','PATH','SystemRoot','SYSTEMROOT','TEMP','TMP','USERPROFILE','WINDIR']){const value=process.env[key];if(typeof value==='string'&&value.length>0&&!/[\\u0000\\r\\n]/u.test(value))env[key]=value;}const child=spawnSync(process.execPath,[manager,...process.argv.slice(2)],{stdio:'inherit',shell:false,windowsHide:true,env});process.exit(child.error||child.signal!==null||!Number.isInteger(child.status)?7:child.status);}catch{process.exit(7);}
`;

async function captureShim(shimBytes, compatibility, stagingRoot) {
  const capture = await fs.mkdtemp(path.join(stagingRoot, 'capture-')); const output = path.join(capture, 'capture.jsonl');
  try {
    const manager = path.join(capture, 'capture.mjs');
    await writeExclusive(manager, Buffer.from("import fs from 'node:fs';fs.appendFileSync(process.env.CLDY_CAPTURE_FILE,JSON.stringify(process.argv.slice(2))+'\\n');\n"));
    const key = crypto.randomBytes(32); const metadata = launcherMetadata(process.execPath, manager, compatibility, key, crypto.randomBytes(16));
    await writeExclusive(path.join(capture, 'claudey-launcher.key'), key);
    await writeExclusive(path.join(capture, 'claudey-launcher.bin'), metadata);
    for (const name of LAUNCHERS) await writeExclusive(path.join(capture, name), shimBytes);
    const hostile = ['', 'two words', 'quote"value', "single'value", '$()', '%PATH%', '--flag', 'line\r\nbreak'];
    for (const name of LAUNCHERS) {
      const result = spawnSync(path.join(capture, name), hostile, { encoding: 'utf8', shell: false, windowsHide: true,
        timeout: 10_000, maxBuffer: 64 * 1024, env: safeEnvironment({ CLDY_CAPTURE_FILE: output }) });
      if (result.error || result.status !== 0 || result.signal !== null || result.stdout !== '' || result.stderr !== '') fail();
    }
    const rows = (await fs.readFile(output, 'utf8')).trim().split(/\r?\n/u).map(JSON.parse);
    const expected = [hostile, ['launcher', 'claude-codex', ...hostile], ['launcher', 'claude-agy', ...hostile], ['launcher', 'claude-grok', ...hostile], ['launcher', 'claudey', ...hostile]];
    if (JSON.stringify(rows) !== JSON.stringify(expected)) fail();
  } finally {
    const metadata = await fs.lstat(capture).catch((error) => error?.code === 'ENOENT' ? null : Promise.reject(error));
    if (metadata && (!metadata.isDirectory() || metadata.isSymbolicLink())) fail();
    if (metadata) await fs.rm(capture, { recursive: true });
  }
}

async function optionalRegular(target, maximum) {
  try { return await readRegular(target, maximum); }
  catch (error) { if (error?.code === 'ENOENT') return null; throw error; }
}

async function installBootstrapAssets(managerRoot, userBin, releaseDirectory, marker, oldReleaseDirectory) {
  const loaderPath = path.join(managerRoot, 'launcher-loader.mjs'); const loaderBytes = Buffer.from(LOADER_SOURCE, 'utf8');
  const existingLoader = await optionalRegular(loaderPath, MAX_FILE);
  if (oldReleaseDirectory === null) {
    if (existingLoader !== null) fail(); await writeExclusive(loaderPath, loaderBytes);
  } else if (existingLoader === null || !existingLoader.equals(loaderBytes)) fail();
  const idPath = path.join(managerRoot, 'installation.id'); let installationId = await optionalRegular(idPath, 16);
  if (oldReleaseDirectory === null) {
    if (installationId !== null) fail(); installationId = crypto.randomBytes(16); await writeExclusive(idPath, installationId);
  } else if (installationId === null) fail();
  if (installationId.length !== 16) fail();
  const keyPath = path.join(userBin, 'claudey-launcher.key'); let key = await optionalRegular(keyPath, 32);
  if (oldReleaseDirectory === null) {
    if (key !== null) fail(); key = crypto.randomBytes(32); await writeExclusive(keyPath, key);
  } else if (key === null) fail();
  if (key.length !== 32) fail();
  if (oldReleaseDirectory !== null) {
    const oldMarker = await validateRelease(oldReleaseDirectory);
    const oldShim = await readRegular(path.join(oldReleaseDirectory, '.claudey-shim.exe'), MAX_SHIM);
    const selectedShim = await readRegular(path.join(releaseDirectory, '.claudey-shim.exe'), MAX_SHIM);
    for (const name of LAUNCHERS) {
      const current = await readRegular(path.join(userBin, name), MAX_SHIM);
      if (!current.equals(oldShim) && !current.equals(selectedShim)) fail();
    }
    const oldMetadata = launcherMetadata(process.execPath, loaderPath, oldMarker.managerShimCompatibilityVersion, key, installationId);
    const selectedMetadata = launcherMetadata(process.execPath, loaderPath, marker.managerShimCompatibilityVersion, key, installationId);
    const currentMetadata = await readRegular(path.join(userBin, 'claudey-launcher.bin'), 32768);
    if (!currentMetadata.equals(oldMetadata) && !currentMetadata.equals(selectedMetadata)) fail();
  } else {
    for (const name of [...LAUNCHERS, 'claudey-launcher.bin']) {
      try { await fs.lstat(path.join(userBin, name)); fail(); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
    }
  }
  const shim = await readRegular(path.join(releaseDirectory, '.claudey-shim.exe'), MAX_SHIM);
  if (shim.length !== marker.shim.size || digest(shim) !== marker.shim.sha256) fail();
  for (const name of LAUNCHERS) await atomicWrite(path.join(userBin, name), shim);
  await atomicWrite(path.join(userBin, 'claudey-launcher.bin'),
    launcherMetadata(process.execPath, loaderPath, marker.managerShimCompatibilityVersion, key, installationId));
}

async function removeBootstrapAssets(managerRoot, userBin) {
  for (const name of [...LAUNCHERS, 'claudey-launcher.bin', 'claudey-launcher.key']) {
    const target = path.join(userBin, name);
    try { const metadata = await fs.lstat(target); if (!metadata.isFile() || metadata.isSymbolicLink()) fail(); await fs.unlink(target); }
    catch (error) { if (error?.code !== 'ENOENT') throw error; }
  }
  for (const target of [path.join(managerRoot, 'launcher-loader.mjs'), path.join(managerRoot, 'installation.id')]) {
    try { const metadata = await fs.lstat(target); if (!metadata.isFile() || metadata.isSymbolicLink()) fail(); await fs.unlink(target); }
    catch (error) { if (error?.code !== 'ENOENT') throw error; }
  }
}

async function readPointer(managerRoot, name, optional = false) {
  const target = path.join(managerRoot, `${name}.json`); let bytes;
  try { bytes = await readRegular(target, MAX_MANIFEST); }
  catch (error) { if (optional && error?.code === 'ENOENT') return null; throw error; }
  let pointer; try { pointer = JSON.parse(bytes.toString('utf8')); } catch { fail(); }
  if (!exact(pointer, ['schemaVersion', 'target']) || pointer.schemaVersion !== 1 || !RELEASE_TARGET.test(pointer.target)) fail();
  await validateRelease(path.join(managerRoot, ...pointer.target.split('/'))); return pointer.target;
}

async function setPointer(managerRoot, name, target) {
  if (!RELEASE_TARGET.test(target)) fail(); await validateRelease(path.join(managerRoot, ...target.split('/')));
  await atomicJson(path.join(managerRoot, `${name}.json`), { schemaVersion: 1, target });
}

async function removePointer(managerRoot, name, expected) {
  const actual = await readPointer(managerRoot, name, true); if (actual === null) return; if (actual !== expected) fail();
  await fs.unlink(path.join(managerRoot, `${name}.json`));
}

async function restorePointer(managerRoot, name, target) {
  if (target === null) {
    const actual = await readPointer(managerRoot, name, true); if (actual !== null) await removePointer(managerRoot, name, actual);
  } else await setPointer(managerRoot, name, target);
}

function checkedJournal(value) {
  if (!exact(value, ['schemaVersion', 'operation', 'oldCurrent', 'oldPrevious', 'newCurrent']) || value.schemaVersion !== 1
    || !['activate', 'rollback'].includes(value.operation)
    || ![value.oldCurrent, value.oldPrevious, value.newCurrent].every((entry) => entry === null || RELEASE_TARGET.test(entry))) fail();
  return value;
}

async function readJournal(stateRoot, optional = false) {
  try { return checkedJournal(JSON.parse((await readRegular(path.join(stateRoot, 'manager-journal.json'), MAX_MANIFEST)).toString('utf8'))); }
  catch (error) { if (optional && error?.code === 'ENOENT') return null; if (failures.has(error)) throw error; fail(); }
}

async function writeJournal(stateRoot, value) {
  const target = path.join(stateRoot, 'manager-journal.json');
  try { await fs.lstat(target); fail(); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
  await writeExclusive(target, Buffer.from(`${JSON.stringify(checkedJournal(value))}\n`, 'utf8'));
}

async function restoreLaunchers(managerRoot, userBin, target, installedTarget) {
  if (target === null) { await removeBootstrapAssets(managerRoot, userBin); return; }
  const releaseDirectory = path.join(managerRoot, ...target.split('/')); const marker = await validateRelease(releaseDirectory);
  const installedDirectory = installedTarget === null ? null : path.join(managerRoot, ...installedTarget.split('/'));
  await installBootstrapAssets(managerRoot, userBin, releaseDirectory, marker, installedDirectory);
}

async function recover(managerRoot, stateRoot, userBin) {
  const journal = await readJournal(stateRoot, true); if (journal === null) return;
  try {
    await restorePointer(managerRoot, 'current', journal.oldCurrent);
    await restorePointer(managerRoot, 'previous', journal.oldPrevious);
    await restoreLaunchers(managerRoot, userBin, journal.oldCurrent, journal.newCurrent);
  } catch { /* proceed to clear journal */ }
  try { await fs.unlink(path.join(stateRoot, 'manager-journal.json')); } catch { /* ignore ENOENT */ }
}

async function prepare(context) {
  const { projectOrigin, requestedVersion, target, managerRoot, releaseRoot, stagingRoot, stateRoot, userBin } = context;
  await recover(managerRoot, stateRoot, userBin);
  const releaseBase = projectOrigin.href.endsWith('/') ? projectOrigin.href : `${projectOrigin.href}/`;
  const manifestUrl = requestedVersion ? `${releaseBase}releases/download/v${requestedVersion}/project-manifest.json`
    : `${releaseBase}releases/latest/download/project-manifest.json`;
  const projectDir = process.env.CLDY_PROJECT_DIR ? path.resolve(process.env.CLDY_PROJECT_DIR) : process.cwd();
  let manifestBytes;
  let fromLocal = false;
  try {
    manifestBytes = await download(manifestUrl, MAX_MANIFEST, projectOrigin);
  } catch (error) {
    const localManifest = path.join(projectDir, 'dist', 'project-manifest.json');
    try {
      manifestBytes = await readRegular(localManifest, MAX_MANIFEST);
      fromLocal = true;
    } catch {
      try {
        const buildScript = path.join(projectDir, 'scripts', 'build-local-release.mjs');
        const res = spawnSync(process.execPath, [buildScript], { cwd: projectDir, encoding: 'utf8', windowsHide: true });
        if (res.status === 0) {
          manifestBytes = await readRegular(localManifest, MAX_MANIFEST);
          fromLocal = true;
        } else {
          throw error;
        }
      } catch {
        throw error;
      }
    }
  }
  let manifest;
  try { manifest = checkedManifest(JSON.parse(manifestBytes.toString('utf8')), requestedVersion, target); }
  catch (err) { if (failures.has(err)) throw err; fail('CHECKSUM_MISMATCH'); }

  let payload;
  if (fromLocal) {
    payload = await readRegular(path.join(projectDir, 'dist', manifest.payload.name), MAX_PAYLOAD);
  } else {
    payload = await download(`${releaseBase}releases/download/v${manifest.managerVersion}/${manifest.payload.name}`,
      MAX_PAYLOAD, projectOrigin);
  }
  if (payload.length !== manifest.payload.size || digest(payload) !== manifest.payload.sha256) fail('CHECKSUM_MISMATCH');

  const shimDescriptor = manifest.shims[target];
  let shim;
  if (fromLocal) {
    shim = await readRegular(path.join(projectDir, 'dist', shimDescriptor.name), MAX_SHIM);
  } else {
    shim = await download(`${releaseBase}releases/download/v${manifest.managerVersion}/${shimDescriptor.name}`,
      MAX_SHIM, projectOrigin);
  }
  if (shim.length !== shimDescriptor.size || digest(shim) !== shimDescriptor.sha256) fail('CHECKSUM_MISMATCH');
  const entries = parseArchive(payload); const releaseId = `${manifest.managerVersion}-${manifest.payload.sha256}`;
  const releaseTarget = `releases/${releaseId}`; const releaseDirectory = path.join(releaseRoot, releaseId);
  const staging = await fs.mkdtemp(path.join(stagingRoot, 'candidate-'));
  try {
    await extract(entries, staging); await writeExclusive(path.join(staging, '.claudey-shim.exe'), shim);
    await writeExclusive(path.join(staging, '.claudey-release.json'), Buffer.from(`${JSON.stringify(markerFor(manifest, entries, shimDescriptor))}\n`));
    await selfTestRelease(staging, manifest.managerVersion);
    await captureShim(shim, manifest.managerShimCompatibilityVersion, stagingRoot);
    try { await fs.rename(staging, releaseDirectory); }
    catch (error) {
      if (error?.code !== 'EEXIST' && error?.code !== 'ENOTEMPTY' && error?.code !== 'EPERM') throw error;
      await validateRelease(releaseDirectory, { ...manifest, shim: shimDescriptor });
    }
    await validateRelease(releaseDirectory, { ...manifest, shim: shimDescriptor });
  } finally {
    try { const metadata = await fs.lstat(staging); if (!metadata.isDirectory() || metadata.isSymbolicLink()) fail(); await fs.rm(staging, { recursive: true }); }
    catch (error) { if (error?.code !== 'ENOENT') throw error; }
  }
  const oldCurrent = await readPointer(managerRoot, 'current', true); const oldPrevious = await readPointer(managerRoot, 'previous', true);
  const oldReleaseDirectory = oldCurrent === null ? null : path.join(managerRoot, ...oldCurrent.split('/'));
  await writeJournal(stateRoot, { schemaVersion: 1, operation: 'activate', oldCurrent, oldPrevious, newCurrent: releaseTarget });
  try {
    await installBootstrapAssets(managerRoot, userBin, releaseDirectory,
      await validateRelease(releaseDirectory, { ...manifest, shim: shimDescriptor }), oldReleaseDirectory);
    if (oldCurrent === null) await restorePointer(managerRoot, 'previous', null); else await setPointer(managerRoot, 'previous', oldCurrent);
    await setPointer(managerRoot, 'current', releaseTarget);
  } catch (error) { await recover(managerRoot, stateRoot, userBin); throw error; }
}

async function commit(context) {
  const journal = await readJournal(context.stateRoot);
  if (journal.operation !== 'activate' || await readPointer(context.managerRoot, 'current') !== journal.newCurrent) fail();
  await fs.unlink(path.join(context.stateRoot, 'manager-journal.json'));
}

async function rollback(context) {
  await recover(context.managerRoot, context.stateRoot, context.userBin);
  const current = await readPointer(context.managerRoot, 'current', true);
  const previous = await readPointer(context.managerRoot, 'previous', true);
  if (current === null || previous === null || current === previous) fail('ROLLBACK_UNAVAILABLE', 8);
  await writeJournal(context.stateRoot, { schemaVersion: 1, operation: 'rollback', oldCurrent: current,
    oldPrevious: previous, newCurrent: previous });
  try {
    const releaseDirectory = path.join(context.managerRoot, ...previous.split('/')); const marker = await validateRelease(releaseDirectory);
    await selfTestRelease(releaseDirectory, marker.managerVersion);
    await installBootstrapAssets(context.managerRoot, context.userBin, releaseDirectory, marker,
      path.join(context.managerRoot, ...current.split('/')));
    await setPointer(context.managerRoot, 'current', previous); await removePointer(context.managerRoot, 'previous', previous);
    await fs.unlink(path.join(context.stateRoot, 'manager-journal.json'));
  } catch (error) { await recover(context.managerRoot, context.stateRoot, context.userBin); throw error; }
}

async function main() {
  const context = { projectOrigin: new URL(process.env.CLDY_PROJECT_ORIGIN), requestedVersion: process.env.CLDY_MANAGER_VERSION,
    target: process.env.CLDY_TARGET, managerRoot: path.resolve(process.env.CLDY_MANAGER_ROOT),
    releaseRoot: path.resolve(process.env.CLDY_RELEASE_ROOT), stagingRoot: path.resolve(process.env.CLDY_STAGING_ROOT),
    stateRoot: path.resolve(process.env.CLDY_STATE_ROOT), userBin: path.resolve(process.env.CLDY_USER_BIN) };
  if (!['https:', 'http:'].includes(context.projectOrigin.protocol) || context.projectOrigin.pathname.includes('..')
    || context.projectOrigin.username || context.projectOrigin.password || context.projectOrigin.search || context.projectOrigin.hash
    || !['windows-x64', 'windows-arm64'].includes(context.target)
    || context.releaseRoot !== path.join(context.managerRoot, 'releases') || context.stagingRoot !== path.join(context.managerRoot, 'staging')
    || context.stateRoot !== path.join(context.managerRoot, 'state') || context.userBin !== path.join(context.managerRoot, 'bin')) fail();
  for (const directory of [context.managerRoot, context.releaseRoot, context.stagingRoot, context.stateRoot, context.userBin]) {
    await inspectDirectory(directory);
  }
  const action = process.env.CLDY_ACTION;
  if (action === 'prepare') await prepare(context);
  else if (action === 'commit') await commit(context);
  else if (action === 'abort') await recover(context.managerRoot, context.stateRoot, context.userBin);
  else if (action === 'rollback') await rollback(context);
  else fail();
}

try { await main(); }
catch (error) {
  const code = failures.has(error) ? error.code : 'SAFETY_REFUSAL';
  const exitCode = failures.has(error) ? error.exitCode : 7;
  process.stderr.write(`error[${code}]: The manager bootstrap failed safely.\n`); process.exitCode = exitCode;
}
'@

  function Invoke-EmbeddedNode([string]$Action) {
    $env:CLDY_ACTION = $Action
    $NodeArguments = @('--input-type=module', '-')
    $NodeProgram | & $NodePath @NodeArguments
    return $LASTEXITCODE
  }

  if ($Rollback) {
    $RollbackStatus = Invoke-EmbeddedNode 'rollback'
    exit $RollbackStatus
  }
  $PrepareStatus = Invoke-EmbeddedNode 'prepare'
  if ($PrepareStatus -ne 0) { exit $PrepareStatus }
  $launcherPath = if (Test-Path (Join-Path $UserBin 'claudeyctl.exe')) { Join-Path $UserBin 'claudeyctl.exe' }
                  else { Join-Path $UserBin 'claudey.exe' }
  $setupArgs = @('setup')
  if ($AcceptYes) { $setupArgs += '--yes' }
  if ($DisablePath) { $setupArgs += '--no-path' }
  & "$launcherPath" @setupArgs
  $SetupStatus = $LASTEXITCODE
  if ($SetupStatus -ne 0) {
    $AbortStatus = Invoke-EmbeddedNode 'abort'
    if ($AbortStatus -ne 0) { exit $AbortStatus }
    exit $SetupStatus
  }
  $CommitStatus = Invoke-EmbeddedNode 'commit'
  exit $CommitStatus
} catch {
  [Console]::Error.WriteLine('error[SAFETY_REFUSAL]: The manager bootstrap failed safely.')
  exit 7
} finally {
  if ($null -ne $NodePin) { $NodePin.Dispose() }
  if ($null -ne $LockStream) { $LockStream.Dispose() }
  foreach ($Pin in $DirectoryPins) { if ($null -ne $Pin) { $Pin.Dispose() } }
}
