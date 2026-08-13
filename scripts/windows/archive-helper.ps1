param(
    [Parameter(Mandatory = $true)][string]$RequestPath,
    [Parameter(Mandatory = $true)][string]$ExpectedRequestSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedDestinationVolume,
    [Parameter(Mandatory = $true)][string]$ExpectedDestinationFileId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$request = $null
$requestStream = $null
$archiveStream = $null
$zip = $null
$destinationIdentity = $null
$invariant = [Globalization.CultureInfo]::InvariantCulture
[Threading.Thread]::CurrentThread.CurrentCulture = $invariant
[Threading.Thread]::CurrentThread.CurrentUICulture = $invariant
$utf8 = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8

if (-not ('ClaudexArchiveNativeIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public sealed class ClaudexArchiveDirectoryIdentity : IDisposable {
    public readonly SafeFileHandle Handle;
    public readonly uint VolumeSerialNumber;
    public readonly ulong FileId;
    public ClaudexArchiveDirectoryIdentity(SafeFileHandle handle, uint volume, ulong fileId) {
        Handle = handle; VolumeSerialNumber = volume; FileId = fileId;
    }
    public void Dispose() { Handle.Dispose(); }
}

public static class ClaudexArchiveNativeIdentity {
    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, FileShare share, IntPtr security, FileMode mode, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out BY_HANDLE_FILE_INFORMATION info);
    public static ClaudexArchiveDirectoryIdentity OpenDirectory(string path) {
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        SafeFileHandle handle = CreateFileW(path, 0, FileShare.Read | FileShare.Write, IntPtr.Zero, FileMode.Open, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (handle.IsInvalid) throw new IOException("Directory identity open failed.", new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
        BY_HANDLE_FILE_INFORMATION info;
        if (!GetFileInformationByHandle(handle, out info)) {
            int code = Marshal.GetLastWin32Error(); handle.Dispose();
            throw new IOException("Directory identity query failed.", new System.ComponentModel.Win32Exception(code));
        }
        if ((info.FileAttributes & 0x400) != 0) { handle.Dispose(); throw new IOException("Directory is a reparse point."); }
        ulong fileId = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
        return new ClaudexArchiveDirectoryIdentity(handle, info.VolumeSerialNumber, fileId);
    }
}
'@
}
function Write-Response([object]$Value, [int]$ExitCode) {
    [Console]::Out.Write(($Value | ConvertTo-Json -Compress -Depth 8))
    [Console]::Out.Flush()
    exit $ExitCode
}

function Fail([string]$RequestId, [string]$Code) {
    Write-Response ([ordered]@{ ok = $false; schemaVersion = 1; requestId = $RequestId; code = $Code; message = 'Archive extraction was refused.' }) 1
}

function Assert-ExactProperties([object]$Value, [string[]]$Required) {
    $names = @($Value.PSObject.Properties.Name)
    if ($names.Count -ne $Required.Count -or @($names | Where-Object { $_ -notin $Required }).Count -ne 0) { throw 'Schema.' }
}

function Assert-NoReparse([string]$LiteralPath) {
    if ([string]::IsNullOrWhiteSpace($LiteralPath) -or $LiteralPath -match '[\x00\r\n]' -or -not [IO.Path]::IsPathRooted($LiteralPath)) { throw 'Path.' }
    $full = [IO.Path]::GetFullPath($LiteralPath)
    $root = [IO.Path]::GetPathRoot($full)
    $current = $root
    foreach ($segment in @($full.Substring($root.Length).TrimStart('\') -split '\\' | Where-Object { $_ })) {
        $current = Join-Path $current $segment
        if (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse.' }
    }
    return $full
}

function Assert-PrivateRequest([string]$LiteralPath) {
    $safe = Assert-NoReparse $LiteralPath
    $item = Get-Item -LiteralPath $safe -Force
    if ($item.PSIsContainer -or $item.Length -gt 2097152) { throw 'Request.' }
    $acl = Get-Acl -LiteralPath $safe
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($ownerSid -ne $currentSid -or -not $acl.AreAccessRulesProtected -or $rules.Count -ne 2) { throw 'ACL.' }
    $allowed = @($currentSid, 'S-1-5-18')
    foreach ($rule in $rules) {
        if ($rule.IsInherited -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.IdentityReference.Value -notin $allowed -or
            ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { throw 'ACL.' }
    }
    return $safe
}

function Relative-Forward([string]$Root, [string]$Target) {
    $prefix = $Root.TrimEnd('\') + '\'
    if (-not $Target.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Escape.' }
    return $Target.Substring($prefix.Length).Replace('\', '/')
}
function Get-DirectoryIdentity([string]$LiteralPath) {
    $safe = Assert-NoReparse $LiteralPath
    $item = Get-Item -LiteralPath $safe -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Destination.' }
    $native = [ClaudexArchiveNativeIdentity]::OpenDirectory($safe)
    return [pscustomobject]@{ path = $item.FullName; volume = $native.VolumeSerialNumber; fileId = $native.FileId; native = $native }
}

function Assert-DirectoryIdentity([string]$LiteralPath, [object]$Identity) {
    if ($null -eq $Identity -or $Identity.native.Handle.IsInvalid -or $Identity.native.Handle.IsClosed) { throw 'Destination identity.' }
    $current = Get-DirectoryIdentity $LiteralPath
    try {
        if ($current.path -ne $Identity.path -or $current.volume -ne $Identity.volume -or $current.fileId -ne $Identity.fileId) { throw 'Destination identity.' }
        return $current.path
    } finally { $current.native.Dispose() }
}

try {
    $safeRequest = Assert-PrivateRequest $RequestPath
    if ($ExpectedRequestSha256 -notmatch '^[a-f0-9]{64}$') { throw 'Request digest.' }
    $requestStream = [IO.File]::Open($safeRequest, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    [void](Assert-PrivateRequest $safeRequest)
    $requestSha = [Security.Cryptography.SHA256]::Create()
    try {
        $actualRequestSha256 = ([BitConverter]::ToString($requestSha.ComputeHash($requestStream))).Replace('-', '').ToLowerInvariant()
    } finally { $requestSha.Dispose() }
    if ($actualRequestSha256 -ne $ExpectedRequestSha256) { throw 'Request digest.' }
    $requestStream.Position = 0
    $reader = [IO.StreamReader]::new($requestStream, $utf8, $false, 4096, $true)
    try { $raw = $reader.ReadToEnd() } finally { $reader.Dispose() }
    $request = $raw | ConvertFrom-Json
    Assert-ExactProperties $request @('schemaVersion', 'requestId', 'operation', 'archivePath', 'destination', 'archiveSha256', 'entries')
    if ($request.schemaVersion -ne 1 -or
        $request.requestId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$' -or
        $request.operation -ne 'extractZip' -or $request.archiveSha256 -notmatch '^[a-f0-9]{64}$' -or @($request.entries).Count -gt 2048) { throw 'Request.' }
    $archive = Assert-NoReparse ([string]$request.archivePath)
    $destination = Assert-NoReparse ([string]$request.destination)
    if ($ExpectedDestinationVolume -notmatch '^(0|[1-9][0-9]*)$' -or $ExpectedDestinationFileId -notmatch '^(0|[1-9][0-9]*)$') { throw 'Destination identity.' }
    $destinationIdentity = Get-DirectoryIdentity $destination
    if ([string]$destinationIdentity.volume -ne $ExpectedDestinationVolume -or [string]$destinationIdentity.fileId -ne $ExpectedDestinationFileId) { throw 'Destination identity.' }
    if (@((Get-Item -LiteralPath $destination -Force).EnumerateFileSystemInfos()).Count -ne 0) { throw 'Destination.' }
    $archiveStream = [IO.File]::Open($archive, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $archiveHash = ([BitConverter]::ToString($sha.ComputeHash($archiveStream))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
    if ($archiveHash -ne $request.archiveSha256) { throw 'Digest.' }
    $archiveStream.Position = 0
    [void](Assert-DirectoryIdentity $destination $destinationIdentity)
    foreach ($entry in @($request.entries)) {
        Assert-ExactProperties $entry @('path', 'type', 'size', 'sha256')
        if ($entry.path -notmatch '^[^\x00-\x1f\\/:]+(?:/[^\x00-\x1f\\/:]+)*$' -or
            $entry.type -notin @('file', 'directory') -or
            $entry.size -lt 0 -or $entry.size -gt 268435456 -or
            ($entry.type -eq 'file' -and $entry.sha256 -notmatch '^[a-f0-9]{64}$') -or
            ($entry.type -eq 'directory' -and $null -ne $entry.sha256)) { throw 'Entry.' }
    }
    Add-Type -AssemblyName System.IO.Compression
    $zip = [IO.Compression.ZipArchive]::new($archiveStream, [IO.Compression.ZipArchiveMode]::Read, $true)
    $zipEntries = @{}
    foreach ($zipEntry in @($zip.Entries)) {
        $zipPath = $zipEntry.FullName.Replace('\', '/').TrimEnd('/')
        if ([string]::IsNullOrWhiteSpace($zipPath) -or $zipEntries.ContainsKey($zipPath)) { throw 'ZIP entries.' }
        $zipEntries[$zipPath] = $zipEntry
    }
    foreach ($planned in @($request.entries | Sort-Object path)) {
        [void](Assert-DirectoryIdentity $destination $destinationIdentity)
        if (-not $zipEntries.ContainsKey($planned.path)) { throw 'ZIP entries.' }
        $zipEntry = $zipEntries[$planned.path]
        $target = [IO.Path]::GetFullPath((Join-Path $destination $planned.path.Replace('/', '\')))
        [void](Relative-Forward $destination $target)
        if ($planned.type -eq 'directory') {
            if ($zipEntry.Length -ne 0) { throw 'ZIP directory.' }
            [void][IO.Directory]::CreateDirectory($target)
        } else {
            $parent = [IO.Path]::GetDirectoryName($target)
            [void](Assert-NoReparse $parent)
            $inputStream = $zipEntry.Open()
            $outputStream = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $inputStream.CopyTo($outputStream)
                $outputStream.Flush($true)
            } finally {
                $outputStream.Dispose()
                $inputStream.Dispose()
            }
        }
        [void](Assert-DirectoryIdentity $destination $destinationIdentity)
        [void](Assert-NoReparse $target)
    }
    $zip.Dispose()
    $archiveStream.Dispose()
    [void](Assert-DirectoryIdentity $destination $destinationIdentity)
    $actual = @()
    $expanded = [long]0
    foreach ($item in @(Get-ChildItem -LiteralPath $destination -Recurse -Force | Sort-Object FullName)) {
        [void](Assert-NoReparse $item.FullName)
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse.' }
        $relative = Relative-Forward $destination $item.FullName
        if ($item.PSIsContainer) {
            $actual += [pscustomobject][ordered]@{ path = $relative; type = 'directory'; size = 0; sha256 = $null }
        } else {
            $itemLength = [long]$item.Length
            if ($itemLength -lt 0 -or $expanded -gt (536870912 - $itemLength)) { throw 'Expanded.' }
            $expanded += $itemLength
            if ($expanded -gt 536870912) { throw 'Expanded.' }
            $actual += [pscustomobject][ordered]@{ path = $relative; type = 'file'; size = [long]$item.Length; sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
        }
    }
    $actual = @($actual | Sort-Object path)
    $expectedJson = @($request.entries | Sort-Object path) | ConvertTo-Json -Compress -Depth 5
    $actualJson = $actual | ConvertTo-Json -Compress -Depth 5
    if ($expectedJson -ne $actualJson) { throw 'Mismatch.' }
    [void](Assert-DirectoryIdentity $destination $destinationIdentity)
    $requestStream.Dispose()
    $requestStream = $null
    $destinationIdentity.native.Dispose()
    $destinationIdentity = $null
    Write-Response ([ordered]@{
        ok = $true; schemaVersion = 1; requestId = $request.requestId
        result = [ordered]@{ canonicalDestination = $destination; entryCount = $actual.Count; expandedBytes = $expanded; entries = $actual }
    }) 0
} catch {
    if ($null -ne $destinationIdentity) { $destinationIdentity.native.Dispose() }
    if ($null -ne $requestStream) { $requestStream.Dispose() }
    if ($null -ne $zip) { $zip.Dispose() }
    if ($null -ne $archiveStream) { $archiveStream.Dispose() }
    $requestId = if ($null -ne $request -and $null -ne $request.requestId) { [string]$request.requestId } else { '' }
    Fail $requestId 'SAFETY_REFUSAL'
}
