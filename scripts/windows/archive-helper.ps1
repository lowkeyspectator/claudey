param(
    [Parameter(Mandatory = $true)][string]$RequestPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$request = $null
$invariant = [Globalization.CultureInfo]::InvariantCulture
[Threading.Thread]::CurrentThread.CurrentCulture = $invariant
[Threading.Thread]::CurrentThread.CurrentUICulture = $invariant
$utf8 = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8

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

try {
    $safeRequest = Assert-PrivateRequest $RequestPath
    $raw = [IO.File]::ReadAllText($safeRequest, $utf8)
    $request = $raw | ConvertFrom-Json
    Assert-ExactProperties $request @('schemaVersion', 'requestId', 'operation', 'archivePath', 'destination', 'archiveSha256', 'entries')
    if ($request.schemaVersion -ne 1 -or
        $request.requestId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$' -or
        $request.operation -ne 'extractZip' -or $request.archiveSha256 -notmatch '^[a-f0-9]{64}$' -or @($request.entries).Count -gt 2048) { throw 'Request.' }
    $archive = Assert-NoReparse ([string]$request.archivePath)
    $destination = Assert-NoReparse ([string]$request.destination)
    $destinationItem = Get-Item -LiteralPath $destination -Force
    if (-not $destinationItem.PSIsContainer -or
        @($destinationItem.EnumerateFileSystemInfos()).Count -ne 0 -or
        ($destinationItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Destination.' }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $request.archiveSha256) { throw 'Digest.' }
    foreach ($entry in @($request.entries)) {
        Assert-ExactProperties $entry @('path', 'type', 'size', 'sha256')
        if ($entry.path -notmatch '^[^\x00-\x1f\\/:]+(?:/[^\x00-\x1f\\/:]+)*$' -or
            $entry.type -notin @('file', 'directory') -or
            $entry.size -lt 0 -or $entry.size -gt 268435456 -or
            ($entry.type -eq 'file' -and $entry.sha256 -notmatch '^[a-f0-9]{64}$') -or
            ($entry.type -eq 'directory' -and $null -ne $entry.sha256)) { throw 'Entry.' }
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($archive, $destination)
    [void](Assert-NoReparse $destination)
    $actual = @()
    $expanded = [long]0
    foreach ($item in @(Get-ChildItem -LiteralPath $destination -Recurse -Force | Sort-Object FullName)) {
        [void](Assert-NoReparse $item.FullName)
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse.' }
        $relative = Relative-Forward $destination $item.FullName
        if ($item.PSIsContainer) {
            $actual += [ordered]@{ path = $relative; type = 'directory'; size = 0; sha256 = $null }
        } else {
            $expanded = [Math]::AddChecked($expanded, [long]$item.Length)
            if ($expanded -gt 536870912) { throw 'Expanded.' }
            $actual += [ordered]@{ path = $relative; type = 'file'; size = [long]$item.Length; sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
        }
    }
    $actual = @($actual | Sort-Object path)
    $expectedJson = @($request.entries | Sort-Object path) | ConvertTo-Json -Compress -Depth 5
    $actualJson = $actual | ConvertTo-Json -Compress -Depth 5
    if ($expectedJson -ne $actualJson) { throw 'Mismatch.' }
    [void](Assert-NoReparse $destination)
    Write-Response ([ordered]@{
        ok = $true; schemaVersion = 1; requestId = $request.requestId
        result = [ordered]@{ canonicalDestination = $destination; entryCount = $actual.Count; expandedBytes = $expanded; entries = $actual }
    }) 0
} catch {
    $requestId = if ($null -ne $request -and $null -ne $request.requestId) { [string]$request.requestId } else { '' }
    Fail $requestId 'SAFETY_REFUSAL'
}
