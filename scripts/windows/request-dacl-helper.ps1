param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][ValidateSet('file', 'directory')][string]$ExpectedType,
    [Parameter(Mandatory = $true)][string]$CurrentUserSid,
    [Parameter(Mandatory = $true)][string]$RequestId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$invariantCulture = [System.Globalization.CultureInfo]::InvariantCulture
[System.Threading.Thread]::CurrentThread.CurrentCulture = $invariantCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $invariantCulture
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom

function Write-Response([object]$Response, [int]$ExitCode) {
    [Console]::Out.Write(($Response | ConvertTo-Json -Compress -Depth 6))
    [Console]::Out.Flush()
    exit $ExitCode
}

function Fail() {
    Write-Response ([ordered]@{ ok = $false; schemaVersion = 1; requestId = $RequestId; code = 'SAFETY_REFUSAL'; message = 'Private request DACL verification failed.' }) 1
}

function Assert-NoReparsePath([string]$LiteralPath) {
    if ([string]::IsNullOrWhiteSpace($LiteralPath) -or $LiteralPath -match '[\x00\r\n]' -or -not [IO.Path]::IsPathRooted($LiteralPath)) { throw 'Unsafe path.' }
    $fullPath = [IO.Path]::GetFullPath($LiteralPath)
    $root = [IO.Path]::GetPathRoot($fullPath)
    $relative = $fullPath.Substring($root.Length).TrimStart('\')
    $current = $root
    foreach ($segment in @($relative -split '\\' | Where-Object { $_ })) {
        $current = Join-Path -Path $current -ChildPath $segment
        $attributes = [IO.File]::GetAttributes($current)
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point.' }
    }
    return $fullPath
}

try {
    if ($RequestId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$') { throw 'Invalid request identity.' }
    if ($CurrentUserSid -notmatch '^S-1-\d+(?:-\d+)+$') { throw 'Invalid SID.' }
    $actualCurrentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($CurrentUserSid -ne $actualCurrentUserSid) { throw 'Unexpected SID.' }
    $safePath = Assert-NoReparsePath $Path
    $item = Get-Item -LiteralPath $safePath -Force
    $type = if ($item.PSIsContainer) { 'directory' } else { 'file' }
    if ($type -ne $ExpectedType) { throw 'Unexpected type.' }
    [void](Assert-NoReparsePath $safePath)
    $acl = Get-Acl -LiteralPath $safePath
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    $aces = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
        [ordered]@{
            type = if ($_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) { 'allow' } else { 'deny' }
            sid = $_.IdentityReference.Value
            rights = if (($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq [System.Security.AccessControl.FileSystemRights]::FullControl) { 'full-control' } else { 'other' }
            inherited = [bool]$_.IsInherited
        }
    })
    $result = [ordered]@{ canonicalPath = $item.FullName; type = $type; isReparsePoint = $false; ownerSid = $owner; daclProtected = [bool]$acl.AreAccessRulesProtected; aces = $aces }
    Write-Response ([ordered]@{ ok = $true; schemaVersion = 1; requestId = $RequestId; result = $result }) 0
} catch {
    Fail
}