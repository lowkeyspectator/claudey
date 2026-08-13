param(
    [Parameter(Mandatory = $true)]
    [string]$RequestPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom

function Write-Response([object]$Response, [int]$ExitCode) {
    $json = $Response | ConvertTo-Json -Compress -Depth 6
    [Console]::Out.Write($json)
    [Console]::Out.Flush()
    exit $ExitCode
}

function Fail([string]$RequestId, [string]$Code, [string]$Message) {
    Write-Response ([ordered]@{ ok = $false; schemaVersion = 1; requestId = $RequestId; code = $Code; message = $Message }) 1
}

function Assert-NoReparsePath([string]$LiteralPath) {
    if ([string]::IsNullOrWhiteSpace($LiteralPath) -or $LiteralPath -match '[\x00\r\n]' -or -not [IO.Path]::IsPathRooted($LiteralPath)) { throw 'Unsafe path.' }
    $fullPath = [IO.Path]::GetFullPath($LiteralPath)
    $root = [IO.Path]::GetPathRoot($fullPath)
    $relative = $fullPath.Substring($root.Length).TrimStart('\\')
    $current = $root
    foreach ($segment in @($relative -split '\\' | Where-Object { $_ })) {
        $current = Join-Path -Path $current -ChildPath $segment
        $attributes = [IO.File]::GetAttributes($current)
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point.' }
    }
    return $fullPath
}

try {
    $safeRequestPath = Assert-NoReparsePath $RequestPath
    $raw = [IO.File]::ReadAllText($safeRequestPath, $utf8NoBom)
    $request = $raw | ConvertFrom-Json
    $required = @('schemaVersion', 'requestId', 'operation', 'path', 'expectedType', 'currentUserSid')
    $names = @($request.PSObject.Properties.Name)
    if ($names.Count -ne $required.Count -or @($names | Where-Object { $_ -notin $required }).Count -ne 0) { Fail '' 'SAFETY_REFUSAL' 'Windows helper request is invalid.' }
    if ($request.schemaVersion -ne 1 -or $request.requestId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$' -or $request.operation -notin @('inspect', 'protect') -or $request.expectedType -notin @('file', 'directory') -or $request.currentUserSid -notmatch '^S-1-\d+(?:-\d+)+$' -or $request.path -notmatch '^[A-Za-z]:\\' -or $request.path -match '[\x00\r\n]') { Fail $request.requestId 'SAFETY_REFUSAL' 'Windows helper request is invalid.' }
    $actualCurrentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($request.currentUserSid -ne $actualCurrentUserSid) { Fail $request.requestId 'SAFETY_REFUSAL' 'Windows helper request is invalid.' }
    $safeTargetPath = Assert-NoReparsePath $request.path
    $item = Get-Item -LiteralPath $safeTargetPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail $request.requestId 'SAFETY_REFUSAL' 'Managed path is not eligible for permission mutation.' }
    $type = if ($item.PSIsContainer) { 'directory' } else { 'file' }
    if ($type -ne $request.expectedType) { Fail $request.requestId 'SAFETY_REFUSAL' 'Managed path type does not match.' }
    if ($request.operation -eq 'protect') {
        [void](Assert-NoReparsePath $safeTargetPath)
        $acl = Get-Acl -LiteralPath $safeTargetPath
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleAll($rule) }
        foreach ($sidText in @($request.currentUserSid, 'S-1-5-18')) {
            $sid = [System.Security.Principal.SecurityIdentifier]::new($sidText)
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)
            [void]$acl.AddAccessRule($rule)
        }
        [void](Assert-NoReparsePath $safeTargetPath)
        Set-Acl -LiteralPath $safeTargetPath -AclObject $acl
    }
    [void](Assert-NoReparsePath $safeTargetPath)
    $acl = Get-Acl -LiteralPath $safeTargetPath
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    $aces = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
        [ordered]@{ type = if ($_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) { 'allow' } else { 'deny' }; sid = $_.IdentityReference.Value; rights = if (($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq [System.Security.AccessControl.FileSystemRights]::FullControl) { 'full-control' } else { 'other' }; inherited = [bool]$_.IsInherited }
    })
    $result = [ordered]@{ canonicalPath = $item.FullName; type = $type; isReparsePoint = $false; ownerSid = $owner; daclProtected = [bool]$acl.AreAccessRulesProtected; aces = $aces }
    Write-Response ([ordered]@{ ok = $true; schemaVersion = 1; requestId = $request.requestId; result = $result }) 0
} catch {
    $requestId = if ($request -and $request.requestId) { [string]$request.requestId } else { '' }
    Fail $requestId 'SAFETY_REFUSAL' 'Managed path is not eligible for permission mutation.'
}