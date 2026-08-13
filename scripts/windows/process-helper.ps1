param(
    [Parameter(Mandatory = $true)]
    [string]$RequestPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Write-Result([object]$Value, [int]$ExitCode) {
    $json = ConvertTo-Json -InputObject $Value -Compress -Depth 8
    [Console]::Out.Write($json)
    exit $ExitCode
}

function Fail([string]$RequestId, [string]$Message) {
    Write-Result ([ordered]@{ schemaVersion = 1; requestId = $RequestId; ok = $false; code = 'SAFETY_REFUSAL'; message = $Message }) 1
}

function Exact-Keys([object]$Value, [string[]]$Expected) {
    if ($null -eq $Value) { return $false }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    return ($actual.Count -eq $wanted.Count -and (Compare-Object $actual $wanted).Count -eq 0)
}

function Assert-No-Reparse([string]$Target) {
    $current = [System.IO.Path]::GetPathRoot($Target)
    $relative = $Target.Substring($current.Length).Split([System.IO.Path]::DirectorySeparatorChar)
    foreach ($segment in $relative) {
        if ([string]::IsNullOrEmpty($segment)) { continue }
        $current = [System.IO.Path]::Combine($current, $segment)
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse path refused.' }
    }
}

function Assert-PrivateAcl([string]$Target, [bool]$Directory, [string]$OwnerSid) {
    $acl = Get-Acl -LiteralPath $Target
    $actualOwnerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if (-not $acl.AreAccessRulesProtected -or $actualOwnerSid -ne $OwnerSid) { throw 'Unprotected request path refused.' }
    $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw 'Unexpected request ACL refused.' }
    $allowed = @($OwnerSid, 'S-1-5-18')
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -notin $allowed -or $rule.AccessControlType -ne 'Allow' -or $rule.IsInherited -or
            (($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne [System.Security.AccessControl.FileSystemRights]::FullControl)) {
            throw 'Unexpected request ACL refused.'
        }
        if ($Directory) {
            $required = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            if ($rule.InheritanceFlags -ne $required -or $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) { throw 'Unexpected request ACL flags refused.' }
        } elseif ($rule.InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None -or $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {
            throw 'Unexpected request file ACL flags refused.'
        }
    }
}

$requestId = ''
try {
    if ([string]::IsNullOrWhiteSpace($RequestPath) -or -not [System.IO.Path]::IsPathRooted($RequestPath) -or
        $RequestPath.IndexOfAny([char[]]@([char]0, [char]10, [char]13)) -ge 0) { throw 'Unsafe request path.' }
    $fullRequestPath = [System.IO.Path]::GetFullPath($RequestPath)
    if ($fullRequestPath -cne $RequestPath -or [System.IO.Path]::GetExtension($fullRequestPath) -cne '.json') { throw 'Unsafe request path.' }
    Assert-No-Reparse $fullRequestPath
    $ownerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Assert-PrivateAcl ([System.IO.Path]::GetDirectoryName($fullRequestPath)) $true $ownerSid
    Assert-PrivateAcl $fullRequestPath $false $ownerSid
    $stream = [System.IO.File]::Open($fullRequestPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 2 -or $stream.Length -gt 16384) { throw 'Request size refused.' }
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.UTF8Encoding]::new($false, $true), $true)
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
    $request = ConvertFrom-Json -InputObject $text
    if ($request.requestId -is [string]) { $requestId = $request.requestId }
    if ($request.schemaVersion -ne 1 -or $requestId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$' -or
        $request.pid -isnot [int] -or $request.pid -lt 1) { throw 'Invalid process request.' }
    if ($request.operation -eq 'signalProcess') {
        if (-not (Exact-Keys $request @('schemaVersion', 'requestId', 'operation', 'pid', 'force')) -or $request.force -isnot [bool]) { throw 'Invalid signal request.' }
    } elseif ($request.operation -in @('inspectProcess', 'listDescendants')) {
        if (-not (Exact-Keys $request @('schemaVersion', 'requestId', 'operation', 'pid'))) { throw 'Invalid inspect request.' }
    } else { throw 'Unknown process operation.' }

    if ($request.operation -eq 'inspectProcess') {
        $process = Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId = {0}" -f $request.pid)
        if ($null -eq $process -or @($process).Count -ne 1 -or [string]::IsNullOrWhiteSpace($process.ExecutablePath)) { throw 'Process identity unavailable.' }
        $started = if ($process.CreationDate -is [DateTime]) { $process.CreationDate } else { [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$process.CreationDate) }
        $identity = [ordered]@{
            pid = [int]$process.ProcessId
            parentPid = [int]$process.ParentProcessId
            processStartTime = $started.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
            executableCanonicalPath = [System.IO.Path]::GetFullPath([string]$process.ExecutablePath)
        }
        Write-Result ([ordered]@{ schemaVersion = 1; requestId = $requestId; ok = $true; result = $identity }) 0
    }

    if ($request.operation -eq 'listDescendants') {
        $all = @(Get-CimInstance -ClassName Win32_Process)
        $queue = [Collections.Generic.Queue[int]]::new()
        $queue.Enqueue([int]$request.pid)
        $found = @()
        while ($queue.Count -gt 0) {
            $parent = $queue.Dequeue()
            foreach ($child in @($all | Where-Object { [int]$_.ParentProcessId -eq $parent })) {
                if ([string]::IsNullOrWhiteSpace($child.ExecutablePath)) { throw 'Descendant identity unavailable.' }
                $started = if ($child.CreationDate -is [DateTime]) { $child.CreationDate } else { [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$child.CreationDate) }
                $found += [ordered]@{
                    pid = [int]$child.ProcessId; parentPid = [int]$child.ParentProcessId
                    processStartTime = $started.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
                    executableCanonicalPath = [System.IO.Path]::GetFullPath([string]$child.ExecutablePath)
                }
                $queue.Enqueue([int]$child.ProcessId)
            }
        }
        Write-Result ([ordered]@{ schemaVersion = 1; requestId = $requestId; ok = $true; result = [ordered]@{ rootPid = [int]$request.pid; complete = $true; processes = @($found) } }) 0
    }

    $taskkill = Join-Path ([Environment]::GetFolderPath('System')) 'taskkill.exe'
    $arguments = @('/PID', [string]$request.pid, '/T')
    if ($request.force) { $arguments += '/F' }
    $child = Start-Process -FilePath $taskkill -ArgumentList $arguments -NoNewWindow -Wait -PassThru
    $signal = [ordered]@{ pid = [int]$request.pid; force = [bool]$request.force; acknowledged = ($child.ExitCode -eq 0); exitCode = [int]$child.ExitCode }
    Write-Result ([ordered]@{ schemaVersion = 1; requestId = $requestId; ok = $true; result = $signal }) 0
} catch {
    Fail $requestId 'Process helper refused the request.'
}
