[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('x64', 'arm64')]
  [string]$Architecture,
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^(?:[0-9a-f]{40}|[0-9a-f]{64})$')]
  [string]$SourceRevision,
  [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
  [Parameter(Mandatory = $true)]
  [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$cmake = (Get-Command 'cmake.exe' -CommandType Application -ErrorAction Stop).Source
$source = [IO.Path]::GetFullPath((Join-Path $SourceRoot 'native\windows-shim'))
$output = [IO.Path]::GetFullPath($OutputDirectory)
$build = [IO.Path]::GetFullPath((Join-Path $output "build-$Architecture"))
$generatorArchitecture = if ($Architecture -eq 'x64') { 'x64' } else { 'ARM64' }
$artifactName = "claudex-windows-${Architecture}.exe"
$artifact = Join-Path $output $artifactName
$compilerFlags = @('/W4', '/WX', '/O2', '/guard:cf', '/sdl', '/DYNAMICBASE', '/NXCOMPAT')

[IO.Directory]::CreateDirectory($output) | Out-Null
[IO.Directory]::CreateDirectory($build) | Out-Null
& $cmake '-S' $source '-B' $build '-A' $generatorArchitecture
if ($LASTEXITCODE -ne 0) { throw 'CMake configure failed.' }
& $cmake '--build' $build '--config' 'Release' '--target' 'claudex-shim' 'capture-child'
if ($LASTEXITCODE -ne 0) { throw 'CMake build failed.' }

$candidate = Join-Path $build 'Release\claudex-shim.exe'
$captureChild = Join-Path $build 'Release\capture-child.exe'
if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw 'The shim artifact is absent.' }
if (-not (Test-Path -LiteralPath $captureChild -PathType Leaf)) { throw 'The capture child is absent.' }
Copy-Item -LiteralPath $candidate -Destination $artifact -Force
$file = Get-Item -LiteralPath $artifact
$digest = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
$cl = (Get-Command 'cl.exe' -CommandType Application -ErrorAction Stop).Source
$compilerVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($cl).FileVersion
$descriptor = [ordered]@{
  schemaVersion = 1
  target = "windows-${Architecture}"
  sourceRevision = $SourceRevision
  name = $artifactName
  sha256 = $digest
  size = [int64]$file.Length
  managerShimCompatibilityVersion = 1
  compiler = [ordered]@{ name = 'MSVC'; version = $compilerVersion; flags = $compilerFlags }
}
$descriptorPath = Join-Path $output "$artifactName.json"
[IO.File]::WriteAllText($descriptorPath, (($descriptor | ConvertTo-Json -Depth 5 -Compress) + "`n"), [Text.UTF8Encoding]::new($false))

$captureRoot = Join-Path $output "capture-$Architecture"
[IO.Directory]::CreateDirectory($captureRoot) | Out-Null
$captureLauncher = Join-Path $captureRoot 'claudexctl.exe'
Copy-Item -LiteralPath $candidate -Destination $captureLauncher -Force
$managerPath = [IO.Path]::GetFullPath((Join-Path $SourceRoot 'bin\claudexctl.js'))
$nodeBytes = [Text.Encoding]::Unicode.GetBytes([IO.Path]::GetFullPath($captureChild))
$managerBytes = [Text.Encoding]::Unicode.GetBytes($managerPath)
$key = [byte[]](0..31)
$prefixStream = [IO.MemoryStream]::new()
$writer = [IO.BinaryWriter]::new($prefixStream, [Text.Encoding]::UTF8, $true)
$writer.Write([Text.Encoding]::ASCII.GetBytes('CLDXL001'))
$writer.Write([uint32]1)
$writer.Write([uint32]1)
$writer.Write([uint32]($nodeBytes.Length / 2))
$writer.Write([uint32]($managerBytes.Length / 2))
$writer.Write([byte[]]::new(16))
$writer.Flush()
$prefix = $prefixStream.ToArray()
$authenticated = [byte[]]::new($prefix.Length + $nodeBytes.Length + $managerBytes.Length)
[Array]::Copy($prefix, 0, $authenticated, 0, $prefix.Length)
[Array]::Copy($nodeBytes, 0, $authenticated, $prefix.Length, $nodeBytes.Length)
[Array]::Copy($managerBytes, 0, $authenticated, $prefix.Length + $nodeBytes.Length, $managerBytes.Length)
$hmac = [Security.Cryptography.HMACSHA256]::new($key)
$tag = $hmac.ComputeHash($authenticated)
$metadata = [byte[]]::new($prefix.Length + $tag.Length + $nodeBytes.Length + $managerBytes.Length)
[Array]::Copy($prefix, 0, $metadata, 0, $prefix.Length)
[Array]::Copy($tag, 0, $metadata, $prefix.Length, $tag.Length)
[Array]::Copy($nodeBytes, 0, $metadata, $prefix.Length + $tag.Length, $nodeBytes.Length)
[Array]::Copy($managerBytes, 0, $metadata, $prefix.Length + $tag.Length + $nodeBytes.Length, $managerBytes.Length)
[IO.File]::WriteAllBytes((Join-Path $captureRoot 'claudex-launcher.bin'), $metadata)
[IO.File]::WriteAllBytes((Join-Path $captureRoot 'claudex-launcher.key'), $key)
$node = (Get-Command 'node.exe' -CommandType Application -ErrorAction Stop).Source
& $node (Join-Path $SourceRoot 'scripts\windows-shim-capture.mjs') $captureLauncher $managerPath
if ($LASTEXITCODE -ne 0) { throw 'Native launcher capture proof failed.' }
