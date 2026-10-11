param(
    [string]$TargetProfile,
    [string]$PublisherArtifact,
    [int]$HealthTimeoutSeconds = 90,
    [string]$RuntimeDirectory,
    [string]$DeploymentName = 'agentic-closure-engine',
    [ValidateRange(1024,65535)][int]$ConsolePort = 8782,
    [ValidateRange(1024,65535)][int]$PublisherPort = 8784
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$runtime = if ($RuntimeDirectory) { [IO.Path]::GetFullPath($RuntimeDirectory) } else { Join-Path $projectRoot '.runtime' }
function Enter-StartupLock {
    # One host-wide exclusive lock serialises every ACE start (any deployment name), so the
    # single-authority check and compose up cannot interleave with another start. The OS
    # releases the handle if this process dies, so a crashed start never leaves a stale lock.
    $lockPath = if ($env:ACE_START_LOCK) { $env:ACE_START_LOCK } else {
        Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'agentic-closure-engine\start.lock'
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $lockPath) -Force | Out-Null
    try {
        return [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    } catch [System.IO.IOException] {
        [Console]::Error.WriteLine("ACE_START_BUSY: another ACE startup holds the host startup lock ($lockPath). Retry after it finishes.")
        exit 75
    }
}
$startupLock = Enter-StartupLock
function Assert-SingleAuthority([string]$TrustPin) {
    # Labels cover current deployments; the custody fallback also covers installations predating labels.
    $matchingIds = @(& docker ps --filter "label=ace.trust_hash=$TrustPin" --format '{{.ID}}')
    foreach ($matchingId in $matchingIds) {
        if (-not $matchingId) { continue }
        $matching = (& docker inspect $matchingId | ConvertFrom-Json)[0]
        $otherProject = $matching.Config.Labels.'com.docker.compose.project'
        if ($otherProject -ne $DeploymentName) { throw "Another service with these signing identities is active: $otherProject." }
    }
    $custodyIds = @(& docker ps --filter label=com.docker.compose.service=custody --format '{{.ID}}')
    foreach ($containerId in $custodyIds) {
        if (-not $containerId) { continue }
        $metadata = (& docker inspect $containerId | ConvertFrom-Json)[0]
        $otherProject = $metadata.Config.Labels.'com.docker.compose.project'
        if ($otherProject -eq $DeploymentName) { continue }
        $otherPin = $metadata.Config.Labels.'ace.trust_hash'
        if (-not $otherPin -and $metadata.Config.Image -eq 'agentic-closure-engine:0.3.0') {
            $otherPin = (& docker exec $containerId python -I -c "from pathlib import Path; print(Path('/state/operator/trust.pin').read_text().strip())").Trim()
            if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect an existing ACE custody identity; startup refused.' }
        }
        if ($otherPin -eq $TrustPin) { throw "Another signing authority with this enrollment is active: $otherProject. Stop it before starting $DeploymentName." }
    }
}
try {
$existingPin = Join-Path $runtime 'trust.pin'
if (Test-Path -LiteralPath $existingPin) { Assert-SingleAuthority ((Get-Content -Raw -LiteralPath $existingPin).Trim()) }
New-Item -ItemType Directory -Path $runtime -Force | Out-Null
$profileCopy = Join-Path $runtime 'target-profile.json'
if ($TargetProfile) {
    $profileSource = (Resolve-Path -LiteralPath $TargetProfile).Path
    if (Test-Path -LiteralPath $profileCopy) {
        if ((Get-FileHash -LiteralPath $profileSource).Hash -ne (Get-FileHash -LiteralPath $profileCopy).Hash) {
            throw 'The existing target enrollment differs. Use a separate deployment; never silently replace it.'
        }
    } else { Copy-Item -LiteralPath $profileSource -Destination $profileCopy }
}
if (-not (Test-Path -LiteralPath $profileCopy)) { throw 'First installation requires -TargetProfile with actual target checks.' }
$artifactCopy = Join-Path $runtime 'initial-artifact.json'
if ($PublisherArtifact) {
    $artifactSource = (Resolve-Path -LiteralPath $PublisherArtifact).Path
    if (Test-Path -LiteralPath $artifactCopy) {
        if ((Get-FileHash -LiteralPath $artifactSource).Hash -ne (Get-FileHash -LiteralPath $artifactCopy).Hash) {
            throw 'Initial artifact is already retained. Deploy changes through authorized transactions.'
        }
    } else { Copy-Item -LiteralPath $artifactSource -Destination $artifactCopy }
}
$composeArgs = @('compose', '-p', $DeploymentName, '-f', 'compose.yaml')
if (Test-Path -LiteralPath $artifactCopy) { $composeArgs += @('-f', 'compose.publisher.yaml') }
Push-Location -LiteralPath $projectRoot
$previousRuntime, $previousConsole, $previousPublisher, $previousTrust = $env:ACE_RUNTIME_DIRECTORY, $env:ACE_CONSOLE_PORT, $env:ACE_PUBLISHER_PORT, $env:ACE_TRUST_HASH
try {
    $env:ACE_RUNTIME_DIRECTORY, $env:ACE_CONSOLE_PORT, $env:ACE_PUBLISHER_PORT = $runtime, "$ConsolePort", "$PublisherPort"
    docker build -t agentic-closure-engine:0.3.0 .
    if ($LASTEXITCODE -ne 0) { throw 'ACE image build failed.' }
    if (-not (Test-Path -LiteralPath $existingPin)) {
        & docker @composeArgs run --rm --no-deps -T bootstrap bootstrap
        if ($LASTEXITCODE -ne 0) { throw 'Initial enrollment failed; state retained for diagnosis.' }
    }
    $env:ACE_TRUST_HASH = (Get-Content -Raw -LiteralPath $existingPin).Trim()
    Assert-SingleAuthority $env:ACE_TRUST_HASH
    & docker @composeArgs up -d
    if ($LASTEXITCODE -ne 0) { throw 'ACE startup failed; state is retained for diagnosis.' }
    # The guard and compose up are complete; health polling does not need the host lock.
    $startupLock.Dispose()
    $deadline = (Get-Date).AddSeconds($HealthTimeoutSeconds)
    do {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$ConsolePort/" -TimeoutSec 2
            if ($response.StatusCode -eq 200 -and $response.Content.Contains('Agentic Closure Engine')) {
                Write-Output "ACE: http://127.0.0.1:$ConsolePort/"
                Write-Output "Operator token file: $runtime\operator.token"
                return
            }
        } catch { }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)
    throw 'ACE startup check timed out. Inspect docker compose logs gateway custody broker verifier.'
} finally {
    $env:ACE_RUNTIME_DIRECTORY, $env:ACE_CONSOLE_PORT, $env:ACE_PUBLISHER_PORT, $env:ACE_TRUST_HASH = $previousRuntime, $previousConsole, $previousPublisher, $previousTrust
    Pop-Location
}
} finally {
    $startupLock.Dispose()  # idempotent; releases on every failure path
}
