param(
    [string]$TargetProfile,
    [string]$PublisherArtifact,
    [int]$HealthTimeoutSeconds = 90
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$runtime = Join-Path $projectRoot '.runtime'
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
$composeArgs = @('compose', '-f', 'compose.yaml')
if (Test-Path -LiteralPath $artifactCopy) { $composeArgs += @('-f', 'compose.publisher.yaml') }
Push-Location -LiteralPath $projectRoot
try {
    docker build -t agentic-closure-engine:0.3.0 .
    if ($LASTEXITCODE -ne 0) { throw 'ACE image build failed.' }
    & docker @composeArgs up -d
    if ($LASTEXITCODE -ne 0) { throw 'ACE startup failed; state is retained for diagnosis.' }
    $deadline = (Get-Date).AddSeconds($HealthTimeoutSeconds)
    do {
        try {
            $response = Invoke-WebRequest -Uri 'http://127.0.0.1:8782/' -TimeoutSec 2
            if ($response.StatusCode -eq 200 -and $response.Content.Contains('Agentic Closure Engine')) {
                Write-Output 'ACE: http://127.0.0.1:8782/'
                Write-Output "Operator token file: $runtime\operator.token"
                return
            }
        } catch { }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)
    throw 'ACE startup check timed out. Inspect docker compose logs gateway custody broker verifier.'
} finally { Pop-Location }
