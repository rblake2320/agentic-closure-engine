param([string]$DeploymentName = 'agentic-closure-engine',[string]$RuntimeDirectory)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    $composeArgs = @('compose', '-p', $DeploymentName, '-f', 'compose.yaml')
    $runtime = if ($RuntimeDirectory) { [IO.Path]::GetFullPath($RuntimeDirectory) } else { Join-Path $projectRoot '.runtime' }
    if (Test-Path -LiteralPath (Join-Path $runtime 'initial-artifact.json')) { $composeArgs += @('-f', 'compose.publisher.yaml') }
    & docker @composeArgs stop
    if ($LASTEXITCODE -ne 0) { throw 'ACE stop failed.' }
    Write-Output 'ACE stopped. Identity, evidence, target and ledger volumes are retained.'
} finally { Pop-Location }
