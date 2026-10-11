$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    $composeArgs = @('compose', '-f', 'compose.yaml')
    if (Test-Path -LiteralPath '.runtime/initial-artifact.json') { $composeArgs += @('-f', 'compose.publisher.yaml') }
    & docker @composeArgs stop
    if ($LASTEXITCODE -ne 0) { throw 'ACE stop failed.' }
    Write-Output 'ACE stopped. Identity, evidence, target and ledger volumes are retained.'
} finally { Pop-Location }
