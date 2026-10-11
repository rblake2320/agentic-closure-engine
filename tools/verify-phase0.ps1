param([string]$Python = 'python', [string]$Output = '')
$ErrorActionPreference = 'Stop'
$closureRepo = Split-Path -Parent $PSScriptRoot
if (!$Output) { $Output = Join-Path $closureRepo ('evidence-runs\installed-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
& $Python (Join-Path $PSScriptRoot 'verify_phase0.py') --output $Output
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
