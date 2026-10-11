param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][string]$KeyDirectory
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$backupDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$keyDirectory = [IO.Path]::GetFullPath($KeyDirectory)
if ($keyDirectory.StartsWith($backupDirectory.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or $keyDirectory -eq $backupDirectory) {
    throw 'Keep the decryption key in a separate operator-controlled directory outside the archive directory.'
}
if (Test-Path -LiteralPath $backupDirectory) { throw 'Choose a new private backup directory; existing backups are never replaced.' }
New-Item -ItemType Directory -Path $backupDirectory | Out-Null
if (Test-Path -LiteralPath $keyDirectory) { throw 'Choose a new separate key directory; existing keys are never replaced.' }
New-Item -ItemType Directory -Path $keyDirectory | Out-Null
$previousDirectory = $env:ACE_BACKUP_DIRECTORY
$previousKeyDirectory = $env:ACE_BACKUP_KEY_DIRECTORY
$env:ACE_BACKUP_DIRECTORY = $backupDirectory
$env:ACE_BACKUP_KEY_DIRECTORY = $keyDirectory
Push-Location -LiteralPath $projectRoot
try {
    $pin = (Get-Content -Raw -LiteralPath '.runtime/trust.pin').Trim()
    & tools/stop-product.ps1
    $composeArgs = @('compose', '-f', 'compose.yaml')
    if (Test-Path -LiteralPath '.runtime/initial-artifact.json') { $composeArgs += @('-f', 'compose.publisher.yaml') }
    $composeArgs += @('-f', 'compose.backup.yaml')
    & docker @composeArgs run --rm --no-deps -T backup backup $pin
    if ($LASTEXITCODE -ne 0) { throw 'Backup failed. State and partial output are retained; services remain stopped.' }
    & tools/start-product.ps1
    Write-Output "Encrypted backup: $backupDirectory\snapshot.ace"
    Write-Output "Private decryption key: $keyDirectory\snapshot.key"
} finally {
    $env:ACE_BACKUP_DIRECTORY = $previousDirectory
    $env:ACE_BACKUP_KEY_DIRECTORY = $previousKeyDirectory
    Pop-Location
}
