param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][string]$KeyDirectory,
    [string]$RuntimeDirectory,
    [string]$DeploymentName = 'agentic-closure-engine',
    [ValidateRange(1024,65535)][int]$ConsolePort = 8782,
    [ValidateRange(1024,65535)][int]$PublisherPort = 8784
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'physical-path.ps1')
. (Join-Path $PSScriptRoot 'checked-start.ps1')
$runtime = if ($RuntimeDirectory) { [IO.Path]::GetFullPath($RuntimeDirectory) } else { Join-Path $projectRoot '.runtime' }
$backupDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$keyDirectory = [IO.Path]::GetFullPath($KeyDirectory)
Assert-SeparateBackupKey $backupDirectory $keyDirectory
if (Test-Path -LiteralPath $backupDirectory) { throw 'Choose a new private backup directory; existing backups are never replaced.' }
New-Item -ItemType Directory -Path $backupDirectory | Out-Null
if (Test-Path -LiteralPath $keyDirectory) { throw 'Choose a new separate key directory; existing keys are never replaced.' }
New-Item -ItemType Directory -Path $keyDirectory | Out-Null
$previousDirectory = $env:ACE_BACKUP_DIRECTORY
$previousKeyDirectory = $env:ACE_BACKUP_KEY_DIRECTORY
$previousRuntime, $previousConsole, $previousPublisher = $env:ACE_RUNTIME_DIRECTORY, $env:ACE_CONSOLE_PORT, $env:ACE_PUBLISHER_PORT
$env:ACE_BACKUP_DIRECTORY = $backupDirectory
$env:ACE_BACKUP_KEY_DIRECTORY = $keyDirectory
Push-Location -LiteralPath $projectRoot
try {
    $env:ACE_RUNTIME_DIRECTORY, $env:ACE_CONSOLE_PORT, $env:ACE_PUBLISHER_PORT = $runtime, "$ConsolePort", "$PublisherPort"
    $pin = (Get-Content -Raw -LiteralPath (Join-Path $runtime 'trust.pin')).Trim()
    & tools/stop-product.ps1 -DeploymentName $DeploymentName -RuntimeDirectory $runtime
    if ($LASTEXITCODE -ne 0) { throw 'ACE stop failed; backup refused.' }
    $composeArgs = @('compose', '-p', $DeploymentName, '-f', 'compose.yaml')
    if (Test-Path -LiteralPath (Join-Path $runtime 'initial-artifact.json')) { $composeArgs += @('-f', 'compose.publisher.yaml') }
    $composeArgs += @('-f', 'compose.backup.yaml')
    & docker @composeArgs run --rm --no-deps -T backup backup $pin
    if ($LASTEXITCODE -ne 0) { throw 'Backup failed. State and partial output are retained; services remain stopped.' }
    $archive = Join-Path $backupDirectory 'snapshot.ace'
    $receipt = [ordered]@{result='BACKUP_SAVED'; archive=$archive; archive_sha256=(Get-FileHash -LiteralPath $archive).Hash.ToLowerInvariant(); trust_hash=$pin; deployment=$DeploymentName; key_file=(Join-Path $keyDirectory 'snapshot.key')}
    $receiptFile = Join-Path $keyDirectory 'snapshot.receipt.json'
    [IO.File]::WriteAllText($receiptFile,($receipt | ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    Write-Output ($receipt | ConvertTo-Json -Compress)
    Invoke-CheckedProductStart @{RuntimeDirectory=$runtime; DeploymentName=$DeploymentName; ConsolePort=$ConsolePort; PublisherPort=$PublisherPort} "Backup and receipt saved at $receiptFile. Services were stopped for the snapshot."
    $receipt.result = 'Worked'
    [IO.File]::WriteAllText($receiptFile,($receipt | ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    Write-Output ($receipt | ConvertTo-Json -Compress)
} finally {
    $env:ACE_BACKUP_DIRECTORY = $previousDirectory
    $env:ACE_BACKUP_KEY_DIRECTORY = $previousKeyDirectory
    $env:ACE_RUNTIME_DIRECTORY, $env:ACE_CONSOLE_PORT, $env:ACE_PUBLISHER_PORT = $previousRuntime, $previousConsole, $previousPublisher
    Pop-Location
}
