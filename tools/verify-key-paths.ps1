param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'physical-path.ps1')
$root = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $root) { throw 'Choose a new verification directory.' }
$archive = Join-Path $root 'archive'
$separate = Join-Path $root 'separate'
New-Item -ItemType Directory -Path $archive,$separate | Out-Null
$alias = Join-Path $root 'archive-alias'
New-Item -ItemType Junction -Path $alias -Target $archive | Out-Null
$cases = @()
foreach ($key in @($archive, (Join-Path $archive 'new-key-dir'), (Join-Path $alias 'new-key-dir'))) {
    try { Assert-SeparateBackupKey $archive $key; throw 'Unsafe key path accepted.' }
    catch {
        if ($_.Exception.Message -ne 'BACKUP_KEY_STORAGE_NOT_SEPARATE') { throw }
        $cases += @{result='Worked'; expected='BACKUP_KEY_STORAGE_NOT_SEPARATE'; path=$key}
    }
}
foreach ($key in @($separate, (Join-Path $root 'archive-sibling/new-key-dir'))) {
    Assert-SeparateBackupKey $archive $key
    $cases += @{result='Worked'; expected='allowed'; path=$key}
}
@{result='Worked'; cases=$cases} | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath (Join-Path $root 'receipt.json') -Encoding UTF8
Write-Output "Worked: $($cases.Count) physical key-storage path controls; receipt retained."
