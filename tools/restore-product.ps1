param(
    [Parameter(Mandatory=$true)][string]$BackupDirectory,
    [Parameter(Mandatory=$true)][string]$KeyFile,
    [Parameter(Mandatory=$true)][string]$ExpectedCheckpointFile,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedArchiveHash,
    [Parameter(Mandatory=$true)][ValidatePattern('^sha256:[0-9a-f]{64}$')][string]$TrustHash,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-z][a-z0-9-]{2,50}$')][string]$DeploymentName,
    [switch]$Start,
    [ValidateRange(1024,65535)][int]$ConsolePort = 8782,
    [ValidateRange(1024,65535)][int]$PublisherPort = 8784
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'physical-path.ps1')
. (Join-Path $PSScriptRoot 'checked-start.ps1')
$backup = (Resolve-Path -LiteralPath $BackupDirectory).Path
$keyFile = (Resolve-Path -LiteralPath $KeyFile).Path
$checkpointFile = (Resolve-Path -LiteralPath $ExpectedCheckpointFile).Path
Assert-SeparateBackupKey $backup $keyFile
if ((Get-FileHash -LiteralPath (Join-Path $backup 'snapshot.ace')).Hash -ne $ExpectedArchiveHash) { throw 'Archive differs from its independently retained digest.' }
if ($DeploymentName -eq 'agentic-closure-engine') { throw 'Restore into a new deployment name; existing production data is never overwritten.' }
$runtime = Join-Path $projectRoot ".recovered/$DeploymentName"
if (Test-Path -LiteralPath $runtime) { throw 'Restore configuration already exists; inspect before continuing.' }
$staging = $runtime + '.staging'
$binding = [ordered]@{archive_sha256=$ExpectedArchiveHash.ToLowerInvariant(); trust_hash=$TrustHash; checkpoint_sha256=(Get-FileHash -LiteralPath $checkpointFile).Hash.ToLowerInvariant(); deployment=$DeploymentName}
$bindingFile = Join-Path $staging '.restore-source.json'
if (Test-Path -LiteralPath $staging) {
    if (-not (Test-Path -LiteralPath $bindingFile)) { throw 'Restore export staging has no authenticated source binding; inspect it before retrying.' }
    $previousBinding = Get-Content -Raw -LiteralPath $bindingFile | ConvertFrom-Json
    if (@($previousBinding.PSObject.Properties.Name).Count -ne $binding.Count -or @($binding.Keys | Where-Object { $previousBinding.$_ -ne $binding[$_] }).Count) { throw 'Restore export staging belongs to a different source; refused.' }
}
$mounts = @{
 'actor-key'='keys/actor';'owner-key'='keys/owner';'authority-key'='keys/authority';
 'verifier-key'='keys/verifier';'broker-key'='keys/broker';'operator'='operator';
 'actor-auth'='auth/actor';'owner-auth'='auth/owner';'authority-auth'='auth/authority';
 'verifier-auth'='auth/verifier';'broker-auth'='auth/broker';'custody-auth'='custody-auth';
 'custody-data'='custody-data';'broker-intents'='broker-intents';'gateway-data'='gateway';
 'gateway-auth'='gateway-auth';'publisher-data'='publisher-data';'export-data'='exports'
}
$arguments = @('run','--rm','--network','none','--read-only','--cap-drop','ALL','--cap-add','CHOWN','--cap-add','FOWNER','--cap-add','DAC_OVERRIDE','--security-opt','no-new-privileges:true','--user','0:0','--env','TMPDIR=/scratch')
foreach ($entry in $mounts.GetEnumerator()) {
    $arguments += @('--mount', "type=volume,source=$($DeploymentName)_$($entry.Key),target=/volumes/$($entry.Value)")
}
$arguments += @('--tmpfs','/scratch:rw,noexec,nosuid,size=1g,mode=700',
 '--mount',"type=bind,source=$backup,target=/backup,readonly",
 '--mount',"type=bind,source=$keyFile,target=/backup-key/snapshot.key,readonly",
 '--mount',"type=bind,source=$checkpointFile,target=/anchor/checkpoint.json,readonly",
 'agentic-closure-engine:0.3.0','restore',$TrustHash,$ExpectedArchiveHash)
& docker @arguments
if ($LASTEXITCODE -ne 0) { throw 'Restore refused or failed. Source archive and destination state are retained; no services were started.' }
New-Item -ItemType Directory -Path $staging -Force | Out-Null
[IO.File]::WriteAllText($bindingFile,($binding | ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
$copyCode = @'
import os
import uuid
from pathlib import Path
source, destination = Path('/exports'), Path('/configured')
entries = [path for path in source.iterdir() if path.is_file() and not path.is_symlink()]
if not entries:
    raise ValueError('RESTORE_EXPORT_EMPTY')
for path in entries:
    raw = path.read_bytes()
    temporary = destination / ('.export-' + uuid.uuid4().hex)
    try:
        with temporary.open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination / path.name)
        if (destination / path.name).read_bytes() != raw:
            raise ValueError('RESTORE_EXPORT_MISMATCH')
    finally:
        temporary.unlink(missing_ok=True)
'@
$copyArgs = @('run','--rm','--network','none','--read-only','--user','0:0','--mount',"type=volume,source=$($DeploymentName)_export-data,target=/exports,readonly",'--mount',"type=bind,source=$staging,target=/configured",'--entrypoint','python','agentic-closure-engine:0.3.0','-I','-c',$copyCode)
& docker @copyArgs
if ($LASTEXITCODE -ne 0) { throw "Restored configuration export failed; volumes and staging retained at $staging. Correct the storage failure and retry the same command; no runtime was promoted." }
Move-Item -LiteralPath $staging -Destination $runtime
Write-Output "Verified restore configuration: $runtime"
if ($Start) { Invoke-CheckedProductStart @{RuntimeDirectory=$runtime; DeploymentName=$DeploymentName; ConsolePort=$ConsolePort; PublisherPort=$PublisherPort} "Verified restore configuration saved at $runtime; no running-service success is claimed." }
