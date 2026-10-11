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
$backup = (Resolve-Path -LiteralPath $BackupDirectory).Path
$keyFile = (Resolve-Path -LiteralPath $KeyFile).Path
$checkpointFile = (Resolve-Path -LiteralPath $ExpectedCheckpointFile).Path
Assert-SeparateBackupKey $backup $keyFile
if ((Get-FileHash -LiteralPath (Join-Path $backup 'snapshot.ace')).Hash -ne $ExpectedArchiveHash) { throw 'Archive differs from its independently retained digest.' }
if ($DeploymentName -eq 'agentic-closure-engine') { throw 'Restore into a new deployment name; existing production data is never overwritten.' }
$runtime = Join-Path $projectRoot ".recovered/$DeploymentName"
if (Test-Path -LiteralPath $runtime) { throw 'Restore configuration already exists; inspect before continuing.' }
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
 'agentic-closure-engine:0.3.0','restore',$TrustHash)
& docker @arguments
if ($LASTEXITCODE -ne 0) { throw 'Restore refused or failed. Source archive and destination state are retained; no services were started.' }
New-Item -ItemType Directory -Path $runtime | Out-Null
$copyArgs = @('run','--rm','--network','none','--read-only','--user','0:0','--mount',"type=volume,source=$($DeploymentName)_export-data,target=/exports,readonly",'--mount',"type=bind,source=$runtime,target=/configured",'--entrypoint','python','agentic-closure-engine:0.3.0','-I','-c',"import pathlib,shutil; [shutil.copyfile(p,pathlib.Path('/configured')/p.name) for p in pathlib.Path('/exports').iterdir() if p.is_file()]")
& docker @copyArgs
if ($LASTEXITCODE -ne 0) { throw 'Restored public configuration export failed; restored volumes retained.' }
Write-Output "Verified restore configuration: $runtime"
if ($Start) { & (Join-Path $PSScriptRoot 'start-product.ps1') -RuntimeDirectory $runtime -DeploymentName $DeploymentName -ConsolePort $ConsolePort -PublisherPort $PublisherPort }
