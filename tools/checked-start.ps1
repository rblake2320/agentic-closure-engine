function Invoke-CheckedProductStart([hashtable]$Arguments, [string]$SavedState) {
    $global:LASTEXITCODE = 0
    & (Join-Path $PSScriptRoot 'start-product.ps1') @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "ACE_START_FAILED: $SavedState Startup refused or failed (exit $LASTEXITCODE); no running-service success is claimed. Retry tools/start-product.ps1 with the same deployment arguments."
    }
}
