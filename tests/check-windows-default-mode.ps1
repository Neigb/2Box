param(
    [Parameter(Mandatory = $true)][string]$Baseline,
    [Parameter(Mandatory = $true)][string]$ManagedDefault
)

# Default (plain multi-instance) mode must not simulate any device: every identifier the probe reads
# must equal what the unmanaged baseline process sees.
$ErrorActionPreference = 'Stop'
$base = Get-Content -LiteralPath $Baseline -Raw | ConvertFrom-Json
$managed = Get-Content -LiteralPath $ManagedDefault -Raw | ConvertFrom-Json

if ($managed.FatalError) { throw "Default-mode probe failed: $($managed.FatalError)" }

foreach ($field in 'WmiSerial', 'AsyncWmiSerial', 'WmiModel', 'WmiBiosSerial', 'WmiProductUuid', 'WmiMac',
                   'WmiAdapterGuid', 'SmbiosSystem', 'MachineGuid', 'StorageSerial', 'AsyncStorageSerial', 'ShortQuery',
                   'InvalidWmiClassStatus') {
    if ([string]$base.$field -ne [string]$managed.$field) {
        throw "Default mode changed '$field' (device simulation must be off by default)"
    }
}
if ((@($base.IpHelperMacs) -join ',') -ne (@($managed.IpHelperMacs) -join ',')) { throw 'Default mode changed IP Helper MAC addresses' }
if ((@($base.IpHelperGuids) -join ',') -ne (@($managed.IpHelperGuids) -join ',')) { throw 'Default mode changed IP Helper adapter GUIDs' }

Write-Host 'Default mode leaves every device identifier untouched.'
