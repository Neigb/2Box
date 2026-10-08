param(
    [Parameter(Mandatory = $true)][string]$Baseline,
    [Parameter(Mandatory = $true)][string]$ManagedA,
    [Parameter(Mandatory = $true)][string]$ManagedB,
    [switch]$ExpectMachineGuid
)

$ErrorActionPreference = 'Stop'
$base = Get-Content -LiteralPath $Baseline -Raw | ConvertFrom-Json
$first = Get-Content -LiteralPath $ManagedA -Raw | ConvertFrom-Json
$second = Get-Content -LiteralPath $ManagedB -Raw | ConvertFrom-Json

if ($first.FatalError) { throw "First managed probe failed: $($first.FatalError)" }
if ($second.FatalError) { throw "Second managed probe failed: $($second.FatalError)" }

function Check([bool]$condition, [string]$message) {
    if (-not $condition) { throw $message }
}

function Is-Serial([string]$value) {
    return $value -and $value -notmatch '^(OPEN_ERROR|QUERY_ERROR|WAIT_ERROR|EVENT_ERROR|NO_|TIMEOUT$)'
}

function Normalize-Serial([string]$value) {
    return $value.Trim().ToUpperInvariant()
}

Check ($base.InvalidWmiClassStatus -eq $first.InvalidWmiClassStatus) 'WMI failure status changed'
Check ($base.ShortQuery -eq $first.ShortQuery) 'Short-buffer descriptor response changed'
Check ($base.WmiModel -eq $first.WmiModel) 'Non-unique disk model changed'
Check ((Is-Serial $base.WmiSerial) -or (Is-Serial $base.StorageSerial) -or $base.WmiMac) 'No device identifier available on runner'
Check ((Is-Serial $base.StorageSerial) -or $base.StorageSerial -eq 'NO_SERIAL') 'Storage descriptor query did not complete'
Check ((Is-Serial $base.AsyncStorageSerial) -or $base.AsyncStorageSerial -eq 'NO_SERIAL') 'Overlapped storage descriptor query did not complete'
Check ($base.ShortQuery -match '^SHORT_OK:') 'Short-buffer storage descriptor header query did not complete'

if (Is-Serial $base.WmiSerial) {
    Check ((Normalize-Serial $base.WmiSerial) -ne (Normalize-Serial $first.WmiSerial)) 'WMI disk serial was not rewritten'
    Check ((Normalize-Serial $first.WmiSerial) -ne (Normalize-Serial $second.WmiSerial)) 'WMI disk serial is not unique per environment'
    if ((Normalize-Serial $base.WmiSerial) -eq (Normalize-Serial $base.AsyncWmiSerial)) {
        Check ($first.WmiSerial -eq $first.AsyncWmiSerial) 'Synchronous and asynchronous WMI serials disagree'
    }
}
if (Is-Serial $base.AsyncWmiSerial) {
    Check ((Normalize-Serial $base.AsyncWmiSerial) -ne (Normalize-Serial $first.AsyncWmiSerial)) 'Asynchronous WMI serial was not rewritten'
    Check ((Normalize-Serial $first.AsyncWmiSerial) -ne (Normalize-Serial $second.AsyncWmiSerial)) 'Asynchronous WMI serial is not unique per environment'
}
if ($base.WmiBiosSerial) {
    Check ($base.WmiBiosSerial -ne $first.WmiBiosSerial) 'WMI BIOS serial was not rewritten'
    Check ($first.WmiBiosSerial -ne $second.WmiBiosSerial) 'WMI BIOS serial is not unique per environment'
}
if ($base.WmiProductUuid -and $base.WmiProductUuid -ne 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF') {
    Check ($base.WmiProductUuid -ne $first.WmiProductUuid) 'WMI product UUID was not rewritten'
    Check ($first.WmiProductUuid -ne $second.WmiProductUuid) 'WMI product UUID is not unique per environment'
    Check ($first.WmiProductUuid -match '^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$') 'WMI product UUID format is invalid'
}
if (Is-Serial $base.StorageSerial) {
    Check ((Normalize-Serial $base.StorageSerial) -ne (Normalize-Serial $first.StorageSerial)) 'Storage descriptor serial was not rewritten'
    Check ((Normalize-Serial $first.StorageSerial) -ne (Normalize-Serial $second.StorageSerial)) 'Storage descriptor serial is not unique per environment'
    Check ($first.StorageSerial -eq $first.AsyncStorageSerial) 'Synchronous and overlapped storage results differ'
    if ((Is-Serial $base.WmiSerial) -and
        ((Normalize-Serial $base.WmiSerial) -eq (Normalize-Serial $base.StorageSerial))) {
        Check ($first.WmiSerial -eq $first.StorageSerial) 'WMI and storage serials disagree for the same source'
    }
}
if ($base.WmiMac) {
    Check ($base.WmiMac -ne $first.WmiMac) 'WMI MAC address was not rewritten'
    Check ($first.WmiMac -ne $second.WmiMac) 'WMI MAC address is not unique per environment'
    Check ($base.WmiMac.Substring(0, 8) -eq $first.WmiMac.Substring(0, 8)) 'Network OUI changed'
    if ($base.IpHelperMacs -contains $base.WmiMac) {
        Check ($first.IpHelperMacs -contains $first.WmiMac) 'WMI and IP Helper MAC addresses disagree'
    }
}
if ($base.WmiAdapterGuid) {
    Check ($base.WmiAdapterGuid -ne $first.WmiAdapterGuid) 'WMI adapter GUID was not rewritten'
    Check ($first.WmiAdapterGuid -ne $second.WmiAdapterGuid) 'WMI adapter GUID is not unique per environment'
    if ($base.IpHelperGuids -contains $base.WmiAdapterGuid) {
        Check ($first.IpHelperGuids -contains $first.WmiAdapterGuid) 'WMI and IP Helper adapter GUIDs disagree'
    }
}

if ($ExpectMachineGuid -and $base.MachineGuid) {
    Check ($base.MachineGuid -ne $first.MachineGuid) 'MachineGuid was not rewritten'
    Check ($first.MachineGuid -ne $second.MachineGuid) 'MachineGuid is not unique per environment'
    Check ($first.MachineGuid -match '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$') 'MachineGuid format is invalid'
}

# Raw SMBIOS table versus WMI: the same data must read the same through both APIs.
if ($base.SmbiosSystem -and $base.SmbiosSystem -ne 'NO_SMBIOS' -and $first.SmbiosSystem -and $second.SmbiosSystem) {
    $baseParts = ([string]$base.SmbiosSystem).Split('|', 2)
    $firstParts = ([string]$first.SmbiosSystem).Split('|', 2)
    $secondParts = ([string]$second.SmbiosSystem).Split('|', 2)
    if ($baseParts[0] -ne 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF') {
        Check ($baseParts[0] -ne $firstParts[0]) 'SMBIOS table UUID was not rewritten'
        Check ($firstParts[0] -ne $secondParts[0]) 'SMBIOS table UUID is not unique per environment'
        if ($base.WmiProductUuid -eq $baseParts[0]) {
            Check ($first.WmiProductUuid -eq $firstParts[0]) 'WMI and SMBIOS table UUIDs disagree'
        }
    }
    if ($baseParts[1]) {
        Check ($baseParts[1] -ne $firstParts[1]) 'SMBIOS table system serial was not rewritten'
        Check ($firstParts[1] -ne $secondParts[1]) 'SMBIOS table system serial is not unique per environment'
        Check ($baseParts[1].Length -eq $firstParts[1].Length) 'SMBIOS table system serial length changed'
        if ($base.WmiBiosSerial -eq $baseParts[1]) {
            Check ($first.WmiBiosSerial -eq $firstParts[1]) 'WMI BIOS serial and SMBIOS table serial disagree'
        }
    }
}

Write-Host "Managed device query checks passed. Storage serial rewrite exercised: $(Is-Serial $base.StorageSerial)."
