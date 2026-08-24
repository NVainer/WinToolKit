<#
.SYNOPSIS
    Device Control Console -- a GUI and CLI for pnputil and the Windows device tree.

.DESCRIPTION
    The same console as the Python and native builds, running entirely under
    Windows PowerShell.  It exists because Smart App Control and enterprise
    WDAC/AppLocker policies block unsigned executables: this build never
    produces one.  Everything it runs through is already Microsoft-signed --
    powershell.exe, the PnpDevice module, and pnputil.exe.

    Resolves an instance ID to the device a human would recognise:

        USB\VID_1038&PID_1838\6&2ae87d4e&0&1
          -> SteelSeries Aerox 3 Wireless (Mouse)

.EXAMPLE
    .\DeviceControlConsole.ps1
    Starts the local web console.

.EXAMPLE
    .\DeviceControlConsole.ps1 resolve "USB\VID_1038&PID_1838\6&2ae87d4e&0&1" -Relations

.EXAMPLE
    .\DeviceControlConsole.ps1 orphans -Superseded
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('serve', 'devices', 'drivers', 'resolve', 'orphans', 'tree', 'status',
        'check', 'update-hwids', 'delete-driver', 'enable-device', 'disable-device',
        'restart-device', 'remove-device', 'bundle', 'help')]
    [string]$Command = 'serve',

    [Parameter(Position = 1)]
    [string]$Query = '',

    [int]$Port = 8777,
    [switch]$NoBrowser,
    [string]$TokenFile = '',

    [ValidateSet('all', 'connected', 'disconnected', 'problem')]
    [string]$Status = 'all',
    [ValidateSet('all', 'inuse', 'orphaned', 'superseded', 'extension')]
    [string]$State = 'all',
    [string]$Class = '',
    [string]$Type = '',
    [int]$Limit = 60,
    [int]$Depth = 4,
    [switch]$Relations,
    [switch]$Superseded,
    [switch]$Uninstall,
    [switch]$Force,
    [switch]$Reboot,
    [switch]$Subtree,
    [switch]$Yes,
    [string]$Csv = '',
    [string]$OutFile = ''
)

$ErrorActionPreference = 'Stop'
# Progress rendering makes the PnP cmdlets several times slower.
$ProgressPreference = 'SilentlyContinue'

$script:Version = '1.0.0'
$script:Root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

#region ----------------------------------------------------------- constants

# Descriptions that name a Windows enumerator rather than a product.
$script:GenericDesc = @(
    'usb composite device', 'usb input device', 'usb root hub', 'generic usb hub',
    'usb hub', 'unknown device', 'usb mass storage device',
    'usb attached scsi (uas) mass storage device', 'composite bus enumerator',
    'hid-compliant mouse', 'hid-compliant device', 'hid-compliant consumer control device',
    'hid-compliant vendor-defined device', 'hid-compliant system controller',
    'hid keyboard device', 'hid-compliant touch pad', 'usb printing support',
    'generic pnp monitor', 'pci device', 'pci standard host cb bridge',
    'base system device', 'usb serial converter', 'microsoft usb generic device',
    'usb device', 'bluetooth device', 'generic bluetooth adapter',
    'standard nvm express controller', 'standard sata ahci controller',
    'sd host controller', 'unknown usb device', 'audio endpoint'
)
$script:GenericMfgPrefix = @('(standard', '(generic', '(default', '(retired')
$script:GenericMfgExact = @('microsoft', 'generic', 'compatible', 'system', 'unknown')

$script:ClassToType = @{
    'mouse' = 'Mouse'; 'keyboard' = 'Keyboard'; 'hidclass' = 'HID'; 'display' = 'Graphics'
    'monitor' = 'Monitor'; 'net' = 'Network adapter'; 'netclient' = 'Network client'
    'netservice' = 'Network service'; 'nettrans' = 'Network protocol'; 'media' = 'Audio/Video'
    'audioendpoint' = 'Audio endpoint'; 'audioprocessingobject' = 'Audio processing'
    'sound' = 'Audio'; 'usb' = 'USB controller/hub'; 'usbdevice' = 'USB device'
    'diskdrive' = 'Disk'; 'cdrom' = 'Optical drive'; 'volume' = 'Volume'
    'volumesnapshot' = 'Volume snapshot'; 'scsiadapter' = 'Storage controller'
    'hdc' = 'Storage controller'; 'printer' = 'Printer'; 'printqueue' = 'Print queue'
    'image' = 'Camera/Scanner'; 'camera' = 'Camera'; 'bluetooth' = 'Bluetooth'
    'ports' = 'Serial/Parallel port'; 'modem' = 'Modem'; 'battery' = 'Battery'
    'processor' = 'Processor'; 'system' = 'System device'; 'computer' = 'Computer'
    'firmware' = 'Firmware'; 'securitydevices' = 'Security device'
    'smartcardreader' = 'Smart card reader'; 'biometric' = 'Biometric'; 'sensor' = 'Sensor'
    'wpd' = 'Portable device'; 'aenetdevice' = 'Network device'
    'softwarecomponent' = 'Software component'; 'softwaredevice' = 'Software device'
    'extension' = 'Driver extension'; 'dot4' = 'Multi-function printer'
    'dot4print' = 'Printer function'; 'medialocation' = 'Media location'
    'infrared' = 'Infrared'; 'smartcardfilter' = 'Smart card filter'
    'memory' = 'Memory technology'; 'mtd' = 'Memory technology'
    'computeaccelerator' = 'Compute accelerator'; '1394' = 'IEEE 1394'; 'pcmcia' = 'PCMCIA'
    'fdc' = 'Floppy controller'; 'floppydisk' = 'Floppy drive'; 'tapedrive' = 'Tape drive'
    'unknown' = 'Unknown'
}

$script:HidUsageToType = @{
    '0001:0002' = 'Mouse'; '0001:0004' = 'Joystick'; '0001:0005' = 'Gamepad'
    '0001:0006' = 'Keyboard'; '0001:0007' = 'Keypad'; '0001:0080' = 'System control'
    '000C:0001' = 'Consumer control'; '000D:0001' = 'Digitizer'; '000D:0002' = 'Pen'
    '000D:0004' = 'Touch screen'; '000D:0005' = 'Touch pad'; '0080:0001' = 'Smart card'
    'FF00:0001' = 'Vendor-specific'
}

# Classes that describe a container or a bus rather than the thing itself.
$script:ContainerClasses = @('usb', 'usbdevice', 'system', 'computer', 'softwaredevice',
    'extension', 'volume', 'hdc', 'scsiadapter', 'unknown', 'usbfnproviders')
# Types that are correct but say little; a sibling saying "Mouse" wins.
$script:WeakTypes = @('HID', 'Consumer control', 'Vendor-specific', 'System control',
    'USB device', 'USB controller/hub', 'Unknown', 'Software device',
    'Software component', 'Driver extension', 'System device', 'HID device')

$script:ProblemText = @{
    1 = 'Not configured correctly'; 3 = 'Driver may be corrupted, or low on memory'
    10 = 'The device cannot start'; 12 = 'Cannot find enough free resources'
    14 = 'Restart the computer to use this device'; 18 = 'Reinstall the drivers'
    19 = 'The registry configuration is incomplete or damaged'
    21 = 'Windows is removing the device'; 22 = 'The device is disabled'
    24 = 'Device is not present, not working properly, or missing drivers'
    28 = 'The drivers for this device are not installed'
    31 = 'Windows cannot load the drivers for this device'
    32 = 'A driver for this device has been disabled'
    35 = 'The firmware does not include enough information'
    37 = 'The driver returned a failure when it executed DriverEntry'
    38 = 'A previous instance of the driver is still in memory'
    39 = 'The driver is corrupted or missing'
    40 = 'The service key information in the registry is missing or invalid'
    43 = 'Windows stopped this device because it reported problems'
    45 = 'The device is not connected to the computer'
    47 = 'Prepared for safe removal but not removed'
    48 = 'The software for this device has been blocked'
    52 = 'The driver signature could not be verified'
    54 = 'The device has failed and is undergoing a reset'
}

# Properties fetched in bulk for every present device.
$script:BulkKeys = @(
    # First, so every bulk result can say which device it came from:
    # Invoke-CimMethod returns only the method's out-parameters, with no
    # reference back to the instance it was invoked on.
    'DEVPKEY_Device_InstanceId'
    'DEVPKEY_Device_BusReportedDeviceDesc'
    'DEVPKEY_Device_Parent'
    'DEVPKEY_Device_Children'
    'DEVPKEY_Device_ContainerId'
    'DEVPKEY_Device_DriverInfPath'
    'DEVPKEY_Device_DriverVersion'
    'DEVPKEY_Device_DriverProvider'
    'DEVPKEY_Device_LocationInfo'
    'DEVPKEY_Device_LastArrivalDate'
    'DEVPKEY_Device_LastRemovalDate'
    'DEVPKEY_Device_InstallDate'
    'DEVPKEY_Device_ProblemCode'
    'DEVPKEY_Device_DevNodeStatus'
    'DEVPKEY_Device_CompatibleIds'
)

$script:SeedUsbVendors = @{
    '03F0' = 'HP'; '0403' = 'FTDI'; '041E' = 'Creative Technology'; '0424' = 'Microchip (SMSC)'
    '045E' = 'Microsoft'; '046D' = 'Logitech'; '04A9' = 'Canon'; '04B4' = 'Cypress'
    '04B8' = 'Seiko Epson'; '04CA' = 'Lite-On'; '04E8' = 'Samsung'; '04F2' = 'Chicony'
    '04F3' = 'Elan Microelectronics'; '050D' = 'Belkin'; '054C' = 'Sony'; '056A' = 'Wacom'
    '057E' = 'Nintendo'; '058F' = 'Alcor Micro'; '05AC' = 'Apple'; '05C6' = 'Qualcomm'
    '05E3' = 'Genesys Logic'; '067B' = 'Prolific'; '06CB' = 'Synaptics'; '0781' = 'SanDisk'
    '0846' = 'NetGear'; '090C' = 'Silicon Motion'; '0930' = 'Toshiba'; '093A' = 'Pixart Imaging'
    '0951' = 'Kingston'; '09DA' = 'A4Tech'; '0A5C' = 'Broadcom'; '0B05' = 'ASUSTek'
    '0B0E' = 'GN Netcom (Jabra)'; '0BC2' = 'Seagate'; '0BDA' = 'Realtek'; '0C45' = 'Microdia'
    '0CF3' = 'Qualcomm Atheros'; '0D8C' = 'C-Media'; '0E8D' = 'MediaTek'; '1004' = 'LG Electronics'
    '1038' = 'SteelSeries ApS'; '1050' = 'Yubico'; '1058' = 'Western Digital'
    '10C4' = 'Silicon Labs'; '12D1' = 'Huawei'; '13D3' = 'IMC Networks'; '1462' = 'MSI'
    '1532' = 'Razer'; '174C' = 'ASMedia'; '17EF' = 'Lenovo'; '18D1' = 'Google'
    '1A86' = 'QinHeng Electronics'; '1B1C' = 'Corsair'; '1D6B' = 'Linux Foundation'
    '2109' = 'VIA Labs'; '22B8' = 'Motorola'; '2341' = 'Arduino'; '2357' = 'TP-Link'
    '2717' = 'Xiaomi'; '27C6' = 'Goodix'; '28DE' = 'Valve'; '2E8A' = 'Raspberry Pi'
    '413C' = 'Dell'; '5986' = 'Acer/Bison Electronics'; '8086' = 'Intel'; '8087' = 'Intel'
}
$script:SeedPciVendors = @{
    '1002' = 'AMD/ATI'; '1022' = 'AMD'; '1028' = 'Dell'; '103C' = 'Hewlett-Packard'
    '1043' = 'ASUSTeK'; '104C' = 'Texas Instruments'; '10DE' = 'NVIDIA'
    '10EC' = 'Realtek'; '11AB' = 'Marvell'; '144D' = 'Samsung'; '14E4' = 'Broadcom'
    '15AD' = 'VMware'; '15B7' = 'Sandisk'; '168C' = 'Qualcomm Atheros'; '197B' = 'JMicron'
    '1B21' = 'ASMedia'; '1C5C' = 'SK hynix'; '1E0F' = 'KIOXIA'; '2646' = 'Kingston'
    '8086' = 'Intel Corporation'; '9005' = 'Adaptec'
}

#endregion

#region -------------------------------------------------------------- helpers

function Test-GenericDesc {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $true }
    $low = $Text.Trim().ToLowerInvariant()
    foreach ($g in $script:GenericDesc) {
        if ($low -eq $g -or $low.StartsWith($g)) { return $true }
    }
    return $false
}

function Test-GenericMfg {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $true }
    $low = $Text.Trim().ToLowerInvariant()
    if ($script:GenericMfgExact -contains $low) { return $true }
    foreach ($p in $script:GenericMfgPrefix) { if ($low.StartsWith($p)) { return $true } }
    return $false
}

function Get-HwIds {
    param([string]$InstanceId, [string[]]$HardwareIds)
    $bus = ''
    if ($InstanceId -and $InstanceId.Contains('\')) {
        $bus = $InstanceId.Substring(0, $InstanceId.IndexOf('\')).ToUpperInvariant()
    }
    $ids = [ordered]@{ bus = $bus; vid = $null; pid = $null
        subsys_vendor = $null; subsys_device = $null; id_kind = $null }

    $pool = New-Object System.Collections.ArrayList
    $null = $pool.Add($InstanceId)
    if ($HardwareIds) { foreach ($h in $HardwareIds) { if ($h) { $null = $pool.Add($h) } } }

    foreach ($candidate in $pool) {
        if ($candidate -match 'VID_([0-9A-Fa-f]{4}).*?PID_([0-9A-Fa-f]{4})') {
            $ids.vid = $Matches[1].ToUpperInvariant()
            $ids.pid = $Matches[2].ToUpperInvariant()
            $ids.id_kind = 'usb'
            break
        }
        if ($candidate -match 'VEN_([0-9A-Fa-f]{4}).*?DEV_([0-9A-Fa-f]{4})') {
            $ids.vid = $Matches[1].ToUpperInvariant()
            $ids.pid = $Matches[2].ToUpperInvariant()
            $ids.id_kind = 'pci'
            break
        }
    }
    foreach ($candidate in $pool) {
        if ($candidate -match 'SUBSYS_([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})') {
            $ids.subsys_device = $Matches[1].ToUpperInvariant()
            $ids.subsys_vendor = $Matches[2].ToUpperInvariant()
            break
        }
    }
    return $ids
}

function Get-HidUsageType {
    param([string[]]$Ids)
    if (-not $Ids) { return $null }
    foreach ($id in $Ids) {
        if (-not $id) { continue }
        if ($id -match 'UP:([0-9A-Fa-f]{4})_U:([0-9A-Fa-f]{4})') {
            $key = "$($Matches[1].ToUpperInvariant()):$($Matches[2].ToUpperInvariant())"
            if ($script:HidUsageToType.ContainsKey($key)) { return $script:HidUsageToType[$key] }
        }
        $upper = $id.ToUpperInvariant()
        if ($upper.EndsWith('HID_DEVICE_SYSTEM_MOUSE')) { return 'Mouse' }
        if ($upper.EndsWith('HID_DEVICE_SYSTEM_KEYBOARD')) { return 'Keyboard' }
        if ($upper.EndsWith('HID_DEVICE_SYSTEM_GAME')) { return 'Gamepad' }
    }
    return $null
}

function Get-ClassType {
    param([string]$ClassName)
    if ([string]::IsNullOrWhiteSpace($ClassName)) { return $null }
    $key = $ClassName.Trim().ToLowerInvariant()
    if ($script:ClassToType.ContainsKey($key)) { return $script:ClassToType[$key] }
    return $null
}

function Get-VendorFromIds {
    param($Ids)
    $result = @{ vendor = $null; product = $null }
    if (-not $Ids -or -not $Ids.id_kind -or -not $Ids.vid) { return $result }
    $table = if ($Ids.id_kind -eq 'usb') { $script:SeedUsbVendors } else { $script:SeedPciVendors }
    $file = Join-Path (Get-HwIdsCacheDir) "$($Ids.id_kind).ids"
    $loaded = Get-HwIdsTable -Path $file
    if ($loaded -and $loaded.ContainsKey($Ids.vid)) {
        $entry = $loaded[$Ids.vid]
        $result.vendor = $entry.name
        if ($Ids.pid -and $entry.products.ContainsKey($Ids.pid)) {
            $result.product = $entry.products[$Ids.pid]
        }
        return $result
    }
    if ($table.ContainsKey($Ids.vid)) { $result.vendor = $table[$Ids.vid] }
    return $result
}

function Get-HwIdsCacheDir {
    $candidate = Join-Path $script:Root 'hwids'
    try {
        if (-not (Test-Path $candidate)) { New-Item -ItemType Directory -Path $candidate -Force | Out-Null }
        $probe = Join-Path $candidate '.writable'
        Set-Content -LiteralPath $probe -Value '' -Force
        Remove-Item -LiteralPath $probe -Force
        return $candidate
    } catch {
        $appData = Join-Path $env:LOCALAPPDATA 'DeviceControlConsole'
        if (-not (Test-Path $appData)) { New-Item -ItemType Directory -Path $appData -Force | Out-Null }
        return $appData
    }
}

$script:HwIdsCache = @{}
function Get-HwIdsTable {
    param([string]$Path)
    if ($script:HwIdsCache.ContainsKey($Path)) { return $script:HwIdsCache[$Path] }
    if (-not (Test-Path -LiteralPath $Path)) { $script:HwIdsCache[$Path] = $null; return $null }
    $table = @{}
    $current = $null
    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        if ($line.Length -eq 0 -or $line[0] -eq '#') { continue }
        if ($line.StartsWith("`t`t")) { continue }
        if ($line[0] -eq "`t") {
            if ($current -and $line -match '^\t([0-9a-fA-F]{4})\s+(.*)$') {
                $current.products[$Matches[1].ToUpperInvariant()] = $Matches[2].Trim()
            }
            continue
        }
        if ($line -match '^([0-9a-fA-F]{4})\s+(.*)$') {
            $current = @{ name = $Matches[2].Trim(); products = @{} }
            $table[$Matches[1].ToUpperInvariant()] = $current
        } else { $current = $null }
    }
    $script:HwIdsCache[$Path] = $table
    return $table
}

$script:ClassDisplayCache = @{}
function Get-ClassDisplayName {
    param([string]$ClassGuid)
    if (-not $ClassGuid) { return '' }
    $key = $ClassGuid.ToLowerInvariant()
    if ($script:ClassDisplayCache.ContainsKey($key)) { return $script:ClassDisplayCache[$key] }
    $name = ''
    foreach ($hive in @('HKLM:\SYSTEM\CurrentControlSet\Control\Class')) {
        try {
            $item = Get-ItemProperty -LiteralPath (Join-Path $hive $ClassGuid) -ErrorAction Stop
            if ($item.PSObject.Properties['ClassDesc'] -and $item.ClassDesc) {
                $name = [string]$item.ClassDesc
                # Values like "@system32\foo.dll,-123" are resource references.
                if ($name.StartsWith('@')) { $name = '' }
            }
            if (-not $name -and $item.PSObject.Properties['Class']) { $name = [string]$item.Class }
        } catch { }
    }
    $script:ClassDisplayCache[$key] = $name
    return $name
}

function Copy-OrderedMap {
    # [ordered]@{} is an OrderedDictionary, which has no Clone().
    param($Map)
    $copy = [ordered]@{}
    foreach ($k in $Map.Keys) { $copy[$k] = $Map[$k] }
    return $copy
}

function Test-Elevated {
    if ($null -ne $script:IsElevated) { return $script:IsElevated }
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        $script:IsElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { $script:IsElevated = $false }
    return $script:IsElevated
}
$script:IsElevated = $null

#endregion

#region ------------------------------------------------------------- pnputil

$script:PnpUtilPath = Join-Path $env:SystemRoot 'System32\pnputil.exe'

function Invoke-PnpUtilXml {
    param([string[]]$Arguments)
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dcc_pnp_" + [guid]::NewGuid().ToString('N') + ".xml")
    try {
        $full = @($Arguments) + @('/format', 'xml', '/output-file', $tmp)
        $null = & $script:PnpUtilPath @full 2>&1
        if (-not (Test-Path -LiteralPath $tmp)) { return $null }
        $text = Get-Content -LiteralPath $tmp -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }
        return [xml]$text
    } catch {
        Write-Verbose "pnputil failed: $($_.Exception.Message)"
        return $null
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Get-DriverStore {
    $xml = Invoke-PnpUtilXml -Arguments @('/enum-drivers', '/devices', '/ids')
    $packages = New-Object System.Collections.ArrayList
    if (-not $xml -or -not $xml.PnpUtil) { return $packages }
    foreach ($node in @($xml.PnpUtil.Driver)) {
        if (-not $node) { continue }
        $deviceIds = New-Object System.Collections.ArrayList
        if ($node.Devices -and $node.Devices.Device) {
            foreach ($d in @($node.Devices.Device)) {
                if ($d.InstanceId) { $null = $deviceIds.Add([string]$d.InstanceId) }
            }
        }
        $attributes = @()
        if ($node.CatalogAttributes -and $node.CatalogAttributes.Attribute) {
            $attributes = @($node.CatalogAttributes.Attribute | ForEach-Object { [string]$_ })
        }
        $null = $packages.Add([ordered]@{
            driver_name       = [string]$node.DriverName
            original_name     = [string]$node.OriginalName
            provider_name     = [string]$node.ProviderName
            class_name        = [string]$node.ClassName
            class_guid        = [string]$node.ClassGuid
            driver_version    = [string]$node.DriverVersion
            signer_name       = [string]$node.SignerName
            whcp_version      = [string]$node.WhcpVersion
            driver_package_id = [string]$node.DriverPackageId
            family_id         = [string]$node.FamilyId
            attributes        = $attributes
            device_ids_raw    = $deviceIds
        })
    }
    return $packages
}

function Get-PnpUtilDevices {
    $xml = Invoke-PnpUtilXml -Arguments @('/enum-devices')
    $rows = @{}
    if (-not $xml -or -not $xml.PnpUtil) { return $rows }
    foreach ($node in @($xml.PnpUtil.Device)) {
        if (-not $node -or -not $node.InstanceId) { continue }
        $ext = @()
        if ($node.ExtensionDriverNames -and $node.ExtensionDriverNames.DriverName) {
            $ext = @($node.ExtensionDriverNames.DriverName | ForEach-Object { [string]$_ })
        }
        $rows[[string]$node.InstanceId] = @{
            driver_name       = [string]$node.DriverName
            extension_drivers = $ext
            status            = [string]$node.Status
            description       = [string]$node.DeviceDescription
            manufacturer      = [string]$node.ManufacturerName
            class_name        = [string]$node.ClassName
            class_guid        = [string]$node.ClassGuid
        }
    }
    return $rows
}

#endregion

#region -------------------------------------------------------- device scan

function Convert-PropValue {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-ddTHH:mm:sszzz') }
    if ($Value -is [array]) { return @($Value | ForEach-Object { [string]$_ }) }
    return [string]$Value
}

function Get-DeviceSnapshotRaw {
    <#
        One bulk call for every device, then one bulk CIM method call for the
        rich DEVPKEYs.  The method only answers for devices that are present,
        so absent ones keep the base data -- which still carries FriendlyName,
        and that is what names a disconnected composite device through its
        interface children.
    #>
    $devices = @{}
    $all = @(Get-PnpDevice -ErrorAction SilentlyContinue)

    foreach ($d in $all) {
        $hw = @()
        if ($d.HardwareID) { $hw = @($d.HardwareID) }
        $compat = @()
        if ($d.CompatibleID) { $compat = @($d.CompatibleID) }
        $present = [bool]$d.Present
        $devices[$d.InstanceId] = [ordered]@{
            instance_id        = [string]$d.InstanceId
            description        = [string]$d.Description
            friendly_name      = if ($d.FriendlyName) { [string]$d.FriendlyName } else { '' }
            bus_reported       = ''
            class_name         = [string]$d.Class
            class_guid         = ([string]$d.ClassGuid).ToLowerInvariant()
            class_display      = ''
            manufacturer       = [string]$d.Manufacturer
            service            = [string]$d.Service
            hardware_ids       = $hw
            compatible_ids     = $compat
            driver_inf         = ''
            driver_version     = ''
            driver_provider    = ''
            driver_date        = ''
            parent             = ''
            children           = @()
            related            = @()
            container_id       = ''
            location           = ''
            install_date       = ''
            last_arrival       = ''
            last_removal       = ''
            present            = $present
            status             = ''
            problem_code       = 0
            problem_text       = ''
            status_flags       = @()
            ids                = Get-HwIds -InstanceId ([string]$d.InstanceId) -HardwareIds $hw
            driver_name        = ''
            extension_drivers  = @()
            resolved_name      = ''
            resolved_from      = ''
            resolved_confidence = 'none'
            device_type        = ''
            type_from          = ''
            vendor             = ''
            vendor_from        = ''
            driver_is_oem      = $false
            child_count        = 0
            search_blob        = ''
            _enriched          = $false
        }
    }

    # Rich properties, in bulk, for everything that answers.
    $present = @($all | Where-Object { $_.Present })
    if ($present.Count -gt 0) {
        $bulk = @($present | Invoke-CimMethod -MethodName GetDeviceProperties `
            -Arguments @{ devicePropertyKeys = $script:BulkKeys } -ErrorAction SilentlyContinue)
        foreach ($result in $bulk) {
            if (-not $result -or -not $result.deviceProperties) { continue }
            $id = $null
            foreach ($prop in $result.deviceProperties) {
                if ($prop.KeyName -eq 'DEVPKEY_Device_InstanceId' -and $prop.Data) {
                    $id = [string]$prop.Data
                    break
                }
            }
            if (-not $id -or -not $devices.ContainsKey($id)) { continue }
            Set-DeviceProperties -Device $devices[$id] -Properties $result.deviceProperties
            $devices[$id]._enriched = $true
        }
    }
    return $devices
}

function Set-DeviceProperties {
    param($Device, $Properties)
    foreach ($p in $Properties) {
        if ($null -eq $p.Data) { continue }
        $value = Convert-PropValue -Value $p.Data
        switch ($p.KeyName) {
            'DEVPKEY_Device_BusReportedDeviceDesc' { $Device.bus_reported = [string]$value }
            'DEVPKEY_Device_Parent'                { $Device.parent = [string]$value }
            'DEVPKEY_Device_Children'              { $Device.children = @($value) }
            'DEVPKEY_Device_ContainerId'           { $Device.container_id = ([string]$value).ToLowerInvariant() }
            'DEVPKEY_Device_DriverInfPath'         { $Device.driver_inf = [string]$value }
            'DEVPKEY_Device_DriverVersion'         { $Device.driver_version = [string]$value }
            'DEVPKEY_Device_DriverProvider'        { $Device.driver_provider = [string]$value }
            'DEVPKEY_Device_LocationInfo'          { $Device.location = [string]$value }
            'DEVPKEY_Device_LastArrivalDate'       { $Device.last_arrival = [string]$value }
            'DEVPKEY_Device_LastRemovalDate'       { $Device.last_removal = [string]$value }
            'DEVPKEY_Device_InstallDate'           { $Device.install_date = [string]$value }
            'DEVPKEY_Device_ProblemCode'               { $Device.problem_code = [int]$p.Data }
            'DEVPKEY_Device_CompatibleIds'         { $Device.compatible_ids = @($value) }
        }
    }
}

function Update-DeviceDetail {
    <#
        Absent devices are skipped by the bulk method, so their bus-reported
        name is fetched individually -- but only when someone actually looks at
        one, which keeps the cost off the initial scan.
    #>
    param([string]$InstanceId, $Device)
    if ($Device._enriched) { return }
    try {
        $props = Get-PnpDeviceProperty -InstanceId $InstanceId -KeyName $script:BulkKeys -ErrorAction Stop
        Set-DeviceProperties -Device $Device -Properties $props
        $Device._enriched = $true
    } catch {
        Write-Verbose "could not enrich $InstanceId : $($_.Exception.Message)"
    }
}

#endregion

#region -------------------------------------------------------------- resolve

function New-Resolver {
    param($Devices)
    $children = @{}
    $byVidPid = @{}
    $byContainer = @{}

    foreach ($id in $Devices.Keys) {
        $d = $Devices[$id]
        if ($d.ids.vid -and $d.ids.pid) {
            $key = "$($d.ids.vid):$($d.ids.pid)"
            if (-not $byVidPid.ContainsKey($key)) { $byVidPid[$key] = New-Object System.Collections.ArrayList }
            $null = $byVidPid[$key].Add($id)
        }
        if (Test-RealContainer $d.container_id) {
            if (-not $byContainer.ContainsKey($d.container_id)) {
                $byContainer[$d.container_id] = New-Object System.Collections.ArrayList
            }
            $null = $byContainer[$d.container_id].Add($id)
        }
        foreach ($c in $d.children) {
            if (-not $children.ContainsKey($id)) { $children[$id] = New-Object System.Collections.ArrayList }
            if (-not $children[$id].Contains($c)) { $null = $children[$id].Add($c) }
        }
    }
    # The child always remembers its parent even when Children is absent.
    foreach ($id in $Devices.Keys) {
        $parent = $Devices[$id].parent
        if (-not $parent -or -not $Devices.ContainsKey($parent)) { continue }
        if (-not $children.ContainsKey($parent)) { $children[$parent] = New-Object System.Collections.ArrayList }
        if (-not $children[$parent].Contains($id)) { $null = $children[$parent].Add($id) }
    }

    return @{ devices = $Devices; children = $children
              byVidPid = $byVidPid; byContainer = $byContainer }
}

function Test-RealContainer {
    param([string]$ContainerId)
    if ([string]::IsNullOrWhiteSpace($ContainerId)) { return $false }
    $low = $ContainerId.ToLowerInvariant()
    return (-not $low.StartsWith('{00000000')) -and (-not $low.StartsWith('{ffffffff'))
}

function Get-ResolverChildren {
    param($Resolver, [string]$InstanceId)
    if ($Resolver.children.ContainsKey($InstanceId)) { return @($Resolver.children[$InstanceId]) }
    return @()
}

function Test-SamePhysicalDevice {
    param($Resolver, [string]$A, [string]$B)
    $da = $Resolver.devices[$A]; $db = $Resolver.devices[$B]
    if ((Test-RealContainer $da.container_id) -and $da.container_id -eq $db.container_id) { return $true }
    if ($da.ids.vid -and $da.ids.vid -eq $db.ids.vid -and $da.ids.pid -eq $db.ids.pid) { return $true }
    return $false
}

function Get-Descendants {
    param($Resolver, [string]$InstanceId, [int]$MaxDepth = 4)
    $found = New-Object System.Collections.ArrayList
    $seen = @{ $InstanceId = $true }
    $frontier = @($InstanceId)
    for ($level = 0; $level -lt $MaxDepth; $level++) {
        $next = New-Object System.Collections.ArrayList
        foreach ($cur in $frontier) {
            foreach ($child in (Get-ResolverChildren -Resolver $Resolver -InstanceId $cur)) {
                if ($seen.ContainsKey($child) -or -not $Resolver.devices.ContainsKey($child)) { continue }
                $seen[$child] = $true
                $null = $found.Add($child); $null = $next.Add($child)
            }
        }
        if ($next.Count -eq 0) { break }
        $frontier = $next
    }
    return $found
}

function Get-Relatives {
    param($Resolver, [string]$InstanceId)
    $found = New-Object System.Collections.ArrayList
    $seen = @{ $InstanceId = $true }
    $d = $Resolver.devices[$InstanceId]
    if ($d.ids.vid -and $d.ids.pid) {
        $key = "$($d.ids.vid):$($d.ids.pid)"
        if ($Resolver.byVidPid.ContainsKey($key)) {
            foreach ($o in $Resolver.byVidPid[$key]) {
                if (-not $seen.ContainsKey($o)) { $seen[$o] = $true; $null = $found.Add($o) }
            }
        }
    }
    if ((Test-RealContainer $d.container_id) -and $Resolver.byContainer.ContainsKey($d.container_id)) {
        foreach ($o in $Resolver.byContainer[$d.container_id]) {
            if (-not $seen.ContainsKey($o)) { $seen[$o] = $true; $null = $found.Add($o) }
        }
    }
    return $found
}

function Get-Kin {
    param($Resolver, [string]$InstanceId)
    $pool = New-Object System.Collections.ArrayList
    foreach ($x in (Get-Descendants -Resolver $Resolver -InstanceId $InstanceId)) { $null = $pool.Add($x) }
    foreach ($x in (Get-Relatives -Resolver $Resolver -InstanceId $InstanceId)) { $null = $pool.Add($x) }
    $kin = New-Object System.Collections.ArrayList
    foreach ($o in $pool) {
        if ($kin.Contains($o)) { continue }
        if (Test-SamePhysicalDevice -Resolver $Resolver -A $InstanceId -B $o) { $null = $kin.Add($o) }
    }
    # Disconnected devices have no child links, so every relative ranks equally
    # and hashtable order would decide the answer.  Sorting makes it stable and
    # puts the primary interface (MI_00) ahead of the secondary ones, which is
    # what the device tree would have said.
    $kin.Sort([StringComparer]::OrdinalIgnoreCase)
    return $kin
}

function Get-VendorNamed {
    param($Resolver, [string]$InstanceId)
    $d = $Resolver.devices[$InstanceId]
    if ($d.friendly_name -and -not (Test-GenericDesc $d.friendly_name)) {
        return @{ name = $d.friendly_name; source = 'FriendlyName' }
    }
    if ($d.bus_reported -and -not (Test-GenericDesc $d.bus_reported)) {
        return @{ name = $d.bus_reported; source = 'BusReportedDeviceDesc' }
    }
    if ($d.description -and -not (Test-GenericDesc $d.description) -and -not (Test-GenericMfg $d.manufacturer)) {
        return @{ name = $d.description; source = 'DeviceDesc' }
    }
    return $null
}

function Resolve-DeviceIdentity {
    param($Resolver, [string]$InstanceId)
    $d = $Resolver.devices[$InstanceId]

    # --- name -------------------------------------------------------------
    $direct = Get-VendorNamed -Resolver $Resolver -InstanceId $InstanceId
    if ($direct) {
        $d.resolved_name = $direct.name
        $d.resolved_from = $direct.source
        $d.resolved_confidence = 'high'
    } else {
        $ownChildren = Get-ResolverChildren -Resolver $Resolver -InstanceId $InstanceId
        $kin = Get-Kin -Resolver $Resolver -InstanceId $InstanceId
        $hit = $null
        foreach ($other in $kin) {
            $hit = Get-VendorNamed -Resolver $Resolver -InstanceId $other
            if ($hit) {
                $d.resolved_name = $hit.name
                $d.resolved_from = "$other ($($hit.source))"
                $d.resolved_confidence = if ($ownChildren -contains $other) { 'high' } else { 'medium' }
                break
            }
        }
        if (-not $hit) {
            $lookup = Get-VendorFromIds -Ids $d.ids
            if ($lookup.vendor -and $lookup.product) {
                $d.resolved_name = "$($lookup.vendor) $($lookup.product)"
                $d.resolved_from = "$($d.ids.id_kind).ids VID_$($d.ids.vid)/PID_$($d.ids.pid)"
                $d.resolved_confidence = 'medium'
            } elseif ($lookup.vendor) {
                $basis = if ($d.description) { $d.description } else { 'device' }
                $d.resolved_name = "$($lookup.vendor) $basis"
                $d.resolved_from = "$($d.ids.id_kind).ids vendor VID_$($d.ids.vid)"
                $d.resolved_confidence = 'low'
            } else {
                $d.resolved_name = if ($d.description) { $d.description } else { $InstanceId }
                $d.resolved_from = 'DeviceDesc'
                $d.resolved_confidence = 'none'
            }
        }
    }

    # --- type -------------------------------------------------------------
    $ownType = Get-OwnType -Resolver $Resolver -InstanceId $InstanceId
    if ($ownType -and ($ownType.how -eq 'HID usage page' -or $script:WeakTypes -notcontains $ownType.type)) {
        $d.device_type = $ownType.type
        $d.type_from = $ownType.how
    } else {
        $ownChildren = Get-ResolverChildren -Resolver $Resolver -InstanceId $InstanceId
        $bestRank = [int]::MaxValue; $bestType = $null; $bestFrom = $null
        foreach ($other in (Get-Kin -Resolver $Resolver -InstanceId $InstanceId)) {
            $t = Get-OwnType -Resolver $Resolver -InstanceId $other
            if (-not $t) { continue }
            $rank = if ($ownChildren -contains $other) { 0 } else { 2 }
            if ($script:WeakTypes -contains $t.type) { $rank += 4 }
            if ($t.how -ne 'HID usage page') { $rank += 1 }
            if ($rank -lt $bestRank) {
                $bestRank = $rank; $bestType = $t.type; $bestFrom = "$other ($($t.how))"
            }
        }
        if ($bestType) {
            $d.device_type = $bestType; $d.type_from = $bestFrom
        } elseif ($ownType) {
            $d.device_type = $ownType.type; $d.type_from = $ownType.how
        } else {
            $fallback = Get-ClassType -ClassName $d.class_name
            if ($fallback) { $d.device_type = $fallback; $d.type_from = 'setup class' }
            else {
                $d.device_type = if ($d.class_name) { $d.class_name } else { 'Unknown' }
                $d.type_from = 'class name'
            }
        }
    }

    # --- vendor -----------------------------------------------------------
    if ($d.manufacturer -and -not (Test-GenericMfg $d.manufacturer)) {
        $d.vendor = $d.manufacturer; $d.vendor_from = 'ManufacturerName'
    } else {
        $found = $false
        foreach ($other in (Get-Kin -Resolver $Resolver -InstanceId $InstanceId)) {
            $om = $Resolver.devices[$other].manufacturer
            if ($om -and -not (Test-GenericMfg $om)) {
                $d.vendor = $om; $d.vendor_from = $other; $found = $true; break
            }
        }
        if (-not $found) {
            $lookup = Get-VendorFromIds -Ids $d.ids
            if ($lookup.vendor) { $d.vendor = $lookup.vendor; $d.vendor_from = "$($d.ids.id_kind).ids" }
            else { $d.vendor = $d.manufacturer; $d.vendor_from = 'ManufacturerName' }
        }
    }
}

function Get-OwnType {
    param($Resolver, [string]$InstanceId)
    $d = $Resolver.devices[$InstanceId]
    $ids = @()
    if ($d.hardware_ids) { $ids += $d.hardware_ids }
    if ($d.compatible_ids) { $ids += $d.compatible_ids }
    $hid = Get-HidUsageType -Ids $ids
    if ($hid) { return @{ type = $hid; how = 'HID usage page' } }
    $own = Get-ClassType -ClassName $d.class_name
    if ($own -and ($script:ContainerClasses -notcontains $d.class_name.ToLowerInvariant())) {
        return @{ type = $own; how = 'setup class' }
    }
    return $null
}

#endregion

#region -------------------------------------------------------------- model

function Test-OemInf {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return $Name.Trim() -match '^oem\d+\.inf$'
}

function Split-DriverVersion {
    param([string]$Text)
    $out = @{ date = $null; version = $null; parts = @() }
    if ([string]::IsNullOrWhiteSpace($Text)) { return $out }
    if ($Text -match '^\s*(\d{1,2}/\d{1,2}/\d{4})\s+(\S+)\s*$') {
        $out.version = $Matches[2]
        $raw = $Matches[1]
        foreach ($fmt in @('MM/dd/yyyy', 'dd/MM/yyyy')) {
            try {
                $parsed = [datetime]::ParseExact($raw, $fmt, [Globalization.CultureInfo]::InvariantCulture)
                $out.date = $parsed.ToString('yyyy-MM-dd')
                break
            } catch { }
        }
        $out.parts = @($out.version.Split('.') | ForEach-Object {
            $n = 0; if ([int]::TryParse($_, [ref]$n)) { $n } else { 0 } })
    } else {
        $out.version = $Text.Trim()
    }
    return $out
}

function Compare-VersionParts {
    param($A, $B)
    $len = [Math]::Max($A.Count, $B.Count)
    for ($i = 0; $i -lt $len; $i++) {
        $x = if ($i -lt $A.Count) { [int]$A[$i] } else { 0 }
        $y = if ($i -lt $B.Count) { [int]$B[$i] } else { 0 }
        if ($x -ne $y) { return $x.CompareTo($y) }
    }
    return 0
}

function Get-StatusLabel {
    param([bool]$Present, [int]$ProblemCode)
    if (-not $Present) { return 'Disconnected' }
    if ($ProblemCode -eq 22) { return 'Disabled' }
    if ($ProblemCode -eq 45) { return 'Disconnected' }
    if ($ProblemCode -ne 0) { return 'Problem' }
    return 'Started'
}

function New-Snapshot {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $devices = Get-DeviceSnapshotRaw
    $pnpRows = Get-PnpUtilDevices

    foreach ($id in @($pnpRows.Keys)) {
        $row = $pnpRows[$id]
        if (-not $devices.ContainsKey($id)) { continue }
        $d = $devices[$id]
        $d.driver_name = $row.driver_name
        $d.extension_drivers = $row.extension_drivers
        if (-not $d.description) { $d.description = $row.description }
        if (-not $d.class_name) { $d.class_name = $row.class_name }
        if (-not $d.manufacturer) { $d.manufacturer = $row.manufacturer }
        if ($row.class_guid -and -not $d.class_guid) { $d.class_guid = $row.class_guid.ToLowerInvariant() }
    }

    foreach ($id in @($devices.Keys)) {
        $d = $devices[$id]
        $d.problem_text = ''
        if ($d.problem_code -ne 0 -and $script:ProblemText.ContainsKey([int]$d.problem_code)) {
            $d.problem_text = $script:ProblemText[[int]$d.problem_code]
        }
        $d.status = Get-StatusLabel -Present ([bool]$d.present) -ProblemCode ([int]$d.problem_code)
    }

    # Get-PnpDevice reports instance IDs upper-cased while the parent/children
    # DEVPKEYs keep the original casing.  PowerShell hashtables ignore case so
    # the backend never notices, but the browser keys a Map on these strings and
    # a Map is case-sensitive -- which silently drops every edge in the tree and
    # graph views.  Canonicalise to the id the index actually holds.
    foreach ($id in @($devices.Keys)) {
        $d = $devices[$id]
        if ($d.parent -and $devices.ContainsKey($d.parent)) {
            $d.parent = $devices[$d.parent].instance_id
        }
        if ($d.children.Count -gt 0) {
            $canonical = @()
            foreach ($c in $d.children) {
                if ($devices.ContainsKey($c)) { $canonical += $devices[$c].instance_id }
                else { $canonical += $c }
            }
            $d.children = $canonical
        }
    }

    $resolver = New-Resolver -Devices $devices
    foreach ($id in @($devices.Keys)) {
        Resolve-DeviceIdentity -Resolver $resolver -InstanceId $id
        $d = $devices[$id]
        $d.children = @(Get-ResolverChildren -Resolver $resolver -InstanceId $id)
        $rel = @(Get-Relatives -Resolver $resolver -InstanceId $id)
        if ($rel.Count -gt 32) { $rel = $rel[0..31] }
        $d.related = $rel
        $d.child_count = $d.children.Count
        $d.class_display = Get-ClassDisplayName -ClassGuid $d.class_guid
        $name = if ($d.driver_name) { $d.driver_name } else { $d.driver_inf }
        $d.driver_is_oem = Test-OemInf $name
        $d.search_blob = (@(
            $d.instance_id, $d.resolved_name, $d.description, $d.friendly_name,
            $d.bus_reported, $d.class_name, $d.class_display, $d.manufacturer,
            $d.vendor, $d.device_type, $d.service, $d.driver_name, $d.driver_inf,
            $d.status, $d.problem_text
        ) + $d.extension_drivers + $d.hardware_ids |
            Where-Object { $_ } ) -join ' '
        $d.search_blob = $d.search_blob.ToLowerInvariant()
    }

    # ---- driver store
    $packages = Get-DriverStore
    $usedBy = @{}
    foreach ($id in @($devices.Keys)) {
        $d = $devices[$id]
        foreach ($inf in (@($d.driver_name, $d.driver_inf) + $d.extension_drivers)) {
            if (-not (Test-OemInf $inf)) { continue }
            $key = $inf.ToLowerInvariant()
            if (-not $usedBy.ContainsKey($key)) { $usedBy[$key] = New-Object System.Collections.ArrayList }
            if (-not $usedBy[$key].Contains($id)) { $null = $usedBy[$key].Add($id) }
        }
    }

    $drivers = New-Object System.Collections.ArrayList
    foreach ($pkg in $packages) {
        $v = Split-DriverVersion -Text $pkg.driver_version
        $linked = New-Object System.Collections.ArrayList
        $key = $pkg.driver_name.ToLowerInvariant()
        if ($usedBy.ContainsKey($key)) { foreach ($x in $usedBy[$key]) { $null = $linked.Add($x) } }
        foreach ($x in $pkg.device_ids_raw) { if (-not $linked.Contains($x)) { $null = $linked.Add($x) } }
        $names = New-Object System.Collections.ArrayList
        $presentCount = 0
        foreach ($x in $linked) {
            if ($devices.ContainsKey($x)) {
                if ($devices[$x].present) { $presentCount++ }
                if ($devices[$x].resolved_name) { $null = $names.Add($devices[$x].resolved_name) }
            }
        }
        $entry = [ordered]@{
            driver_name = $pkg.driver_name; original_name = $pkg.original_name
            provider_name = $pkg.provider_name; class_name = $pkg.class_name
            class_guid = $pkg.class_guid; driver_version = $pkg.driver_version
            signer_name = $pkg.signer_name; attributes = $pkg.attributes
            whcp_version = $pkg.whcp_version; driver_package_id = $pkg.driver_package_id
            family_id = $pkg.family_id; version_date = $v.date; version_number = $v.version
            device_ids = @($linked); device_names = @($names)
            device_count = $linked.Count; present_device_count = $presentCount
            in_use = ($linked.Count -gt 0)
            is_extension = ($pkg.class_name -eq 'Extension')
            orphaned = ($linked.Count -eq 0)
            superseded_by = ''; family_members = @()
            search_blob = ''
            _parts = $v.parts
        }
        $entry.search_blob = ((@($pkg.driver_name, $pkg.original_name, $pkg.provider_name,
            $pkg.class_name, $pkg.driver_version, $pkg.signer_name, $pkg.driver_package_id,
            $pkg.family_id) + $pkg.attributes + @($names)) |
            Where-Object { $_ }) -join ' '
        $entry.search_blob = $entry.search_blob.ToLowerInvariant()
        $null = $drivers.Add($entry)
    }

    # older copies of the same package still sitting in the store
    $families = @{}
    foreach ($e in $drivers) {
        $key = $e.family_id
        if (-not $key) { $key = $e.original_name }
        if (-not $key) { $key = $e.driver_name }
        $key = $key.ToLowerInvariant()
        if (-not $families.ContainsKey($key)) { $families[$key] = New-Object System.Collections.ArrayList }
        $null = $families[$key].Add($e)
    }
    foreach ($key in $families.Keys) {
        $members = @($families[$key])
        if ($members.Count -lt 2) { continue }
        # Sort-Object cannot order integer arrays, so compare the version
        # tuples explicitly: newest package first.
        $sorted = @($members)
        for ($i = 0; $i -lt $sorted.Count; $i++) {
            for ($j = $i + 1; $j -lt $sorted.Count; $j++) {
                if ((Compare-VersionParts -A $sorted[$j]._parts -B $sorted[$i]._parts) -gt 0) {
                    $tmp = $sorted[$i]; $sorted[$i] = $sorted[$j]; $sorted[$j] = $tmp
                }
            }
        }
        $names = @($sorted | ForEach-Object { $_.driver_name })
        foreach ($m in $sorted) { $m.family_members = $names }
        for ($i = 1; $i -lt $sorted.Count; $i++) { $sorted[$i].superseded_by = $sorted[0].driver_name }
    }
    foreach ($e in $drivers) { $e.Remove('_parts') }

    $deviceList = @($devices.Values | Sort-Object -Property instance_id)
    $driverList = @($drivers | Sort-Object -Property @{ Expression = {
        if ($_.driver_name -match '^oem(\d+)\.inf$') { [int]$Matches[1] } else { 1000000 } } })

    $present = @($deviceList | Where-Object { $_.present }).Count
    $problems = @($deviceList | Where-Object { $_.problem_code -ne 0 }).Count
    $orphans = @($driverList | Where-Object { $_.orphaned }).Count
    $superseded = @($driverList | Where-Object { $_.superseded_by }).Count

    return @{
        devices = $deviceList
        drivers = $driverList
        index = $devices
        driverIndex = $(
            $ix = @{}
            foreach ($e in $driverList) { $ix[$e.driver_name.ToLowerInvariant()] = $e }
            $ix)
        resolver = $resolver
        meta = [ordered]@{
            generated_at = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
            device_count = $deviceList.Count
            present_count = $present
            ghost_count = ($deviceList.Count - $present)
            problem_count = $problems
            driver_count = $driverList.Count
            orphan_driver_count = $orphans
            superseded_driver_count = $superseded
            scan_ms = $sw.ElapsedMilliseconds
            warnings = @()
            backend = 'powershell'
        }
    }
}

$script:Snapshot = $null
function Get-Snapshot {
    param([switch]$Refresh)
    if ($Refresh -or -not $script:Snapshot) { $script:Snapshot = New-Snapshot }
    return $script:Snapshot
}

#endregion

#region ------------------------------------------------------------- actions

function Assert-OemInf {
    param([string]$Name)
    $trimmed = "$Name".Trim()
    if ($trimmed -notmatch '^oem\d+\.inf$') {
        throw "'$trimmed' is not a driver-store package name; expected e.g. oem42.inf"
    }
    return $trimmed.ToLowerInvariant()
}

function Assert-InstanceId {
    param([string]$InstanceId, $Known)
    $trimmed = "$InstanceId".Trim()
    if ($trimmed -notmatch '^[A-Za-z0-9_\-.\\{}&#+ ]{3,400}$') {
        throw "'$trimmed' is not a valid device instance ID"
    }
    if ($Known -and -not $Known.ContainsKey($trimmed)) {
        throw "'$trimmed' is not in the current snapshot; refresh and retry"
    }
    return $trimmed
}

# pnputil returns SetupAPI codes, which surface as large negative numbers.
# Only entries confirmed on a real machine (or plain Win32) are named.
$script:ExitCodeText = @{
    0 = 'succeeded'
    3010 = 'succeeded, reboot required'
    2 = 'file not found'
    5 = 'access denied -- needs administrator'
    87 = 'invalid parameter'
    1223 = 'the UAC prompt was declined'
    -536870340 = 'not an installed OEM INF (already deleted?)'   # 0xE000023C
    -536870339 = 'still in use by the system'                    # 0xE000023D
}

function Get-PnpExitReason {
    param([int]$Code)
    if ($script:ExitCodeText.ContainsKey($Code)) { return $script:ExitCodeText[$Code] }
    if ($Code -lt 0) {
        $u = [BitConverter]::ToUInt32([BitConverter]::GetBytes($Code), 0)
        # The L suffix matters: PowerShell reads a bare 0xE0000000 as a
        # *negative* Int32, which makes the range test silently false.
        if ($u -ge [uint32]0xE0000000L -and $u -le [uint32]0xE0000FFFL) {
            return ('SetupAPI error 0x{0:X8}' -f $u)
        }
        return ('error 0x{0:X8}' -f $u)
    }
    return "exit $Code"
}

function Remove-PnpBanner {
    <#  pnputil prints "Microsoft PnP Utility" first; the useful line follows.  #>
    param([string]$Text)
    if (-not $Text) { return '' }
    return ($Text -replace '(?im)^\s*Microsoft PnP Utility\s*\r?\n\s*\r?\n?', '').Trim()
}

function New-PnpBatchScript {
    <#
        Writes a .cmd that runs each pnputil call and records its own exit code.

        Handing the whole pipeline to `cmd /c` as one argument does not survive
        cmd's quote-stripping rule -- a string that starts with a quote and
        holds several more comes back as "The filename, directory name, or
        volume label syntax is incorrect". A script file has no such rule, and
        it lets a batch run behind a single UAC prompt rather than one prompt
        per package.
    #>
    param([object[]]$Commands, [string]$OutPath)
    $script = Join-Path ([System.IO.Path]::GetTempPath()) ("dcc_run_" + [guid]::NewGuid().ToString('N') + ".cmd")
    $lines = New-Object System.Collections.ArrayList
    $null = $lines.Add('@echo off')
    for ($i = 0; $i -lt $Commands.Count; $i++) {
        $quoted = (@($Commands[$i]) | ForEach-Object { '"' + ($_ -replace '"', '""') + '"' }) -join ' '
        $null = $lines.Add('echo.>> "' + $OutPath + '"')
        $null = $lines.Add('"' + $script:PnpUtilPath + '" ' + $quoted + ' >> "' + $OutPath + '" 2>&1')
        # %ERRORLEVEL% expands as each line is read, so this catches the call above it.
        $null = $lines.Add('echo __DCC_ITEM__' + $i + ':%ERRORLEVEL%>> "' + $OutPath + '"')
    }
    Set-Content -LiteralPath $script -Value ($lines -join "`r`n") -Encoding ASCII
    return $script
}

function Split-PnpBatchOutput {
    param([string]$Text, [object[]]$Commands)
    $results = New-Object System.Collections.ArrayList
    $marks = [regex]::Matches($Text, '__DCC_ITEM__(\d+):(-?\d+)')
    $codes = @{}
    $bodies = @{}
    $cursor = 0
    foreach ($m in $marks) {
        $index = [int]$m.Groups[1].Value
        $codes[$index] = [int]$m.Groups[2].Value
        $bodies[$index] = $Text.Substring($cursor, $m.Index - $cursor)
        $cursor = $m.Index + $m.Length
    }
    for ($i = 0; $i -lt $Commands.Count; $i++) {
        $code = if ($codes.ContainsKey($i)) { $codes[$i] } else { -1 }
        $body = if ($bodies.ContainsKey($i)) { $bodies[$i].Trim() } else { '' }
        if (-not $body) { $body = if ($code -eq -1) { 'did not run' } else { '(no output)' } }
        $null = $results.Add(@{
            command = "pnputil $(@($Commands[$i]) -join ' ')"
            returncode = $code
            ok = ($code -eq 0 -or $code -eq 3010)
            reboot_required = ($code -eq 3010)
            reason = $(if ($code -eq -1) { 'did not run' } else { Get-PnpExitReason -Code $code })
            elevated = $true
            output = (Remove-PnpBanner -Text $body)
        })
    }
    return $results
}

function Invoke-PnpActionBatch {
    <#  Runs every command, elevating once for the whole batch when needed.  #>
    param([object[]]$Commands)
    if (-not $Commands -or $Commands.Count -eq 0) { return @() }

    if (Test-Elevated) {
        $results = New-Object System.Collections.ArrayList
        foreach ($cmd in $Commands) {
            $out = & $script:PnpUtilPath @cmd 2>&1 | Out-String
            $code = $LASTEXITCODE
            $cleaned = Remove-PnpBanner -Text $out
            $null = $results.Add(@{
                command = "pnputil $(@($cmd) -join ' ')"
                returncode = $code
                ok = ($code -eq 0 -or $code -eq 3010)
                reboot_required = ($code -eq 3010)
                reason = (Get-PnpExitReason -Code $code)
                elevated = $true
                output = $(if ($cleaned) { $cleaned } else { '(no output)' })
            })
        }
        return $results
    }

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dcc_elev_" + [guid]::NewGuid().ToString('N') + ".txt")
    Set-Content -LiteralPath $tmp -Value '' -NoNewline
    $scriptPath = New-PnpBatchScript -Commands $Commands -OutPath $tmp
    try {
        Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', "`"$scriptPath`"") -Verb RunAs `
            -WindowStyle Hidden -Wait -ErrorAction Stop | Out-Null
        $text = ''
        if (Test-Path -LiteralPath $tmp) { $text = Get-Content -LiteralPath $tmp -Raw }
        if (-not $text -or $text -notmatch '__DCC_ITEM__') {
            # Nothing ran at all: almost always a declined UAC prompt.
            return @($Commands | ForEach-Object {
                @{ command = "pnputil $(@($_) -join ' ')"; returncode = 1223; ok = $false
                   reboot_required = $false; elevated = $true; reason = 'the UAC prompt was declined'
                   output = 'Elevation was cancelled.' } })
        }
        return Split-PnpBatchOutput -Text $text -Commands $Commands
    } catch {
        return @($Commands | ForEach-Object {
            @{ command = "pnputil $(@($_) -join ' ')"; returncode = 1223; ok = $false
               reboot_required = $false; elevated = $true; reason = 'the UAC prompt was declined'
               output = 'Elevation was cancelled.' } })
    } finally {
        foreach ($f in @($tmp, $scriptPath)) {
            if ($f -and (Test-Path -LiteralPath $f)) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
        }
    }
}

function Invoke-PnpAction {
    param([string[]]$Arguments)
    return (Invoke-PnpActionBatch -Commands @(, $Arguments))[0]
}

function Invoke-DeviceAction {
    param([string]$Verb, [string]$InstanceId, $Known, [switch]$WithSubtree)
    if (@('enable-device', 'disable-device', 'restart-device', 'remove-device') -notcontains $Verb) {
        throw "unsupported device action '$Verb'"
    }
    $id = Assert-InstanceId -InstanceId $InstanceId -Known $Known
    $argList = @("/$Verb", $id)
    if ($Verb -eq 'remove-device' -and $WithSubtree) { $argList += '/subtree' }
    return Invoke-PnpAction -Arguments $argList
}

#endregion

#region ---------------------------------------------------------------- http

function Get-WebRoot {
    foreach ($candidate in @((Join-Path $script:Root 'web'),
                             (Join-Path (Split-Path $script:Root -Parent) 'dcc\web'))) {
        if (Test-Path (Join-Path $candidate 'index.html')) { return $candidate }
    }
    return $null
}

function New-SessionToken {
    $bytes = New-Object byte[] 24
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    return ([Convert]::ToBase64String($bytes) -replace '\+', '-' -replace '/', '_' -replace '=', '')
}

function ConvertTo-JsonSafe {
    param($Value, [int]$MaxDepth = 8)
    return ($Value | ConvertTo-Json -Depth $MaxDepth -Compress)
}

function Read-HttpRequest {
    param($Stream)
    $ms = New-Object System.IO.MemoryStream
    $buffer = New-Object byte[] 8192
    $headerEnd = -1
    while ($headerEnd -lt 0) {
        $read = $Stream.Read($buffer, 0, $buffer.Length)
        if ($read -le 0) { return $null }
        $ms.Write($buffer, 0, $read)
        $bytes = $ms.ToArray()
        for ($i = 3; $i -lt $bytes.Length; $i++) {
            if ($bytes[$i - 3] -eq 13 -and $bytes[$i - 2] -eq 10 -and
                $bytes[$i - 1] -eq 13 -and $bytes[$i] -eq 10) { $headerEnd = $i; break }
        }
        if ($ms.Length -gt 262144) { return $null }
    }
    $all = $ms.ToArray()
    $headText = [Text.Encoding]::UTF8.GetString($all, 0, $headerEnd + 1)
    $lines = $headText -split "`r`n"
    $parts = $lines[0] -split ' '
    if ($parts.Count -lt 2) { return $null }

    $request = @{ method = $parts[0].ToUpperInvariant(); path = $parts[1]
                  query = @{}; headers = @{}; body = '' }
    if ($request.path.Contains('?')) {
        $q = $request.path.Substring($request.path.IndexOf('?') + 1)
        $request.path = $request.path.Substring(0, $request.path.IndexOf('?'))
        foreach ($pair in ($q -split '&')) {
            if (-not $pair) { continue }
            $eq = $pair.IndexOf('=')
            if ($eq -lt 0) { $request.query[[Uri]::UnescapeDataString($pair)] = '' }
            else {
                $k = [Uri]::UnescapeDataString($pair.Substring(0, $eq))
                $v = [Uri]::UnescapeDataString(($pair.Substring($eq + 1) -replace '\+', ' '))
                $request.query[$k] = $v
            }
        }
    }
    $request.path = [Uri]::UnescapeDataString($request.path)

    for ($i = 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if (-not $line) { continue }
        $colon = $line.IndexOf(':')
        if ($colon -le 0) { continue }
        $request.headers[$line.Substring(0, $colon).Trim().ToLowerInvariant()] = $line.Substring($colon + 1).Trim()
    }

    $length = 0
    if ($request.headers.ContainsKey('content-length')) {
        [void][int]::TryParse($request.headers['content-length'], [ref]$length)
    }
    if ($length -gt 0) {
        $bodyBytes = New-Object byte[] $length
        $have = $all.Length - ($headerEnd + 1)
        if ($have -gt 0) { [Array]::Copy($all, $headerEnd + 1, $bodyBytes, 0, [Math]::Min($have, $length)) }
        $got = [Math]::Min($have, $length)
        while ($got -lt $length) {
            $read = $Stream.Read($bodyBytes, $got, $length - $got)
            if ($read -le 0) { break }
            $got += $read
        }
        $request.body = [Text.Encoding]::UTF8.GetString($bodyBytes, 0, $got)
    }
    return $request
}

function Write-HttpResponse {
    param($Stream, $Request, [int]$StatusCode, [string]$ContentType, [byte[]]$Body, $Extra)
    $texts = @{ 200 = 'OK'; 400 = 'Bad Request'; 403 = 'Forbidden'
                404 = 'Not Found'; 405 = 'Method Not Allowed'; 500 = 'Internal Server Error' }
    $reason = if ($texts.ContainsKey($StatusCode)) { $texts[$StatusCode] } else { 'OK' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("HTTP/1.1 $StatusCode $reason`r`n")
    [void]$sb.Append("Content-Type: $ContentType`r`n")
    [void]$sb.Append("Content-Length: $($Body.Length)`r`n")
    [void]$sb.Append("Cache-Control: no-store`r`n")
    [void]$sb.Append("X-Content-Type-Options: nosniff`r`n")
    [void]$sb.Append("Referrer-Policy: no-referrer`r`n")
    [void]$sb.Append("Connection: close`r`n")
    if ($Extra) { foreach ($k in $Extra.Keys) { [void]$sb.Append("$k`: $($Extra[$k])`r`n") } }
    [void]$sb.Append("`r`n")
    $head = [Text.Encoding]::UTF8.GetBytes($sb.ToString())
    $Stream.Write($head, 0, $head.Length)
    if ($Request.method -ne 'HEAD' -and $Body.Length -gt 0) { $Stream.Write($Body, 0, $Body.Length) }
    $Stream.Flush()
}

function New-JsonResponse {
    param($Value, [int]$StatusCode = 200)
    return @{ status = $StatusCode; type = 'application/json; charset=utf-8'
              body = [Text.Encoding]::UTF8.GetBytes((ConvertTo-JsonSafe -Value $Value)); extra = @{} }
}

function New-ErrorResponse {
    param([string]$Message, [int]$StatusCode = 400)
    return New-JsonResponse -Value @{ error = $Message } -StatusCode $StatusCode
}

function Get-DeviceBrief {
    param($Snapshot, [string]$Id)
    $m = [ordered]@{ instance_id = $Id; resolved_name = ''; description = ''
                     status = 'Unknown'; device_type = '' }
    if ($Snapshot.index.ContainsKey($Id)) {
        $d = $Snapshot.index[$Id]
        $m.resolved_name = $d.resolved_name; $m.description = $d.description
        $m.status = $d.status; $m.device_type = $d.device_type
    }
    return $m
}

function Invoke-ApiRoute {
    param($Request)

    $hostHeader = ''
    if ($Request.headers.ContainsKey('host')) { $hostHeader = $Request.headers['host'] }
    $hostHeader = ($hostHeader -split ':')[0]
    if (@('127.0.0.1', 'localhost') -notcontains $hostHeader) { return New-ErrorResponse 'bad host' 403 }

    $path = $Request.path
    $webRoot = Get-WebRoot

    if ($path -eq '/' -or $path -eq '/index.html') {
        if (-not $webRoot) { return New-ErrorResponse 'web assets not found' 500 }
        $script:PageLoads++
        if ($script:PageLoads -eq 1) { Write-ConsoleLog 'Browser connected. The console is running.' }
        $html = Get-Content -LiteralPath (Join-Path $webRoot 'index.html') -Raw -Encoding UTF8
        $html = $html.Replace('__DCC_TOKEN__', $script:Token)
        return @{ status = 200; type = 'text/html; charset=utf-8'
                  body = [Text.Encoding]::UTF8.GetBytes($html); extra = @{} }
    }

    if ($path.StartsWith('/static/')) {
        if (-not $webRoot) { return New-ErrorResponse 'web assets not found' 500 }
        $name = $path.Substring(8)
        if ($name.Contains('/') -or $name.Contains('\') -or $name.Contains('..')) {
            return New-ErrorResponse 'forbidden' 403
        }
        $file = Join-Path $webRoot $name
        if (-not (Test-Path -LiteralPath $file)) { return New-ErrorResponse 'not found' 404 }
        $type = 'application/octet-stream'
        if ($name.EndsWith('.js')) { $type = 'text/javascript; charset=utf-8' }
        elseif ($name.EndsWith('.css')) { $type = 'text/css; charset=utf-8' }
        return @{ status = 200; type = $type
                  body = [IO.File]::ReadAllBytes($file); extra = @{} }
    }

    if (-not $path.StartsWith('/api/')) { return New-ErrorResponse 'not found' 404 }

    $given = ''
    if ($Request.headers.ContainsKey('x-dcc-token')) { $given = $Request.headers['x-dcc-token'] }
    if (-not $given -and $Request.query.ContainsKey('token')) { $given = $Request.query['token'] }
    if ($given -ne $script:Token) { return New-ErrorResponse 'bad or missing token' 403 }

    try {
        if ($Request.method -eq 'GET' -or $Request.method -eq 'HEAD') {
            switch ($path) {
                '/api/snapshot' {
                    $refresh = ($Request.query.ContainsKey('refresh') -and $Request.query['refresh'] -eq '1')
                    $snap = Get-Snapshot -Refresh:$refresh
                    $meta = Copy-OrderedMap -Map $snap.meta
                    $meta['elevated'] = (Test-Elevated)
                    $meta['hwids'] = Get-HwIdsStatus
                    return New-JsonResponse @{ meta = $meta; devices = $snap.devices; drivers = $snap.drivers }
                }
                '/api/ping' {
                    return New-JsonResponse @{ ok = $true; elevated = (Test-Elevated)
                        pid = $PID; elevation_declined = $false; backend = 'powershell' }
                }
                '/api/hwids' { return New-JsonResponse (Get-HwIdsStatus) }
                '/api/device' {
                    $id = ''
                    if ($Request.query.ContainsKey('id')) { $id = $Request.query['id'] }
                    $snap = Get-Snapshot
                    if (-not $snap.index.ContainsKey($id)) { return New-ErrorResponse "unknown device '$id'" 404 }
                    $d = $snap.index[$id]
                    # Absent devices are skipped by the bulk scan; fill this one in
                    # now, then resolve again so the pane reports the better source.
                    $wasEnriched = $d._enriched
                    Update-DeviceDetail -InstanceId $id -Device $d
                    if (-not $wasEnriched -and $d._enriched) {
                        Resolve-DeviceIdentity -Resolver $snap.resolver -InstanceId $id
                    }
                    $drivers = @()
                    foreach ($name in (@($d.driver_name) + $d.extension_drivers)) {
                        if (-not $name) { continue }
                        $inStore = $snap.driverIndex.ContainsKey($name.ToLowerInvariant())
                        $pkg = if ($inStore) { $snap.driverIndex[$name.ToLowerInvariant()] } else { $null }
                        $drivers += [ordered]@{
                            driver_name = $name; in_store = $inStore
                            original_name = $(if ($pkg) { $pkg.original_name } else { '' })
                            provider_name = $(if ($pkg) { $pkg.provider_name } else { '' })
                            driver_version = $(if ($pkg) { $pkg.driver_version } else { '' })
                            signer_name = $(if ($pkg) { $pkg.signer_name } else { '' })
                            device_count = $(if ($pkg) { $pkg.device_count } else { 0 })
                            is_extension = ($name -ne $d.driver_name)
                        }
                    }
                    $props = [ordered]@{}
                    foreach ($k in @('description','friendly_name','bus_reported','class_name',
                        'class_guid','manufacturer','service','driver_inf','driver_version',
                        'driver_provider','location','container_id','install_date',
                        'last_arrival','last_removal','hardware_ids','compatible_ids')) {
                        if ($d[$k]) { $props[$k] = $d[$k] }
                    }
                    $parent = $null
                    if ($d.parent -and $snap.index.ContainsKey($d.parent)) {
                        $parent = Get-DeviceBrief -Snapshot $snap -Id $d.parent
                    }
                    return New-JsonResponse @{
                        summary = $d; properties = $props; parent = $parent
                        children = @($d.children | ForEach-Object { Get-DeviceBrief -Snapshot $snap -Id $_ })
                        related = @($d.related | ForEach-Object { Get-DeviceBrief -Snapshot $snap -Id $_ })
                        drivers = $drivers
                    }
                }
                '/api/driver' {
                    $name = ''
                    if ($Request.query.ContainsKey('name')) { $name = $Request.query['name'] }
                    $snap = Get-Snapshot
                    $key = "$name".ToLowerInvariant()
                    if (-not $snap.driverIndex.ContainsKey($key)) {
                        return New-ErrorResponse "unknown driver package '$name'" 404
                    }
                    $pkg = $snap.driverIndex[$key]
                    $devs = @()
                    foreach ($id in $pkg.device_ids) {
                        $b = Get-DeviceBrief -Snapshot $snap -Id $id
                        $b['class_name'] = ''
                        $b['is_extension_use'] = $false
                        if ($snap.index.ContainsKey($id)) {
                            $b['class_name'] = $snap.index[$id].class_name
                            $b['is_extension_use'] = ($snap.index[$id].extension_drivers -contains $pkg.driver_name)
                        }
                        $devs += $b
                    }
                    return New-JsonResponse @{ driver = $pkg; devices = $devs }
                }
                '/api/export' {
                    $what = 'devices'
                    if ($Request.query.ContainsKey('what')) { $what = $Request.query['what'] }
                    $fmt = 'csv'
                    if ($Request.query.ContainsKey('format')) { $fmt = $Request.query['format'] }
                    return New-ExportResponse -What $what -Format $fmt
                }
            }
            return New-ErrorResponse 'unknown endpoint' 404
        }

        if ($Request.method -eq 'POST') {
            $payload = @{}
            if ($Request.body) {
                try {
                    $obj = $Request.body | ConvertFrom-Json
                    foreach ($p in $obj.PSObject.Properties) { $payload[$p.Name] = $p.Value }
                } catch { return New-ErrorResponse 'body is not valid JSON' 400 }
            }
            switch ($path) {
                '/api/refresh' { $script:Snapshot = $null; return New-JsonResponse @{ ok = $true } }
                '/api/shutdown' { $script:StopRequested = $true; return New-JsonResponse @{ ok = $true } }
                '/api/relaunch-admin' {
                    if (Test-Elevated) { return New-JsonResponse @{ ok = $true; already = $true } }
                    $script:RestartElevated = $true
                    $script:StopRequested = $true
                    return New-JsonResponse @{ ok = $true; already = $false }
                }
                '/api/hwids/update' {
                    $res = Update-HwIdsTables
                    $script:Snapshot = $null
                    return New-JsonResponse @{ results = $res; status = (Get-HwIdsStatus) }
                }
                '/api/action' {
                    $verb = ''
                    if ($payload.ContainsKey('verb')) { $verb = "$($payload['verb'])" }
                    $snap = Get-Snapshot
                    $get = { param($k) if ($payload.ContainsKey($k)) { $payload[$k] } else { $null } }
                    $flag = { param($k) if ($payload.ContainsKey($k)) { [bool]$payload[$k] } else { $false } }
                    switch ($verb) {
                        'delete-driver' {
                            $wanted = @()
                            if ($payload.ContainsKey('driver_names') -and $payload['driver_names']) {
                                $wanted = @($payload['driver_names'])
                            } elseif (& $get 'driver_name') {
                                $wanted = @((& $get 'driver_name'))
                            }
                            if ($wanted.Count -eq 0) { throw 'no driver packages given' }
                            # Validate every name first: one bad entry must not
                            # leave half a batch deleted.
                            $names = @($wanted | ForEach-Object { Assert-OemInf $_ })
                            $cmds = @($names | ForEach-Object {
                                $a = @('/delete-driver', $_)
                                if (& $flag 'uninstall') { $a += '/uninstall' }
                                if (& $flag 'force') { $a += '/force' }
                                if (& $flag 'reboot') { $a += '/reboot' }
                                , $a
                            })
                            $batch = @(Invoke-PnpActionBatch -Commands $cmds)
                            for ($i = 0; $i -lt $names.Count; $i++) { $batch[$i]['driver_name'] = $names[$i] }
                            $okCount = @($batch | Where-Object { $_.ok }).Count
                            $r = @{
                                verb = 'delete-driver'; count = $names.Count
                                succeeded = $okCount; failed = ($names.Count - $okCount)
                                ok = ($okCount -eq $names.Count)
                                reboot_required = (@($batch | Where-Object { $_.reboot_required }).Count -gt 0)
                                elevated = $true; results = $batch
                                command = "pnputil /delete-driver x$($names.Count)"
                                output = (($batch | ForEach-Object { "$($_.driver_name): $($_.reason)" }) -join "`n")
                            }
                        }
                        'export-driver' {
                            $name = Assert-OemInf (& $get 'driver_name')
                            $dir = "$(& $get 'target_dir')"
                            if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
                                throw "'$dir' is not an existing directory"
                            }
                            $r = Invoke-PnpAction -Arguments @('/export-driver', $name, (Resolve-Path -LiteralPath $dir).Path)
                        }
                        'add-driver' {
                            $inf = "$(& $get 'inf_path')"
                            if (-not ($inf.ToLowerInvariant().EndsWith('.inf')) -or -not (Test-Path -LiteralPath $inf -PathType Leaf)) {
                                throw "'$inf' is not an existing .inf file"
                            }
                            $a = @('/add-driver', (Resolve-Path -LiteralPath $inf).Path)
                            if (& $flag 'subdirs') { $a += '/subdirs' }
                            if (& $flag 'install') { $a += '/install' }
                            $r = Invoke-PnpAction -Arguments $a
                        }
                        'scan-devices' { $r = Invoke-PnpAction -Arguments @('/scan-devices') }
                        default {
                            if (@('enable-device','disable-device','restart-device','remove-device') -contains $verb) {
                                $r = Invoke-DeviceAction -Verb $verb -InstanceId "$(& $get 'instance_id')" `
                                        -Known $snap.index -WithSubtree:([bool](& $flag 'subtree'))
                            } else { return New-ErrorResponse "unsupported action '$verb'" 400 }
                        }
                    }
                    $script:Snapshot = $null
                    return New-JsonResponse $r
                }
            }
            return New-ErrorResponse 'unknown endpoint' 404
        }
        return New-ErrorResponse 'method not allowed' 405
    } catch {
        return New-ErrorResponse "$($_.Exception.Message)" 400
    }
}

$script:DeviceExportColumns = @(
    @('instance_id','Instance ID'), @('resolved_name','Resolved Device'), @('device_type','Type'),
    @('description','Device Description'), @('class_name','Class Name'), @('class_guid','Class GUID'),
    @('manufacturer','Manufacturer Name'), @('vendor','Resolved Vendor'), @('status','Status'),
    @('problem_text','Problem'), @('driver_name','Driver Name'),
    @('extension_drivers','Extension Driver Names'), @('service','Service'),
    @('driver_version','Driver Version'), @('location','Location'),
    @('last_arrival','Last Arrival'), @('last_removal','Last Removal'),
    @('resolved_from','Name Resolved From')
)
$script:DriverExportColumns = @(
    @('driver_name','Published Name'), @('original_name','Original Name'),
    @('provider_name','Provider Name'), @('class_name','Class Name'), @('class_guid','Class GUID'),
    @('driver_version','Driver Version'), @('signer_name','Signer Name'),
    @('attributes','Attributes'), @('driver_package_id','Driver Package ID'),
    @('family_id','Family ID'), @('device_count','Devices Using'),
    @('present_device_count','Connected Devices'), @('orphaned','Orphaned'),
    @('superseded_by','Superseded By'), @('device_names','Device Names')
)

function ConvertTo-CsvCell {
    param($Value)
    $text = ''
    if ($null -eq $Value) { $text = '' }
    elseif ($Value -is [bool]) { $text = if ($Value) { 'yes' } else { 'no' } }
    elseif ($Value -is [array]) { $text = ($Value -join '; ') }
    else { $text = "$Value" }
    if ($text -match '[",\r\n]') { return '"' + ($text -replace '"', '""') + '"' }
    return $text
}

function New-ExportResponse {
    param([string]$What, [string]$Format)
    $snap = Get-Snapshot
    $rows = if ($What -eq 'devices') { $snap.devices } else { $snap.drivers }
    $columns = if ($What -eq 'devices') { $script:DeviceExportColumns } else { $script:DriverExportColumns }
    if ($Format -eq 'json') {
        $r = New-JsonResponse $rows
        $r.extra['Content-Disposition'] = "attachment; filename=`"$What.json`""
        return $r
    }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append((($columns | ForEach-Object { ConvertTo-CsvCell $_[1] }) -join ',')).Append("`r`n")
    foreach ($row in $rows) {
        $cells = foreach ($c in $columns) { ConvertTo-CsvCell $row[$c[0]] }
        [void]$sb.Append(($cells -join ',')).Append("`r`n")
    }
    $bytes = [Text.Encoding]::UTF8.GetPreamble() + [Text.Encoding]::UTF8.GetBytes($sb.ToString())
    return @{ status = 200; type = 'text/csv'; body = $bytes
              extra = @{ 'Content-Disposition' = "attachment; filename=`"$What.csv`"" } }
}

function Get-HwIdsStatus {
    $out = [ordered]@{}
    foreach ($name in @('usb.ids', 'pci.ids')) {
        $path = Join-Path (Get-HwIdsCacheDir) $name
        $exists = Test-Path -LiteralPath $path
        $table = Get-HwIdsTable -Path $path
        $count = if ($table) { $table.Count } elseif ($name -eq 'usb.ids') { $script:SeedUsbVendors.Count } else { $script:SeedPciVendors.Count }
        $out[$name] = [ordered]@{
            path = $path; downloaded = $exists
            size = $(if ($exists) { (Get-Item -LiteralPath $path).Length } else { 0 })
            mtime = $(if ($exists) { (Get-Item -LiteralPath $path).LastWriteTime.ToString('s') } else { $null })
            vendors = $count
        }
    }
    return $out
}

function Update-HwIdsTables {
    $sources = @{ 'usb.ids' = 'http://www.linux-usb.org/usb.ids'
                  'pci.ids' = 'https://pci-ids.ucw.cz/v2.2/pci.ids' }
    $results = [ordered]@{}
    foreach ($name in $sources.Keys) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $dest = Join-Path (Get-HwIdsCacheDir) $name
            Invoke-WebRequest -Uri $sources[$name] -OutFile $dest -UseBasicParsing -TimeoutSec 60
            $script:HwIdsCache.Remove($dest)
            $table = Get-HwIdsTable -Path $dest
            $results[$name] = @{ ok = $true; bytes = (Get-Item -LiteralPath $dest).Length
                                 vendors = $(if ($table) { $table.Count } else { 0 }) }
        } catch {
            $results[$name] = @{ ok = $false; error = "$($_.Exception.Message)" }
        }
    }
    return $results
}

#endregion

#region ----------------------------------------------------------- console io

$script:PageLoads = 0
$script:StopRequested = $false
$script:RestartElevated = $false
$script:Token = ''

function Write-ConsoleLog {
    param([string]$Message)
    Write-Host ("  " + (Get-Date).ToString('HH:mm:ss') + "  " + $Message)
}

function Test-OwnsConsoleWindow {
    <#
        A script started by double-clicking its launcher owns its console, and
        Windows destroys that console the moment the process exits -- so any
        error flashes past unreadably.  Started from an existing terminal there
        is nothing to hold and pausing would only be in the way.
    #>
    try {
        $parent = (Get-CimInstance Win32_Process -Filter "ProcessId = $PID" -ErrorAction Stop).ParentProcessId
        $name = (Get-Process -Id $parent -ErrorAction Stop).ProcessName
        return @('explorer', 'cmd') -contains $name.ToLowerInvariant()
    } catch { return $false }
}

function Suspend-ForReader {
    param([string]$Reason = '')
    if (-not (Test-OwnsConsoleWindow)) { return }
    Write-Host ''
    if ($Reason) { Write-Host $Reason }
    Write-Host 'Press Enter to close this window...'
    try { [void](Read-Host) } catch { }
}

#endregion

#region ---------------------------------------------------------- serve loop

function Start-Console {
    param([int]$ListenPort, [switch]$SkipBrowser, [string]$TokenPath)

    if ($TokenPath) {
        # Written by the instance that asked for elevation; read once, then gone.
        try { $script:Token = (Get-Content -LiteralPath $TokenPath -Raw).Trim() } catch { }
        try { Remove-Item -LiteralPath $TokenPath -Force -ErrorAction SilentlyContinue } catch { }
    }
    if (-not $script:Token) { $script:Token = New-SessionToken }

    $webRoot = Get-WebRoot
    if (-not $webRoot) {
        Write-Host 'Could not find the web assets (index.html, app.js, style.css).'
        Write-Host "Looked in:  $(Join-Path $script:Root 'web')"
        Write-Host "        and $(Join-Path (Split-Path $script:Root -Parent) 'dcc\web')"
        Suspend-ForReader 'Nothing to serve.'
        return 1
    }

    $url = "http://127.0.0.1:$ListenPort/?token=$($script:Token)"
    Write-Host "Device Control Console $($script:Version) (PowerShell)"
    Write-Host "  URL         : $url"
    Write-Host "  Web assets  : $webRoot"
    Write-Host "  Elevated    : $(if (Test-Elevated) { 'yes' } else { 'no (write actions will prompt for UAC)' })"
    Write-Host "  Stop        : Ctrl+C, or just close this window"
    Write-Host ''
    Write-Host '  Scanning devices...'

    $snap = Get-Snapshot -Refresh
    Write-ConsoleLog ("Ready: $($snap.meta.device_count) devices, $($snap.meta.driver_count) driver packages " +
        "($($snap.meta.orphan_driver_count) orphaned) in $($snap.meta.scan_ms) ms.")
    Write-ConsoleLog 'Waiting for the browser. If it did not open, paste the URL above.'

    if (-not $SkipBrowser) { try { Start-Process $url | Out-Null } catch { } }

    while ($true) {
        $listener = $null
        try {
            $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $ListenPort)
            $listener.ExclusiveAddressUse = $true
            $listener.Start(64)
        } catch {
            Write-Host ''
            Write-Host "Could not listen on port $ListenPort."
            Write-Host "$($_.Exception.Message)"
            Write-Host ''
            Write-Host 'Another console is probably already running. Either use it, or pick a free port:'
            Write-Host "    .\DeviceControlConsole.ps1 serve -Port $($ListenPort + 1)"
            Suspend-ForReader
            return 1
        }

        $script:StopRequested = $false
        try {
            while (-not $script:StopRequested) {
                $client = $listener.AcceptTcpClient()
                try {
                    $client.ReceiveTimeout = 30000
                    $client.SendTimeout = 120000
                    $stream = $client.GetStream()
                    $request = Read-HttpRequest -Stream $stream
                    if ($request) {
                        $response = $null
                        try { $response = Invoke-ApiRoute -Request $request }
                        catch { $response = New-ErrorResponse "$($_.Exception.Message)" 500 }
                        Write-HttpResponse -Stream $stream -Request $request `
                            -StatusCode $response.status -ContentType $response.type `
                            -Body $response.body -Extra $response.extra
                    }
                } catch {
                    Write-Verbose "connection failed: $($_.Exception.Message)"
                } finally {
                    try { $client.Close() } catch { }
                }
            }
        } finally {
            try { $listener.Stop() } catch { }
        }

        if (-not $script:RestartElevated) { return 0 }
        $script:RestartElevated = $false
        Write-Host '  handing over to an elevated instance...'
        if ((Start-ElevatedInstance -ListenPort $ListenPort) -and (Wait-ForPort -ListenPort $ListenPort -TimeoutMs 40000)) {
            Write-Host '  elevated instance is serving; this one is done.'
            return 0
        }
        Write-Host '  elevation did not complete; continuing as standard user.'
    }
}

function Start-ElevatedInstance {
    param([int]$ListenPort)
    $tokenFile = Join-Path ([System.IO.Path]::GetTempPath()) ("dcc_tok_" + [guid]::NewGuid().ToString('N') + ".txt")
    try {
        Set-Content -LiteralPath $tokenFile -Value $script:Token -NoNewline
        $me = Join-Path $script:Root 'DeviceControlConsole.ps1'
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$me`"",
                     'serve', '-Port', "$ListenPort", '-NoBrowser', '-TokenFile', "`"$tokenFile`"")
        Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -ErrorAction Stop | Out-Null
        return $true
    } catch {
        Remove-Item -LiteralPath $tokenFile -Force -ErrorAction SilentlyContinue
        return $false
    }
}

function Wait-ForPort {
    param([int]$ListenPort, [int]$TimeoutMs = 30000)
    $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
    while ((Get-Date) -lt $deadline) {
        try {
            $probe = New-Object System.Net.Sockets.TcpClient
            $async = $probe.BeginConnect('127.0.0.1', $ListenPort, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(400) -and $probe.Connected) {
                $probe.EndConnect($async); $probe.Close(); return $true
            }
            $probe.Close()
        } catch { }
        Start-Sleep -Milliseconds 300
    }
    return $false
}

#endregion

#region ------------------------------------------------------------ cli views

function Write-Table {
    param($Rows, [string[]]$Headers, [string[]]$Fields, [int]$RowLimit)
    if (-not $Rows -or @($Rows).Count -eq 0) { Write-Host '(no matching rows)'; return }
    $all = @($Rows)
    $shown = if ($RowLimit -gt 0 -and $RowLimit -lt $all.Count) { $all[0..($RowLimit - 1)] } else { $all }
    $widths = @()
    for ($i = 0; $i -lt $Headers.Count; $i++) { $widths += $Headers[$i].Length }
    foreach ($r in $shown) {
        for ($i = 0; $i -lt $Fields.Count; $i++) {
            $v = "$($r[$Fields[$i]])"
            if ($v.Length -gt $widths[$i]) { $widths[$i] = [Math]::Min($v.Length, 58) }
        }
    }
    $line = { param($cells)
        $parts = @()
        for ($i = 0; $i -lt $widths.Count; $i++) {
            $v = "$($cells[$i])"
            if ($v.Length -gt $widths[$i]) { $v = $v.Substring(0, $widths[$i]) }
            $parts += $v.PadRight($widths[$i])
        }
        ($parts -join '  ').TrimEnd()
    }
    Write-Host (& $line $Headers)
    Write-Host (& $line @($widths | ForEach-Object { '-' * $_ }))
    foreach ($r in $shown) {
        $cells = foreach ($f in $Fields) {
            $v = $r[$f]
            if ($v -is [array]) { ($v -join ', ') } else { "$v" }
        }
        Write-Host (& $line $cells)
    }
    if ($shown.Count -lt $all.Count) {
        Write-Host "... $($all.Count - $shown.Count) more (use -Limit 0 to show all)"
    }
}

function Test-Match {
    param([string]$Blob, [string]$Needle)
    if (-not $Needle) { return $true }
    foreach ($term in ($Needle.ToLowerInvariant() -split '\s+')) {
        if (-not $term) { continue }
        if ($Blob -notlike "*$term*") { return $false }
    }
    return $true
}

function Invoke-CmdDevices {
    $snap = Get-Snapshot
    $rows = @($snap.devices | Where-Object {
        (Test-Match -Blob $_.search_blob -Needle $Query) -and
        ($Status -ne 'connected' -or $_.present) -and
        ($Status -ne 'disconnected' -or -not $_.present) -and
        ($Status -ne 'problem' -or $_.problem_code -ne 0) -and
        (-not $Class -or $_.class_name -eq $Class) -and
        (-not $Type -or $_.device_type -like "*$Type*")
    } | Sort-Object -Property resolved_name)

    if ($Csv) {
        $rows | Select-Object @{n='Type';e={$_.device_type}}, @{n='Resolved Device';e={$_.resolved_name}},
            @{n='Instance ID';e={$_.instance_id}}, @{n='Status';e={$_.status}},
            @{n='Driver';e={$_.driver_name}}, @{n='Class GUID';e={$_.class_guid}} |
            Export-Csv -LiteralPath $Csv -NoTypeInformation -Encoding UTF8
        Write-Host "wrote $($rows.Count) rows to $Csv"
        return 0
    }
    Write-Table -Rows $rows -Headers @('TYPE','RESOLVED DEVICE','INSTANCE ID','STATUS','DRIVER') `
        -Fields @('device_type','resolved_name','instance_id','status','driver_name') -RowLimit $Limit
    Write-Host ''
    Write-Host "$($rows.Count) device(s) of $($snap.meta.device_count)"
    return 0
}

function Invoke-CmdDrivers {
    $snap = Get-Snapshot
    $rows = @($snap.drivers | Where-Object {
        (Test-Match -Blob $_.search_blob -Needle $Query) -and
        ($State -ne 'orphaned' -or $_.orphaned) -and
        ($State -ne 'inuse' -or -not $_.orphaned) -and
        ($State -ne 'superseded' -or $_.superseded_by) -and
        ($State -ne 'extension' -or $_.is_extension) -and
        (-not $Class -or $_.class_name -eq $Class)
    })
    Write-Table -Rows $rows -Headers @('PUBLISHED','ORIGINAL','PROVIDER','CLASS','VERSION','DEVICES','SUPERSEDED BY') `
        -Fields @('driver_name','original_name','provider_name','class_name','driver_version','device_count','superseded_by') `
        -RowLimit $Limit
    Write-Host ''
    Write-Host "$($rows.Count) package(s) of $($snap.meta.driver_count) ($($snap.meta.orphan_driver_count) orphaned, $($snap.meta.superseded_driver_count) superseded)"
    return 0
}

function Invoke-CmdResolve {
    if (-not $Query) { Write-Host 'resolve needs a query'; return 2 }
    $snap = Get-Snapshot
    $hits = @($snap.devices | Where-Object { $_.instance_id -eq $Query })
    if ($hits.Count -eq 0) {
        $hits = @($snap.devices | Where-Object { Test-Match -Blob $_.search_blob -Needle $Query })
    }
    if ($hits.Count -eq 0) { Write-Host "no device matches '$Query'"; return 1 }

    $shown = 0
    foreach ($d in $hits) {
        if ($Limit -gt 0 -and $shown -ge $Limit) { break }
        $shown++
        # Disconnected devices are skipped by the bulk scan, so fetch this
        # one's properties now and resolve again with the fuller picture.
        $wasEnriched = $d._enriched
        Update-DeviceDetail -InstanceId $d.instance_id -Device $d
        if (-not $wasEnriched -and $d._enriched) {
            Resolve-DeviceIdentity -Resolver $snap.resolver -InstanceId $d.instance_id
        }
        Write-Host ''
        Write-Host "Instance ID:                $($d.instance_id)"
        Write-Host "  >> Resolved device:       $($d.resolved_name)  [$($d.resolved_confidence) confidence]"
        Write-Host "  >> via:                   $($d.resolved_from)"
        Write-Host "  >> Type:                  $($d.device_type)  ($($d.type_from))"
        Write-Host "  >> Vendor:                $($d.vendor)"
        Write-Host "Device Description:         $($d.description)"
        Write-Host "Class Name:                 $($d.class_name)"
        Write-Host "Class GUID:                 $($d.class_guid)"
        Write-Host "Manufacturer Name:          $($d.manufacturer)"
        $statusLine = $d.status
        if ($d.problem_code -ne 0) { $statusLine += "  (problem $($d.problem_code): $($d.problem_text))" }
        Write-Host "Status:                     $statusLine"
        if ($d.driver_name) { Write-Host "Driver Name:                $($d.driver_name)" }
        if ($d.extension_drivers.Count -gt 0) {
            Write-Host "Extension Driver Names:     $($d.extension_drivers -join ', ')"
        }
        if ($Relations) {
            if ($d.children.Count -gt 0) {
                Write-Host 'Children:'
                foreach ($c in $d.children) {
                    $n = if ($snap.index.ContainsKey($c)) { $snap.index[$c].resolved_name } else { '?' }
                    Write-Host ("    " + $n.PadRight(44) + " " + $c)
                }
            }
            if ($d.related.Count -gt 0) {
                Write-Host 'Related hardware:'
                foreach ($r in @($d.related)[0..([Math]::Min(11, $d.related.Count - 1))]) {
                    $n = if ($snap.index.ContainsKey($r)) { $snap.index[$r].resolved_name } else { '?' }
                    Write-Host ("    " + $n.PadRight(44) + " " + $r)
                }
            }
        }
    }
    Write-Host ''
    if ($hits.Count -gt $shown) { Write-Host "($($hits.Count) matches, showing $shown)" }
    return 0
}

function Invoke-CmdOrphans {
    $snap = Get-Snapshot
    $rows = @($snap.drivers | Where-Object { $_.orphaned -or ($Superseded -and $_.superseded_by) })
    Write-Table -Rows $rows -Headers @('PUBLISHED','ORIGINAL','PROVIDER','CLASS','VERSION','DEVICES','SUPERSEDED BY') `
        -Fields @('driver_name','original_name','provider_name','class_name','driver_version','device_count','superseded_by') `
        -RowLimit $Limit
    Write-Host ''
    Write-Host "$($rows.Count) candidate(s); $($snap.meta.orphan_driver_count) package(s) have no device attached."
    Write-Host 'Delete one with:  .\DeviceControlConsole.ps1 delete-driver oem42.inf'
    return 0
}

function Invoke-CmdTree {
    $snap = Get-Snapshot
    $roots = @($snap.devices | Where-Object { -not $_.parent -or -not $snap.index.ContainsKey($_.parent) } |
        Sort-Object -Property resolved_name)
    $walk = {
        param($dev, $level)
        if ($level -gt $Depth) { return }
        $pad = ' ' * ($level * 2)
        $flag = if ($dev.present) { '' } else { '  [disconnected]' }
        Write-Host "$pad$($dev.resolved_name)  ($($dev.device_type))$flag"
        Write-Host "$pad   $($dev.instance_id)"
        foreach ($c in ($dev.children | Sort-Object)) {
            if ($snap.index.ContainsKey($c)) { & $walk $snap.index[$c] ($level + 1) }
        }
    }
    foreach ($r in $roots) { & $walk $r 0 }
    return 0
}

function Invoke-CmdStatus {
    $snap = Get-Snapshot
    $meta = Copy-OrderedMap -Map $snap.meta
    $meta['elevated'] = (Test-Elevated)
    $meta['hwids'] = Get-HwIdsStatus
    Write-Host (ConvertTo-JsonSafe -Value $meta)
    return 0
}

function Invoke-CmdCheck {
    $ports = if ($PSBoundParameters.ContainsKey('Port')) { @($Port) } else { @(8777, 8778, 8779) }
    $found = $false
    foreach ($p in $ports) {
        if (-not (Wait-ForPort -ListenPort $p -TimeoutMs 500)) { continue }
        $found = $true
        Write-Host "Port $p : something is listening."
        try {
            $owner = (Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction Stop |
                      Select-Object -First 1).OwningProcess
            $proc = Get-Process -Id $owner -ErrorAction SilentlyContinue
            if ($proc) { Write-Host "    process  : $($proc.ProcessName) (PID $owner)" }
        } catch { }
        Write-Host "    open it  : http://127.0.0.1:$p/"
        Write-Host '    note     : the page needs the token printed by that console window.'
    }
    if (-not $found) {
        Write-Host "No console is running on port $($ports -join ', ')."
        Write-Host 'Start one with:  .\DeviceControlConsole.ps1'
        return 1
    }
    return 0
}

function Invoke-CmdDeleteDriver {
    if (-not $Query) { Write-Host 'delete-driver needs an oem#.inf name'; return 2 }
    $snap = Get-Snapshot
    $key = $Query.ToLowerInvariant()
    if (-not $snap.driverIndex.ContainsKey($key)) {
        Write-Host "$Query is not in the driver store"; return 1
    }
    $pkg = $snap.driverIndex[$key]
    Write-Host "$($pkg.driver_name)  $($pkg.original_name)  ($($pkg.provider_name), $($pkg.driver_version)) -- used by $($pkg.device_count) device(s)"
    if (-not $Yes) {
        $answer = Read-Host 'Delete this package from the driver store? [y/N]'
        if ($answer -notmatch '^y(es)?$') { Write-Host 'aborted'; return 1 }
    }
    $name = Assert-OemInf $Query
    $argList = @('/delete-driver', $name)
    if ($Uninstall) { $argList += '/uninstall' }
    if ($Force) { $argList += '/force' }
    if ($Reboot) { $argList += '/reboot' }
    $r = Invoke-PnpAction -Arguments $argList
    Write-Host $r.output
    Write-Host "exit $($r.returncode)$(if ($r.reboot_required) { ' (reboot required)' })"
    return $(if ($r.ok) { 0 } else { 2 })
}

function Invoke-CmdDeviceAction {
    param([string]$Verb)
    if (-not $Query) { Write-Host "$Verb needs an instance ID"; return 2 }
    $snap = Get-Snapshot
    $r = Invoke-DeviceAction -Verb $Verb -InstanceId $Query -Known $snap.index -WithSubtree:$Subtree
    Write-Host $r.output
    return $(if ($r.ok) { 0 } else { 2 })
}

function Invoke-CmdUpdateHwids {
    Write-Host 'downloading usb.ids and pci.ids ...'
    $res = Update-HwIdsTables
    foreach ($name in $res.Keys) {
        $r = $res[$name]
        if ($r.ok) { Write-Host "  $name : $($r.bytes) bytes, $($r.vendors) vendors" }
        else { Write-Host "  $name : FAILED -- $($r.error)" }
    }
    Write-Host "cache: $(Get-HwIdsCacheDir)"
    return 0
}

function Invoke-CmdBundle {
    <#
        Writes a self-contained copy: the script plus a web folder beside it,
        so the whole console fits on a USB stick as one directory.
    #>
    $target = if ($OutFile) { $OutFile } else { Join-Path $script:Root 'bundle' }
    $webRoot = Get-WebRoot
    if (-not $webRoot) { Write-Host 'web assets not found'; return 1 }
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $target 'web') -Force | Out-Null
    Copy-Item (Join-Path $script:Root 'DeviceControlConsole.ps1') $target -Force
    if (Test-Path (Join-Path $script:Root 'run.cmd')) {
        Copy-Item (Join-Path $script:Root 'run.cmd') $target -Force
    }
    Copy-Item (Join-Path $webRoot '*') (Join-Path $target 'web') -Force
    Write-Host "Bundled into: $target"
    Write-Host 'Copy that folder anywhere - it needs nothing installed.'
    return 0
}

function Show-Help {
    Write-Host "Device Control Console $($script:Version) (PowerShell build)"
    Write-Host ''
    Write-Host '  .\DeviceControlConsole.ps1 [command] [options]'
    Write-Host ''
    Write-Host 'Commands:'
    Write-Host '  serve                  run the local web console (default)'
    Write-Host '     -Port <n>  -NoBrowser'
    Write-Host '  devices [search]       list devices with resolved names'
    Write-Host '     -Status connected|disconnected|problem  -Class <n>  -Type <n>  -Limit <n>  -Csv <path>'
    Write-Host '  drivers [search]       list driver-store packages'
    Write-Host '     -State inuse|orphaned|superseded|extension'
    Write-Host '  resolve <query>        resolve an instance ID to the real device   [-Relations]'
    Write-Host '  orphans                packages no device is using                 [-Superseded]'
    Write-Host '  tree                   device tree with resolved names             [-Depth <n>]'
    Write-Host '  check                  is a console already running?'
    Write-Host '  delete-driver <oem#.inf>   [-Uninstall] [-Force] [-Reboot] [-Yes]'
    Write-Host '  enable-device | disable-device | restart-device | remove-device <instance id>'
    Write-Host '  update-hwids           download usb.ids / pci.ids'
    Write-Host '  bundle                 make a portable copy   [-OutFile <dir>]'
    Write-Host '  status                 JSON summary of the machine'
    return 0
}

#endregion

#region --------------------------------------------------------------- main

$exitCode = 0
try {
    switch ($Command) {
        'serve'          { $exitCode = Start-Console -ListenPort $Port -SkipBrowser:$NoBrowser -TokenPath $TokenFile }
        'devices'        { $exitCode = Invoke-CmdDevices }
        'drivers'        { $exitCode = Invoke-CmdDrivers }
        'resolve'        { $exitCode = Invoke-CmdResolve }
        'orphans'        { $exitCode = Invoke-CmdOrphans }
        'tree'           { $exitCode = Invoke-CmdTree }
        'status'         { $exitCode = Invoke-CmdStatus }
        'check'          { $exitCode = Invoke-CmdCheck }
        'update-hwids'   { $exitCode = Invoke-CmdUpdateHwids }
        'bundle'         { $exitCode = Invoke-CmdBundle }
        'delete-driver'  { $exitCode = Invoke-CmdDeleteDriver }
        'enable-device'  { $exitCode = Invoke-CmdDeviceAction -Verb 'enable-device' }
        'disable-device' { $exitCode = Invoke-CmdDeviceAction -Verb 'disable-device' }
        'restart-device' { $exitCode = Invoke-CmdDeviceAction -Verb 'restart-device' }
        'remove-device'  { $exitCode = Invoke-CmdDeviceAction -Verb 'remove-device' }
        default          { $exitCode = Show-Help }
    }
} catch {
    Write-Host ''
    Write-Host "error: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.ScriptStackTrace) { Write-Verbose $_.ScriptStackTrace }
    $exitCode = 2
}

if ($exitCode -ne 0) { Suspend-ForReader "Exited with code $exitCode." }
exit $exitCode

#endregion
