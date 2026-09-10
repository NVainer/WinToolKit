<#
    Repair-WinRe.ps1  (Clicknet)
    Flow : reagentc /info -> Disabled? -> Disable-BitLocker + wait for decrypt -> reagentc /enable
           -> still Disabled? -> delete ReAgent.xml + stage Winre.wim + /setreimage -> reagentc /enable
           -> BitLocker on + key to Entra -> reagentc /info
    Exit : 0 = WinRE enabled | 1 = failed
    Needs: 64-bit PowerShell (Sysnative), Winre.wim next to this script ($WimSource)
#>

$WimSource = "$PSScriptRoot\Winre.wim"
$Recovery  = 'C:\Windows\System32\Recovery'
$Log       = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\Repair-WinRe.log"

function Test-WinRE  { [bool]((reagentc /info) -match 'Windows RE status:\s+Enabled') }
function Stop-Script ($Message, $Code) { Write-Output $Message; Stop-Transcript | Out-Null; exit $Code }

Start-Transcript -Path $Log -Append | Out-Null
if ($env:PROCESSOR_ARCHITEW6432) { Stop-Script 'Run in 64-bit PowerShell (Sysnative) - reagentc/System32\Recovery get WOW64-redirected' 1 }

# 1. Detect
if (Test-WinRE) { Stop-Script 'WinRE enabled - no action' 0 }
if (-not (Test-Path $WimSource)) { Stop-Script "Winre.wim not found: $WimSource" 1 }   # bail before touching BitLocker

# 2. Disabled -> decrypt C:, then enable
Disable-BitLocker -MountPoint 'C:' -ErrorAction SilentlyContinue | Out-Null
Write-Output 'Waiting for C: decryption'
while ((Get-BitLockerVolume -MountPoint 'C:').VolumeStatus -ne 'FullyDecrypted') { Start-Sleep -Seconds 30 }
reagentc /enable

# 3. Still disabled (wim missing) -> stage wim, point reagentc at it, enable again
if (-not (Test-WinRE)) {
    Remove-Item "$Recovery\ReAgent.xml" -Force -ErrorAction SilentlyContinue
    Copy-Item $WimSource "$Recovery\Winre.wim" -Force
    reagentc /setreimage /path $Recovery
    reagentc /enable
}

# 4. BitLocker back on + recovery key to Entra (always - never leave C: clear)
manage-bde -on C: -rp
$KeyId = ((Get-BitLockerVolume -MountPoint 'C:').KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }).KeyProtectorId
manage-bde -protectors -aadbackup C: -id $KeyId

# 5. Verify
reagentc /info
if (Test-WinRE) { Stop-Script 'WinRE remediated' 0 }
Stop-Script 'WinRE still disabled' 1
