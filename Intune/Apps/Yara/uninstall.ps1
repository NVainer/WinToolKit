# uninstall.ps1
$registrySubKey = "SOFTWARE\YARA"
$tempdir        = "C:\Program Files\YARA"
$exePath        = Join-Path $tempdir "yara64.exe"
$taskNames      = @("YARA-Quick","YARA-Full")

# 1) Remove Scheduled Tasks
foreach ($t in $taskNames) {
    try {
        if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
            Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue
        }
    } catch {}
}

# 2) Remove Defender exclusion
try {
    Remove-MpPreference -ExclusionProcess $exePath -ErrorAction SilentlyContinue
} catch {}

# 3) Remove registry key (both 64-bit and 32-bit views)
foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        $key = $baseKey.OpenSubKey($registrySubKey, $true)
        if ($key) {
            $key.Close()
            $baseKey.DeleteSubKeyTree($registrySubKey, $false)
        }
        $baseKey.Close()
    } catch {}
}

# 4) Remove files/folder
try {
    if (Test-Path $tempdir) {
        Remove-Item -Path $tempdir -Recurse -Force -ErrorAction SilentlyContinue
    }
} catch {}

exit 0
