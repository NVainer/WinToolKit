param(
 [string]$TargetVersion = "1.0.0",
 [switch]$Force
)

$registrySubKey = "SOFTWARE\YARA"

# Here is the magic: pass the parameter variable into the hashtable
$values = @{ "Version" = $TargetVersion }

foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
 $baseKey = 
[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
 $regKey = $baseKey.CreateSubKey($registrySubKey)

 foreach ($name in $values.Keys) {
 $regKey.SetValue($name, $values[$name], [Microsoft.Win32.RegistryValueKind]::String)
 }
 
$regKey.Close()
 $baseKey.Close()
}

$tempdir = "C:\Program Files\YARA"
New-Item $tempdir -ItemType Directory -Force
Copy-Item ".\scan-quick.ps1" -Destination $tempdir -Force
Copy-Item ".\scan-full.ps1" -Destination $tempdir -Force
Copy-Item ".\compiled_rules.yarc" -Destination $tempdir -Force
Copy-Item ".\yara64.exe" -Destination $tempdir -Force
Copy-Item ".\uninstall.ps1" -Destination $tempdir -Force
Copy-Item ".\YARA-Quick.xml" -Destination $tempdir -Force
Copy-Item ".\YARA-Full.xml" -Destination $tempdir -Force

Register-ScheduledTask -xml (Get-Content '.\YARA-Quick.xml' | Out-String) -TaskName "YARA-Quick" -Force

Register-ScheduledTask -xml (Get-Content '.\YARA-Full.xml' | Out-String) -TaskName "YARA-Full" -Force

Add-MpPreference -ExclusionProcess "C:\Program Files\YARA\yara64.exe"
