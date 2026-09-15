# Detect-WinRe.ps1 - Win32 app detection for "Clicknet_Fix_Recovery_Partition"
# Intune treats the app as installed only when the script exits 0 AND writes to STDOUT
if ((reagentc /info) -match 'Windows RE status:\s+Enabled') { Write-Output 'WinRE Enabled'; exit 0 }
exit 1
