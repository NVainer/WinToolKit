if ((reagentc /info) -match 'Windows RE status:\s+Enabled') { Write-Output 'WinRE Enabled'; exit 0 }
exit 1
