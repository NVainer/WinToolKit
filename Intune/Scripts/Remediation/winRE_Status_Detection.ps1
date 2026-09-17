$status = (((reagentc /info) | Select-String 'Windows RE status') -split ':')[-1].Trim()
Write-Output $status
if ($status -eq 'Enabled') { exit 0 } else { exit 1 }
