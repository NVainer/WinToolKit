# version 1.2
$CiTool = if ([Environment]::Is64BitProcess) { "$env:windir\System32\CiTool.exe" }
          else { "$env:windir\Sysnative\CiTool.exe" }

(& $CiTool -lp -json | ConvertFrom-Json).Policies |
    Where-Object { $_.FriendlyName -like 'Clicknet - App Control - Base*' } |
    ForEach-Object { & $CiTool -rp "{$($_.PolicyID -replace '[{}]','')}" -json | Out-Null }

exit 0