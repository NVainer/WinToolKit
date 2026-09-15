Package — source folder holds only Repair-WinRe.ps1 + Winre.wim, ASCII path:
IntuneWinAppUtil.exe -c C:\Pkg\Src -s Repair-WinRe.ps1 -o C:\Pkg\Out -q → Repair-WinRe.intunewin


| Blade | Setting | Value |
|---|---|---|
| App information | Name | `Clicknet_Fix_Recovery_Partition` |
| App information | Publisher | `Clicknet` |
| App information | Description | Re-enables WinRE (winre.wim missing / BitLocker-blocked), re-encrypts C:, escrows key to Entra |
| Program | Install command | `%windir%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File Repair-WinRe.ps1` |
| Program | Uninstall command | `cmd.exe /c exit 0` (no-op, field is mandatory) |
| Program | Installation time required | `1440` — default is 60 and the install is failed (process killed) if it runs longer; max is 1440. A kill mid-decrypt leaves C: clear, so take the max. |
| Program | Allow available uninstall | No |
| Program | Install behavior | System |
| Program | Device restart behavior | No specific action |
| Program | Return codes | Leave defaults — exit 1 isn't listed → Failed |
| Requirements | Architecture | 64-bit |
| Requirements | Minimum OS | Windows 11 21H2 |
| Detection rules | Rules format | Use a custom detection script → `Detect-WinRe.ps1` |
| Detection rules | Run script as 32-bit | No |
| Detection rules | Enforce signature check | No |
| Dependencies / Supersedence | — | None |
| Assignments | Required | The targeted device group only |
| Assignments | Note | Exclude that group from the Disk Encryption compliance/encryption policy for the rollout window |
