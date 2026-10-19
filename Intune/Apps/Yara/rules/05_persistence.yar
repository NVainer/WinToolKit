/* =============================================================================
   05_persistence.yar
   -----------------------------------------------------------------------------
   Author : Nati
   Date   : 2026-10-14 (v3)
   Scope  : Persistence that leaves a FILE behind on a Windows 11 client:
            scheduled-task XML (System32\Tasks\*, full scan only), the WMI
            repository (OBJECTS.DATA) and MOF/PS/VBS that program it, and
            scripts that write autorun registry values, services or Startup
            folder items. Registry-only persistence (Run keys set via API,
            COM hijacks) lives in hives and is MDE's job.

   Dropped from v2: BITS jobs, GPO logon scripts (no AD), AppDomainManager
   hijack, PowerShell profile tampering (all rare on client fleets).
   ============================================================================= */

/* -----------------------------------------------------------------------------
   PERSIST_HIGH_ScheduledTask_Suspicious
   ----------------------------------------------------------------------------- */
rule PERSIST_HIGH_ScheduledTask_Suspicious
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "persistence"
        severity    = "high"
        description = "Task XML whose Exec runs a script host with URL/IEX/-enc/hidden/javascript:/user-profile-script arguments, or whose Command is a script under a user-writable path; schtasks /create or New-ScheduledTaskAction with the same payload shapes"
        mitre       = "T1053.005"
        fp_notes    = "Vendor tasks run EXEs from AppData (OneDrive, Google, Dropbox updaters); those have no script extension and no payload marker. A vendor task running a .vbs/.bat from ProgramData will fire the Command branch - verify the publisher once, then exclude in KQL by task name."

    strings:
        $xml_task      = /(<Task\s+version=|schemas\.microsoft\.com\/windows\/2004\/02\/mit\/task)/i ascii wide
        $xml_cmd_host  = /<Command>\s*["']?([^<"']{0,200}\\)?(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|msiexec|conhost|forfiles|certutil|bitsadmin|curl)(\.exe)?["']?\s*<\/Command>/i ascii wide
        $xml_args_bad  = /<Arguments>[^<]{0,600}(https?:\/\/|\biex\b|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|FromBase64String|-e(c|n|nc|ncodedcommand)?\s+[A-Za-z0-9+\/]{40,}|-w(indowstyle)?\s+h(idden)?\b|javascript\s*:|vbscript\s*:|\\Users\\[^<\\]{1,80}\\(AppData|Downloads|Desktop|Documents|Pictures)|%(APPDATA|LOCALAPPDATA|TEMP|TMP|PUBLIC|USERPROFILE)%|\\Users\\Public\\|\\Windows\\Temp\\)[^<]{0,600}<\/Arguments>/i ascii wide
        $xml_cmd_upath = /<Command>\s*["']?(\\Users\\[^<\\"']{1,80}\\(AppData|Downloads|Desktop|Documents|Pictures)|%(APPDATA|LOCALAPPDATA|TEMP|TMP|PUBLIC|USERPROFILE)%|\\Users\\Public\\|\\Windows\\Temp\\|\\ProgramData\\)[^<"']{0,200}\.(ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd|scr|cpl)["']?\s*<\/Command>/i ascii wide

        $schtasks      = /\bschtasks(\.exe)?\s+\/create\b[^\r\n]{0,300}\/tr\s+["']?[^\r\n]{0,300}((powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|cmd)(\.exe)?[^\r\n]{0,200}(https?:\/\/|\biex\b|-e(c|n|nc|ncodedcommand)?\s+[A-Za-z0-9+\/]{40,}|-w(indowstyle)?\s+h(idden)?\b|javascript\s*:|DownloadString|FromBase64String)|\\Users\\[^\\\r\n"']{1,80}\\(AppData|Downloads|Desktop|Documents)[^\r\n"']{0,160}\.(ps1|vbs|js|jse|wsf|hta|bat|cmd|exe|scr|dll)|%(APPDATA|LOCALAPPDATA|TEMP|TMP|PUBLIC)%[^\r\n"']{0,160}\.(ps1|vbs|js|jse|wsf|hta|bat|cmd|exe|scr|dll))/i ascii wide
        $ps_task       = /(New-ScheduledTaskAction|Register-ScheduledTask)\b[^\r\n]{0,300}-(Execute|Argument|Action)\s+["']?[^\r\n]{0,300}((powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)(\.exe)?[^\r\n]{0,200}(https?:\/\/|\biex\b|-e(c|n|nc|ncodedcommand)?\s+[A-Za-z0-9+\/]{40,}|-w(indowstyle)?\s+h(idden)?\b|DownloadString|FromBase64String)|\\Users\\[^\\\r\n"']{1,80}\\(AppData|Downloads|Desktop|Documents)[^\r\n"']{0,160}\.(ps1|vbs|js|jse|wsf|hta|bat|cmd|exe|scr|dll)|%(APPDATA|LOCALAPPDATA|TEMP|TMP|PUBLIC)%[^\r\n"']{0,160}\.(ps1|vbs|js|jse|wsf|hta|bat|cmd|exe|scr|dll))/i ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and (
            ( $xml_task and ( ( $xml_cmd_host and $xml_args_bad ) or $xml_cmd_upath ) )
            or $schtasks
            or $ps_task
        )
}

/* -----------------------------------------------------------------------------
   PERSIST_HIGH_WMI_Event_Subscription
   Permanent WMI subscriptions with a command-line or script consumer, either
   in the MOF/PowerShell/VBS that creates them or as instance records inside
   the CIM repository (C:\Windows\System32\wbem\Repository\OBJECTS.DATA).
   ----------------------------------------------------------------------------- */
rule PERSIST_HIGH_WMI_Event_Subscription
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "persistence"
        severity    = "high"
        description = "__EventFilter + CommandLine/ActiveScript consumer + binding/creation verb + payload template in a script; or a consumer INSTANCE in OBJECTS.DATA whose template launches a script host with a URL, encoded command, hidden window or user-writable path"
        mitre       = "T1546.003"
        fp_notes    = "Some OEM/management suites register CommandLineEventConsumer instances that run their own EXE from Program Files; those carry no payload marker and do not fire. Validate any hit with Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer."

    strings:
        $filter   = /__EventFilter\b/ ascii wide
        $consumer = /(CommandLineEventConsumer|ActiveScriptEventConsumer)\b/ ascii wide
        $binding  = /__FilterToConsumerBinding\b/ ascii wide
        $create   = /(Set-WmiInstance|New-CimInstance|New-WmiInstance|Register-WmiEvent|#pragma\s+namespace|instance\s+of\s+(CommandLineEventConsumer|ActiveScriptEventConsumer|__EventFilter)|\.Put\s*\(\s*\)|SpawnInstance_)/i ascii wide
        $payload  = /(CommandLineTemplate|ScriptText|ExecutablePath)\s*[=:]\s*["']?[^\r\n"']{0,80}(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|\\Users\\|AppData|\\Temp\\|ProgramData|http|-enc|\biex\b|FromBase64)/i ascii wide

        $repo_cmd = /CommandLineEventConsumer\x00\x00[\s\S]{0,1500}(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec)[^\x00]{0,400}(https?:|\s-e(c|n|nc|ncodedcommand)?\s+[A-Za-z0-9+\/]{20,}|\biex\b|AppData|\\Temp\\|ProgramData|Users\\Public|FromBase64|-w(indowstyle)?\s+h(idden)?)/i ascii
        $repo_scr = /ActiveScriptEventConsumer\x00\x00[\s\S]{0,1500}(VBScript|JScript)\x00\x00[\s\S]{0,40}(CreateObject|WScript\.Shell|Shell\.Application|powershell|cmd\.exe|https?:|\.Run\s*\()/i ascii

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and (
            ( filesize < 5MB and $filter and $consumer and ( $binding or $create ) and $payload )
            or ( filesize < 300MB and ( $repo_cmd or $repo_scr ) )
        )
}

/* -----------------------------------------------------------------------------
   PERSIST_MEDHIGH_Script_Autorun_Write
   Script text that plants an autorun: registry run/winlogon/IFEO/AppInit/LSA/
   print-monitor/COM/logon-script keys with a payload, a service with a
   script-host or user-path binary, or a file dropped into a Startup folder.
   ----------------------------------------------------------------------------- */
rule PERSIST_MEDHIGH_Script_Autorun_Write
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "persistence"
        severity    = "medium-high"
        description = "Registry write verb + autorun key (Run/RunOnce/Winlogon/IFEO Debugger/AppInit_DLLs/LSA packages/Print Monitors/CLSID InprocServer32/UserInitMprLogonScript/BootExecute/Shell Folders Startup) + payload (script host with URL/IEX/-enc/hidden, or script/binary under a user-writable path, or mimikatz SSP names) in one file; sc create/New-Service with such a binPath; copy/write/CreateShortcut into a Startup folder"
        mitre       = "T1547.001,T1547.004,T1546.012,T1546.010,T1547.002,T1547.010,T1546.015,T1543.003"

    strings:
        $verb_reg = /(reg(\.exe)?\s+add|Set-ItemProperty|New-ItemProperty|New-Item\s+-Path|\[Microsoft\.Win32\.Registry\]::SetValue|\.RegWrite\b|RegWrite\s*\(|Set-Item\s+-Path)/i ascii wide
        $run_key  = /(CurrentVersion\\\\?(Run|RunOnce|RunOnceEx|RunServices|Policies\\\\?Explorer\\\\?Run)\b|Winlogon\\\\?(Userinit|Shell)\b|Image File Execution Options\\\\?[^\\\r\n"']{1,60}\.exe\\\\?Debugger|Windows NT\\\\?CurrentVersion\\\\?Windows\\\\?(AppInit_DLLs|Load)\b|Control\\\\?Lsa\\\\?(Security|Authentication|Notification) Packages|Control\\\\?Print\\\\?Monitors\\\\?|Classes\\\\?CLSID\\\\?\{[0-9A-Fa-f-]{36}\}\\\\?(InprocServer32|TreatAs)|UserInitMprLogonScript|Session Manager\\\\?BootExecute|Shell Folders\\\\?(Common )?Startup)/i ascii wide
        $payload  = /((powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|cmd)(\.exe)?[^\r\n]{0,200}(https?:\/\/|\biex\b|-e(c|n|nc|ncodedcommand)?\s+[A-Za-z0-9+\/]{40,}|-w(indowstyle)?\s+h(idden)?\b|javascript\s*:|DownloadString|FromBase64String|\\AppData\\|%APPDATA%|%TEMP%|%LOCALAPPDATA%)|\\Users\\[^\\\r\n"']{1,80}\\(AppData|Downloads|Desktop|Documents|Pictures)[^\r\n"']{0,160}\.(ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd|exe|scr|dll|lnk)|%(APPDATA|LOCALAPPDATA|TEMP|TMP|PUBLIC|USERPROFILE)%[^\r\n"']{0,160}\.(ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd|exe|scr|dll|lnk)|\\Users\\Public\\[^\r\n"']{0,160}\.(ps1|vbs|js|hta|bat|cmd|exe|scr|dll)|\\Windows\\Temp\\[^\r\n"']{0,160}\.(ps1|vbs|js|hta|bat|cmd|exe|scr|dll)|\\ProgramData\\[^\r\n"']{0,160}\.(ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd)|\b(memssp|mimilib|mimilsa|kiwissp)\b)/i ascii wide

        $svc      = /(\bsc(\.exe)?\s+(\\\\\S+\s+)?create\s+[^\r\n]{0,120}binPath\s*=\s*["']?[^\r\n]{0,80}|New-Service\b[^\r\n]{0,200}-BinaryPathName\s+["']?[^\r\n]{0,80})((powershell|pwsh|cmd|mshta|rundll32)(\.exe)?[^\r\n]{0,200}(https?:\/\/|\biex\b|-e(c|n|nc|ncodedcommand)?\s+[A-Za-z0-9+\/]{40,}|-w(indowstyle)?\s+h(idden)?\b|FromBase64String|DownloadString)|\\Users\\[^\\\r\n"']{1,80}\\|%(APPDATA|LOCALAPPDATA|TEMP|TMP|PUBLIC)%|\\Users\\Public\\|\\Windows\\Temp\\|\\ProgramData\\[^\r\n"']{0,120}\.(bat|cmd|ps1|vbs|js))/i ascii wide

        $startup  = /(Copy-Item|Move-Item|Set-Content|Out-File|Add-Content|WriteAllText|WriteAllBytes|\bcopy\b|\bxcopy\b|\bmove\b|\becho\b|CreateShortcut|\.Save\s*\(\s*\)|New-Item)[^\r\n]{0,300}Start Menu\\\\?Programs\\\\?Start[Uu]p\\\\?[^\r\n"']{0,120}\.(lnk|vbs|vbe|js|jse|wsf|hta|bat|cmd|ps1|exe|scr|url)\b/i ascii wide
        $startup_r= /Start Menu\\\\?Programs\\\\?Start[Uu]p\\\\?[^\r\n"']{0,120}\.(lnk|vbs|vbe|js|jse|wsf|hta|bat|cmd|ps1|exe|scr|url)\b[^\r\n]{0,200}(Copy-Item|Move-Item|Set-Content|Out-File|Add-Content|WriteAllText|WriteAllBytes|CreateShortcut|\.Save\s*\(\s*\))/i ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and (
            ( $verb_reg and $run_key and $payload )
            or $svc
            or $startup or $startup_r
        )
}
