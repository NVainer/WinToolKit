/*
================================================================================
 05_persistence.yar
 Author: Nati
 Category: Persistence (Windows 11 native)
 Severity: Medium-High to High
 Last updated: 2026-05-24

 Design principle (v2 - bound patterns):
   Every rule requires the FULL ATTACK SHAPE inside a single proximity-bounded
   regex window (200-300 chars): persistence target (registry / startup / service
   / scheduled task / WMI) + the write/create verb + the payload (user-writable
   binary, PS cradle, -enc, IEX, downloader). Standalone keyword matches are
   forbidden. This eliminates FPs on vcredist installer logs, Search index,
   MSI rollback logs, etc., which mention persistence locations and copy/exe
   on unrelated lines hundreds of bytes apart.

 Hardening common to every rule:
   - PE / ELF header skip (not MZ, not 0x7F ELF)
   - filesize < 5MB on script/text-based rules
   - ascii wide on script-content strings
   - bound regex with bidirectional proximity (verb<->target<->payload)
================================================================================
*/

/* -----------------------------------------------------------------------------
   PER_HIGH_Run_Key_UserWritable_Or_PS_Cradle
   Run/RunOnce/RunOnceEx write verb + Run path + (user-writable payload OR PS
   cradle) all bound inside a single regex window.
   ----------------------------------------------------------------------------- */
rule PER_HIGH_Run_Key_UserWritable_Or_PS_Cradle
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "persistence"
        severity = "high"
        description = "Bound Run/RunOnce/RunOnceEx write verb + key path + user-writable or PS-cradle payload in one window"
        mitre = "T1547.001"
        reference = "ATT&CK T1547.001 Registry Run Keys / Startup Folder"

    strings:
        // verb -> key -> payload, single window 0..300 chars between key and payload
        $bound_vkp = /(Set-ItemProperty|New-ItemProperty|New-Item\s+-Path|reg(\.exe)?\s+add)\s+[^\r\n]{0,120}(HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)[\\\/]+(SOFTWARE|Software)[\\\/]+(Microsoft[\\\/]+)?Windows[\\\/]+CurrentVersion[\\\/]+(Run|RunOnce|RunOnceEx)\b[^\r\n]{0,300}([A-Za-z]:\\(Users\\[^"'\\\r\n]{1,80}\\|ProgramData\\|Users\\Public\\|Windows\\Temp\\|Temp\\)[^"'\r\n]{0,160}\.(ps1|vbs|hta|js|bat|cmd|exe|dll|scr|lnk|wsf)|(powershell|pwsh)(\.exe)?[^\r\n]{0,120}(-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{60,}|-nop|-w(in(dowstyle)?)?\s+h(idden)?|-(ep|executionpolicy)\s+(bypass|unrestricted))|IEX|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|FromBase64String|mshta(\.exe)?\s+https?:\/\/|regsvr32(\.exe)?\s+\/s\s+\/n\s+\/u\s+\/i:https?:\/\/|rundll32(\.exe)?\s+javascript:)/is ascii wide

        // payload -> key -> verb (reverse direction, e.g. piped one-liners)
        $bound_pkv = /([A-Za-z]:\\(Users\\[^"'\\\r\n]{1,80}\\|ProgramData\\|Users\\Public\\|Windows\\Temp\\|Temp\\)[^"'\r\n]{0,160}\.(ps1|vbs|hta|js|bat|cmd|exe|dll|scr|lnk|wsf)|(powershell|pwsh)(\.exe)?[^\r\n]{0,120}(-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{60,}|IEX|Invoke-Expression|DownloadString|FromBase64String))[^\r\n]{0,300}(HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)[\\\/]+(SOFTWARE|Software)[\\\/]+(Microsoft[\\\/]+)?Windows[\\\/]+CurrentVersion[\\\/]+(Run|RunOnce|RunOnceEx)\b[^\r\n]{0,200}(Set-ItemProperty|New-ItemProperty|reg(\.exe)?\s+add)/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $bound_vkp or $bound_pkv )
}

/* -----------------------------------------------------------------------------
   PER_HIGH_IFEO_Accessibility_Hijack
   IFEO key + accessibility binary + Debugger value + user-writable / LOLBAS
   payload bound in one window.
   ----------------------------------------------------------------------------- */
rule PER_HIGH_IFEO_Accessibility_Hijack
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "persistence"
        severity = "high"
        description = "Bound IFEO Debugger hijack on accessibility binary (sethc/utilman/osk/magnify/narrator/displayswitch/atbroker)"
        mitre = "T1546.012"

    strings:
        // verb -> IFEO\<accessibility>.exe -> Debugger -> payload
        $bound_vkdp = /(Set-ItemProperty|New-ItemProperty|New-Item\s+-Path|reg(\.exe)?\s+add)\s+[^\r\n]{0,200}Image File Execution Options[\\\/]+(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe[^\r\n]{0,200}Debugger\b[^\r\n]{0,250}(cmd(\.exe)?|powershell(\.exe)?|pwsh(\.exe)?|wscript(\.exe)?|cscript(\.exe)?|rundll32(\.exe)?|mshta(\.exe)?|[A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.(exe|dll|ps1|cmd|bat|scr))/is ascii wide

        // alt order: key first, verb on same logical line
        $bound_kvdp = /Image File Execution Options[\\\/]+(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe[^\r\n]{0,250}(Set-ItemProperty|New-ItemProperty|reg(\.exe)?\s+add)[^\r\n]{0,200}Debugger\b[^\r\n]{0,250}(cmd(\.exe)?|powershell(\.exe)?|pwsh(\.exe)?|wscript|cscript|rundll32|mshta|[A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.(exe|dll|ps1|cmd|bat|scr))/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $bound_vkdp or $bound_kvdp )
}

/* -----------------------------------------------------------------------------
   PER_HIGH_IFEO_SilentProcessExit_MonitorProcess
   GlobalFlag 0x200 + SilentProcessExit\<bin>\MonitorProcess + user-writable
   target, all bound. Defangs LSASS auto-dump / process-exit payload trigger.
   ----------------------------------------------------------------------------- */
rule PER_HIGH_IFEO_SilentProcessExit_MonitorProcess
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "persistence"
        severity = "high"
        description = "Bound GlobalFlag 0x200 + SilentProcessExit MonitorProcess + user-writable monitor binary"
        mitre = "T1546.012"

    strings:
        // verb -> GlobalFlag 0x200/512 -> SilentProcessExit\<bin>\MonitorProcess -> payload
        $bound_gsmp = /(Set-ItemProperty|New-ItemProperty|reg(\.exe)?\s+add)\s+[^\r\n]{0,200}GlobalFlag\b[^\r\n]{0,80}(0x200|512)[^\r\n]{0,300}SilentProcessExit[\\\/]+[A-Za-z0-9_\.\-]+\.exe[^\r\n]{0,200}MonitorProcess\b[^\r\n]{0,250}([A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.(exe|dll|ps1|cmd|bat)|cmd(\.exe)?|powershell(\.exe)?|pwsh(\.exe)?|rundll32(\.exe)?)/is ascii wide

        // verb -> SilentProcessExit -> MonitorProcess -> payload, GlobalFlag may appear before
        $bound_smp = /(Set-ItemProperty|New-ItemProperty|reg(\.exe)?\s+add)\s+[^\r\n]{0,200}SilentProcessExit[\\\/]+[A-Za-z0-9_\.\-]+\.exe[^\r\n]{0,200}MonitorProcess\b[^\r\n]{0,250}([A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.(exe|dll|ps1|cmd|bat))/is ascii wide

        // LSASS-specific binding regardless of GlobalFlag order
        $bound_lsass = /(Set-ItemProperty|New-ItemProperty|reg(\.exe)?\s+add)\s+[^\r\n]{0,200}SilentProcessExit[\\\/]+lsass\.exe[^\r\n]{0,250}(MonitorProcess|ReportingMode|DumpFolder|LocalDumps)/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $bound_gsmp or $bound_smp or $bound_lsass )
}

/* -----------------------------------------------------------------------------
   PER_HIGH_WMI_Event_Subscription_Persistence
   __EventFilter + (CommandLine|ActiveScript)EventConsumer + FilterToConsumerBinding
   + Set-WmiInstance / New-CimInstance, all in proximity.
   ----------------------------------------------------------------------------- */
rule PER_HIGH_WMI_Event_Subscription_Persistence
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "persistence"
        severity = "high"
        description = "Bound WMI permanent subscription: EventFilter + EventConsumer + FilterToConsumerBinding + write cmdlet"
        mitre = "T1546.003"

    strings:
        // verb -> __EventFilter -> (CommandLine|ActiveScript)EventConsumer -> __FilterToConsumerBinding
        $bound_full = /(Set-WmiInstance|New-CimInstance|New-WmiInstance|Register-WmiEvent|Register-CimIndicationEvent)\s+[^\r\n]{0,300}__EventFilter\b[\s\S]{0,800}(CommandLineEventConsumer|ActiveScriptEventConsumer)\b[\s\S]{0,800}__FilterToConsumerBinding\b/is ascii wide

        // alt order: EventFilter -> binding -> verb -> consumer in same MOF/PS blob
        $bound_mof  = /__EventFilter\b[\s\S]{0,800}__FilterToConsumerBinding\b[\s\S]{0,800}(CommandLineEventConsumer|ActiveScriptEventConsumer)\b[\s\S]{0,400}(CommandLineTemplate|ScriptText|ScriptingEngine\s*=\s*['"]VBScript['"])/is ascii wide

        // PS one-liner: New-CimInstance -Namespace root/subscription -ClassName ... + payload field
        $bound_psns = /(Set-WmiInstance|New-CimInstance)\s+[^\r\n]{0,200}(root[\\\/]subscription|root\/subscription)[^\r\n]{0,400}(CommandLineTemplate|ScriptText)\s*=/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $bound_full or $bound_mof or $bound_psns )
}

/* -----------------------------------------------------------------------------
   PER_HIGH_Service_Create_Suspicious_BinPath
   sc create / New-Service + binPath + payload (user-writable OR cmd/PS wrapper),
   bound in one window.
   ----------------------------------------------------------------------------- */
rule PER_HIGH_Service_Create_Suspicious_BinPath
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "persistence"
        severity = "high"
        description = "Bound service create (sc/New-Service) + binPath + user-writable or PS/cmd-wrapped payload"
        mitre = "T1543.003"

    strings:
        // sc.exe create ... binPath= <payload-in-user-writable-or-PS/cmd-wrapper>
        $bound_sc = /\bsc(\.exe)?\s+(\\\\[^\s]+\s+)?create\b[^\r\n]{0,200}\bbinPath\s*=\s*["']?[^\r\n]{0,200}([A-Za-z]:\\(Users\\[^"'\\\r\n]{1,80}\\|ProgramData\\|Users\\Public\\|Windows\\Temp\\|Temp\\)[^"'\r\n]{0,160}\.(exe|dll|ps1|cmd|bat)|cmd(\.exe)?\s+\/c\s+[^"\r\n]{0,200}(powershell|certutil|curl|bitsadmin|mshta)|(powershell|pwsh)(\.exe)?\s+[^"\r\n]{0,200}(-e(nc)?\s+[A-Za-z0-9+\/=]{60,}|IEX|Invoke-Expression|DownloadString|Net\.WebClient|FromBase64String))/is ascii wide

        // New-Service -BinaryPathName ... <payload>
        $bound_ns = /\bNew-Service\b[^\r\n]{0,200}-BinaryPathName\s+["']?[^\r\n]{0,200}([A-Za-z]:\\(Users\\[^"'\\\r\n]{1,80}\\|ProgramData\\|Users\\Public\\|Windows\\Temp\\|Temp\\)[^"'\r\n]{0,160}\.(exe|dll|ps1|cmd|bat)|(powershell|pwsh)(\.exe)?\s+[^"\r\n]{0,200}(-e(nc)?\s+[A-Za-z0-9+\/=]{60,}|IEX|DownloadString|FromBase64String))/is ascii wide

        // WMI Win32_Service Create() with PathName containing payload
        $bound_wmi = /Win32_Service[^\r\n]{0,80}::?Create\b[\s\S]{0,400}(PathName|StartName|ServiceName)\s*=\s*["']?[^"'\r\n]{0,200}([A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.(exe|dll|ps1|cmd|bat)|(powershell|pwsh)(\.exe)?\s+[^"\r\n]{0,200}(-e(nc)?\s+[A-Za-z0-9+\/=]{60,}|IEX|FromBase64String))/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $bound_sc or $bound_ns or $bound_wmi )
}

/* -----------------------------------------------------------------------------
   PER_HIGH_Winlogon_Userinit_Shell_Hijack
   Winlogon key + write verb + non-default Userinit/Shell value bound.
   Allows the default tokens userinit.exe, / explorer.exe but flags anything
   appended beyond them.
   ----------------------------------------------------------------------------- */
rule PER_HIGH_Winlogon_Userinit_Shell_Hijack
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "persistence"
        severity = "high"
        description = "Bound Winlogon Userinit/Shell write with non-default appended binary"
        mitre = "T1547.004"

    strings:
        // verb -> Winlogon -> Userinit -> non-default value (anything past userinit.exe,)
        $bound_userinit = /(Set-ItemProperty|New-ItemProperty|reg(\.exe)?\s+add)\s+[^\r\n]{0,200}Microsoft[\\\/]+Windows NT[\\\/]+CurrentVersion[\\\/]+Winlogon[^\r\n]{0,200}Userinit\b[^\r\n]{0,300}(userinit\.exe\s*,\s*[^"\r\n,;]{2,}|[A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.(exe|dll|ps1|cmd|bat|scr)|(cmd|powershell|pwsh|rundll32|mshta|wscript|cscript)(\.exe)?)/is ascii wide

        // verb -> Winlogon -> Shell -> non-default value (anything past explorer.exe)
        $bound_shell = /(Set-ItemProperty|New-ItemProperty|reg(\.exe)?\s+add)\s+[^\r\n]{0,200}Microsoft[\\\/]+Windows NT[\\\/]+CurrentVersion[\\\/]+Winlogon[^\r\n]{0,200}\bShell\b[^\r\n]{0,300}(explorer\.exe\s*,\s*[^"\r\n,;]{2,}|[A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.(exe|dll|ps1|cmd|bat|scr)|(cmd|powershell|pwsh|rundll32|mshta)(\.exe)?)/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $bound_userinit or $bound_shell )
}

/* -----------------------------------------------------------------------------
   PER_HIGH_AppInit_DLLs_Persistence
   Windows NT\CurrentVersion\Windows + AppInit_DLLs + LoadAppInit_DLLs=1 +
   non-empty DLL value, bound. Also flags RequireSignedAppInit_DLLs=0 paired
   with the key write.
   ----------------------------------------------------------------------------- */
rule PER_HIGH_AppInit_DLLs_Persistence
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "persistence"
        severity = "high"
        description = "Bound AppInit_DLLs write with LoadAppInit_DLLs=1 and non-empty DLL value or RequireSigned=0"
        mitre = "T1546.010"

    strings:
        // verb -> AppInit key -> AppInit_DLLs = "<non-empty dll>"
        $bound_appinit = /(Set-ItemProperty|New-ItemProperty|reg(\.exe)?\s+add)\s+[^\r\n]{0,200}Microsoft[\\\/]+Windows NT[\\\/]+CurrentVersion[\\\/]+Windows\b[^\r\n]{0,200}AppInit_DLLs\b[^\r\n]{0,250}["']?[^"'\r\n]{1,160}\.dll["']?/is ascii wide

        // verb -> LoadAppInit_DLLs = 1, then AppInit_DLLs dll within window
        $bound_load = /(Set-ItemProperty|New-ItemProperty|reg(\.exe)?\s+add)\s+[^\r\n]{0,200}LoadAppInit_DLLs\b[^\r\n]{0,80}(0x1|1)\b[\s\S]{0,400}AppInit_DLLs\b[^\r\n]{0,250}["']?[^"'\r\n]{1,160}\.dll/is ascii wide

        // verb -> RequireSignedAppInit_DLLs = 0 + AppInit key (downgrade attack)
        $bound_unsign = /(Set-ItemProperty|New-ItemProperty|reg(\.exe)?\s+add)\s+[^\r\n]{0,200}RequireSignedAppInit_DLLs\b[^\r\n]{0,80}(0x0|0)\b[\s\S]{0,400}AppInit_DLLs\b/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $bound_appinit or $bound_load or $bound_unsign )
}

/* -----------------------------------------------------------------------------
   PER_HIGH_LSA_SSP_Authentication_Package_Mod
   LSA Security/Authentication/Notification Packages + write verb + malicious
   package name (memssp/mimilib/mimilsa/kiwissp) OR user-writable DLL, bound.
   ----------------------------------------------------------------------------- */
rule PER_HIGH_LSA_SSP_Authentication_Package_Mod
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "persistence"
        severity = "high"
        description = "Bound LSA Security/Authentication/Notification Packages write + known-evil SSP name or user-writable DLL"
        mitre = "T1547.002,T1556.002"

    strings:
        // verb -> Lsa\(Security|Authentication|Notification) Packages -> evil-name OR user-writable dll
        $bound_lsa = /(Set-ItemProperty|New-ItemProperty|reg(\.exe)?\s+add|AddMultiString)\s+[^\r\n]{0,200}Control[\\\/]+Lsa\b[^\r\n]{0,200}(Security Packages|Authentication Packages|Notification Packages)\b[^\r\n]{0,300}(memssp|mimilib|mimilsa|kiwissp|[A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.dll)/is ascii wide

        // reverse: package value mentions evil DLL near the Lsa key + verb
        $bound_evil = /(memssp|mimilib|mimilsa|kiwissp)[^\r\n]{0,200}(Security Packages|Authentication Packages|Notification Packages)[\s\S]{0,300}(Set-ItemProperty|New-ItemProperty|reg(\.exe)?\s+add)/is ascii wide

        // Lsa\OSConfig\Skew1 + write + ssp value
        $bound_skew = /(Set-ItemProperty|New-ItemProperty|reg(\.exe)?\s+add)\s+[^\r\n]{0,200}Control[\\\/]+Lsa[\\\/]+(OSConfig|Skew1)\b[^\r\n]{0,300}(Security Packages|memssp|mimilib|mimilsa)/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $bound_lsa or $bound_evil or $bound_skew )
}

/* -----------------------------------------------------------------------------
   PER_HIGH_COM_Hijack_HKCU_InprocServer32
   HKCU\Software\Classes\CLSID\{GUID}\InprocServer32 (or TreatAs) + write verb +
   user-writable DLL path, all bound. HKCU means no admin required.
   ----------------------------------------------------------------------------- */
rule PER_HIGH_COM_Hijack_HKCU_InprocServer32
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "persistence"
        severity = "high"
        description = "Bound HKCU COM CLSID InprocServer32/TreatAs write to user-writable DLL"
        mitre = "T1546.015"

    strings:
        // verb -> HKCU CLSID {GUID} InprocServer32/TreatAs -> user-writable dll
        $bound_inproc = /(Set-ItemProperty|New-ItemProperty|New-Item\s+-Path|reg(\.exe)?\s+add)\s+[^\r\n]{0,200}HKCU[\\\/]+Software[\\\/]+Classes[\\\/]+CLSID[\\\/]+\{[A-Fa-f0-9\-]{36}\}[^\r\n]{0,200}(InprocServer32|TreatAs)\b[^\r\n]{0,300}(["']?[A-Za-z]:\\(Users\\[^"'\\\r\n]{1,80}\\|ProgramData\\|Users\\Public\\|Windows\\Temp\\|Temp\\)[^"'\r\n]{0,160}\.(dll|ocx)["']?|["']?%(LOCALAPPDATA|APPDATA|TEMP|TMP|PUBLIC|ProgramData)%[^"'\r\n]{1,160}\.(dll|ocx))/is ascii wide

        // alt order: CLSID path then verb then dll
        $bound_revin = /HKCU[\\\/]+Software[\\\/]+Classes[\\\/]+CLSID[\\\/]+\{[A-Fa-f0-9\-]{36}\}[^\r\n]{0,200}(InprocServer32|TreatAs)\b[\s\S]{0,300}(Set-ItemProperty|New-ItemProperty|reg(\.exe)?\s+add)[^\r\n]{0,200}([A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.(dll|ocx))/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $bound_inproc or $bound_revin )
}

/* -----------------------------------------------------------------------------
   PER_HIGH_Print_Monitor_Persistence
   Print\Monitors\<name>\Driver + write verb + user-writable DLL bound.
   ----------------------------------------------------------------------------- */
rule PER_HIGH_Print_Monitor_Persistence
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "persistence"
        severity = "high"
        description = "Bound Print\\Monitors\\<name>\\Driver write to user-writable DLL"
        mitre = "T1547.010"

    strings:
        // verb -> Print\Monitors\<name>\Driver -> user-writable dll
        $bound_pmon = /(Set-ItemProperty|New-ItemProperty|New-Item\s+-Path|reg(\.exe)?\s+add)\s+[^\r\n]{0,200}Control[\\\/]+Print[\\\/]+Monitors[\\\/]+[^"'\r\n\\\/]{2,80}[^\r\n]{0,80}Driver\b[^\r\n]{0,250}["']?([A-Za-z]:\\(Users\\[^"'\\\r\n]{1,80}\\|ProgramData\\|Users\\Public\\|Windows\\Temp\\|Temp\\)[^"'\r\n]{0,160}\.dll|%(LOCALAPPDATA|APPDATA|TEMP|ProgramData)%[^"'\r\n]{0,160}\.dll)["']?/is ascii wide

        // AddMonitor[AW] API call + user-writable dll near it
        $bound_addm = /\bAddMonitor[AW]?\b[\s\S]{0,300}[A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.dll/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $bound_pmon or $bound_addm )
}

/* -----------------------------------------------------------------------------
   PER_HIGH_Scheduled_Task_PS_Encoded_Or_UserWritable
   schtasks /create | Register-ScheduledTask + -tr/-Action + PS cradle or
   user-writable script path, all bound.
   ----------------------------------------------------------------------------- */
rule PER_HIGH_Scheduled_Task_PS_Encoded_Or_UserWritable
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "persistence"
        severity = "high"
        description = "Bound schtasks/Register-ScheduledTask + action argument + PS cradle or user-writable script"
        mitre = "T1053.005"

    strings:
        // schtasks /create ... /tr <payload>
        $bound_st = /\bschtasks(\.exe)?\s+\/create\b[^\r\n]{0,300}\/tr\s+["']?[^\r\n]{0,250}((powershell|pwsh)(\.exe)?\s+[^"\r\n]{0,200}(-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{60,}|IEX|Invoke-Expression|DownloadString|FromBase64String|-w(in(dowstyle)?)?\s+h(idden)?[^\r\n]{0,80}-(ep|executionpolicy)\s+(bypass|unrestricted))|[A-Za-z]:\\(Users\\[^"'\\\r\n]{1,80}\\|ProgramData\\|Users\\Public\\|Windows\\Temp\\|Temp\\)[^"'\r\n]{0,160}\.(ps1|vbs|hta|js|bat|cmd|exe|scr|wsf)|mshta(\.exe)?\s+https?:\/\/|rundll32(\.exe)?\s+javascript:)/is ascii wide

        // New-ScheduledTaskAction -Execute ... -Argument <cradle>
        $bound_nst = /(New-ScheduledTaskAction|Register-ScheduledTask)\b[^\r\n]{0,300}(-Execute|-Argument|-Action)\s+["']?[^\r\n]{0,250}((powershell|pwsh)(\.exe)?[^"\r\n]{0,200}(-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{60,}|IEX|Invoke-Expression|DownloadString|FromBase64String)|[A-Za-z]:\\(Users\\[^"'\\\r\n]{1,80}\\|ProgramData\\|Users\\Public\\|Windows\\Temp\\|Temp\\)[^"'\r\n]{0,160}\.(ps1|vbs|hta|js|bat|cmd|exe))/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $bound_st or $bound_nst )
}

/* -----------------------------------------------------------------------------
   PER_HIGH_Startup_Folder_Script_Drop
   Bound write-op + Startup path + script ext within 250 chars (bidirectional).
   Does NOT match vcredist installer logs that mention \Startup, copy, and .exe
   on unrelated lines.
   ----------------------------------------------------------------------------- */
rule PER_HIGH_Startup_Folder_Script_Drop
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "persistence"
        severity = "medium-high"
        description = "Bound write-op + Startup folder path + script/binary file-suffix in one window"
        mitre = "T1547.001"

    strings:
        // verb -> Startup path -> ext, 0..250 chars between verb and target
        $bound_wpe = /(Set-Content|Out-File|Add-Content|Copy-Item|Move-Item|\bcopy\b|\bxcopy\b|New-Item\s+-Path|FileStream|\[IO\.File\]::Write|WriteAllText|WriteAllBytes)[^\r\n]{0,250}[\\\/](Microsoft|ProgramData[\\\/]+Microsoft)[\\\/]+Windows[\\\/]+Start Menu[\\\/]+Programs[\\\/]+Start[Uu]p[\\\/]+[^"'\r\n\\\/]{1,80}\.(ps1|vbs|hta|js|bat|cmd|exe|scr|lnk|wsf|jse|vbe)\b/is ascii wide

        // reverse: Startup\file.ext -> verb close
        $bound_pew = /[\\\/](Microsoft|ProgramData[\\\/]+Microsoft)[\\\/]+Windows[\\\/]+Start Menu[\\\/]+Programs[\\\/]+Start[Uu]p[\\\/]+[^"'\r\n\\\/]{1,80}\.(ps1|vbs|hta|js|bat|cmd|exe|scr|lnk|wsf|jse|vbe)\b[^\r\n]{0,250}(Set-Content|Out-File|Add-Content|Copy-Item|Move-Item|\bcopy\b|\bxcopy\b|New-Item|FileStream|WriteAllText|WriteAllBytes)/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $bound_wpe or $bound_pew )
}

/* -----------------------------------------------------------------------------
   PER_HIGH_DotNet_AppDomainManager_Hijack
   .exe.config + appDomainManagerAssembly + appDomainManagerType, paired bound.
   ----------------------------------------------------------------------------- */
rule PER_HIGH_DotNet_AppDomainManager_Hijack
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "persistence"
        severity = "high"
        description = "Bound .NET AppDomainManager hijack: appDomainManagerAssembly + appDomainManagerType in .exe.config"
        mitre = "T1574.014"

    strings:
        // both elements together within a config-shaped window
        $bound_pair = /<appDomainManagerAssembly\s+value\s*=\s*["'][^"']{1,200}["'][\s\S]{0,500}<appDomainManagerType\s+value\s*=\s*["'][^"']{1,200}["']/is ascii wide
        $bound_rpair = /<appDomainManagerType\s+value\s*=\s*["'][^"']{1,200}["'][\s\S]{0,500}<appDomainManagerAssembly\s+value\s*=\s*["'][^"']{1,200}["']/is ascii wide

        // one element paired with .exe.config reference in same window
        $bound_cfga = /\.(exe|dll)\.config\b[\s\S]{0,600}<appDomainManagerAssembly\s+value\s*=/is ascii wide
        $bound_cfgt = /\.(exe|dll)\.config\b[\s\S]{0,600}<appDomainManagerType\s+value\s*=/is ascii wide
        $bound_cfga2= /<appDomainManagerAssembly\s+value\s*=[\s\S]{0,600}\.(exe|dll)\.config\b/is ascii wide
        $bound_cfgt2= /<appDomainManagerType\s+value\s*=[\s\S]{0,600}\.(exe|dll)\.config\b/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and any of ( $bound_pair, $bound_rpair, $bound_cfga, $bound_cfgt, $bound_cfga2, $bound_cfgt2 )
}

/* -----------------------------------------------------------------------------
   PER_HIGH_PowerShell_Profile_Tampering
   Write to $PROFILE / Microsoft.PowerShell_profile.ps1 + IEX/DownloadString/
   -enc/FromBase64String in proximity, bound.
   ----------------------------------------------------------------------------- */
rule PER_HIGH_PowerShell_Profile_Tampering
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "persistence"
        severity = "high"
        description = "Bound write to $PROFILE / *_profile.ps1 paired with IEX/DownloadString/-enc/FromBase64String"
        mitre = "T1546.013"

    strings:
        // verb -> profile path -> payload
        $bound_vpp = /(Set-Content|Out-File|Add-Content|Append|FileStream|>>|\[IO\.File\]::Append(All)?Text|WriteAllText)\s*[^\r\n]{0,200}(\$PROFILE|[\\\/](WindowsPowerShell|PowerShell)[\\\/](Microsoft\.PowerShell(ISE)?_profile\.ps1|profile\.ps1))[^\r\n]{0,300}(IEX|Invoke-Expression|DownloadString|Net\.WebClient|Invoke-WebRequest|FromBase64String|-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{60,})/is ascii wide

        // payload -> profile path -> verb
        $bound_ppv = /(IEX|Invoke-Expression|DownloadString|FromBase64String|-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{60,})[\s\S]{0,300}(\$PROFILE|[\\\/](WindowsPowerShell|PowerShell)[\\\/](Microsoft\.PowerShell(ISE)?_profile\.ps1|profile\.ps1))[^\r\n]{0,250}(Set-Content|Out-File|Add-Content|Append|>>|WriteAllText)/is ascii wide

        // profile path -> payload -> verb
        $bound_pvp = /(\$PROFILE|[\\\/](WindowsPowerShell|PowerShell)[\\\/](Microsoft\.PowerShell(ISE)?_profile\.ps1|profile\.ps1))[\s\S]{0,300}(IEX|Invoke-Expression|DownloadString|FromBase64String)[\s\S]{0,200}(Set-Content|Out-File|Add-Content|>>|WriteAllText)/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $bound_vpp or $bound_ppv or $bound_pvp )
}

/* -----------------------------------------------------------------------------
   PER_HIGH_BITS_Job_Persistence
   bitsadmin /create + /addfile + /setnotifycmdline bound, OR PS Start-BitsTransfer
   with -NotifyCmdLine + payload bound.
   ----------------------------------------------------------------------------- */
rule PER_HIGH_BITS_Job_Persistence
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "persistence"
        severity = "high"
        description = "Bound bitsadmin /create + /addfile + /setnotifycmdline (or Start-BitsTransfer -NotifyCmdLine) + payload"
        mitre = "T1197"

    strings:
        // /create -> /addfile -> /setnotifycmdline + payload in window
        $bound_bits = /\bbitsadmin(\.exe)?\s+\/create\b[\s\S]{0,600}\bbitsadmin(\.exe)?\s+\/addfile\b[\s\S]{0,600}\bbitsadmin(\.exe)?\s+\/SetNotifyCmdLine\b[^\r\n]{0,300}(powershell|pwsh|cmd(\.exe)?|mshta|rundll32|regsvr32|wscript|cscript|[A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.(exe|dll|ps1|cmd|bat|scr))/is ascii wide

        // PS Start-BitsTransfer -NotifyCmdLine <payload>
        $bound_psbt = /\bStart-BitsTransfer\b[\s\S]{0,400}-NotifyCmdLine\s+["']?[^\r\n]{0,250}(powershell|pwsh|cmd(\.exe)?|mshta|rundll32|[A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.(exe|dll|ps1|cmd|bat))/is ascii wide

        // /setnotifycmdline alone + /addfile + payload (covers split-line scripts)
        $bound_alt = /\bbitsadmin(\.exe)?\s+\/SetNotifyCmdLine\b[^\r\n]{0,300}(powershell|pwsh|cmd\.exe|mshta|rundll32|[A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.(exe|dll|ps1|cmd|bat))[\s\S]{0,600}\bbitsadmin(\.exe)?\s+\/addfile\b/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $bound_bits or $bound_psbt or $bound_alt )
}

/* -----------------------------------------------------------------------------
   PER_HIGH_GPO_Scheduled_Task_Or_Logon_Script
   SYSVOL Policies path + ScheduledTasks.xml / Scripts.ini + cmd payload, bound.
   ----------------------------------------------------------------------------- */
rule PER_HIGH_GPO_Scheduled_Task_Or_Logon_Script
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "persistence"
        severity = "medium-high"
        description = "Bound SYSVOL Policies + ScheduledTasks.xml / Scripts.ini + cmd payload (user-writable or LOLBAS)"
        mitre = "T1053.005,T1037.001"

    strings:
        // SYSVOL Policies -> ScheduledTasks.xml -> Exec Command payload
        $bound_gpst = /(SYSVOL[\\\/]+[^\r\n\\\/]{1,80}[\\\/]+Policies|[\\\/]Policies[\\\/]+\{[A-Fa-f0-9\-]{36}\})[\s\S]{0,400}[\\\/]+Preferences[\\\/]+ScheduledTasks[\\\/]+ScheduledTasks\.xml\b[\s\S]{0,800}<(Exec\s+Command|Task[\s\S]{0,100}Command)[^>]{0,200}["'][^"'\r\n]{0,200}(powershell|pwsh|cmd\.exe|mshta|rundll32|certutil|bitsadmin|[A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.(ps1|vbs|hta|js|bat|cmd|exe))/is ascii wide

        // ScheduledTasks.xml + <ScheduledTasks ...> + Args containing payload (no SYSVOL prefix; staging dir variant)
        $bound_xml = /[\\\/]+Preferences[\\\/]+ScheduledTasks[\\\/]+ScheduledTasks\.xml\b[\s\S]{0,400}<ScheduledTasks\b[\s\S]{0,800}(<Exec\s+Command|<Arguments)[^>]{0,300}(powershell|pwsh|cmd\.exe|mshta|rundll32|certutil|bitsadmin|[A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.(ps1|vbs|hta|js|bat|cmd|exe))/is ascii wide

        // SYSVOL/Policies -> Scripts\Logon\scripts.ini -> payload
        $bound_gpls = /(SYSVOL[\\\/]+[^\r\n\\\/]{1,80}[\\\/]+Policies|[\\\/]Policies[\\\/]+\{[A-Fa-f0-9\-]{36}\})[\s\S]{0,400}[\\\/]+(User|Machine)[\\\/]+Scripts[\\\/]+(Logon|Logoff|Startup|Shutdown)[\\\/]+scripts\.ini\b[\s\S]{0,800}(CmdLine\s*=|Parameters\s*=)[^\r\n]{0,250}(powershell|pwsh|cmd\.exe|mshta|rundll32|[A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.(ps1|vbs|hta|js|bat|cmd|exe))/is ascii wide

        // scripts.ini + CmdLine= payload (staging variant)
        $bound_ini = /[\\\/]+Scripts[\\\/]+(Logon|Logoff|Startup|Shutdown)[\\\/]+scripts\.ini\b[\s\S]{0,400}(CmdLine\s*=|Parameters\s*=)[^\r\n]{0,250}(powershell|pwsh|cmd\.exe|mshta|rundll32|[A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^"'\r\n]{1,160}\.(ps1|vbs|hta|js|bat|cmd|exe))/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $bound_gpst or $bound_xml or $bound_gpls or $bound_ini )
}
