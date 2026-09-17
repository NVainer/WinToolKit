/*
================================================================================
 02_lolbas_abuse.yar
 Author: Nati
 Category: LOLBAS Abuse - Living Off the Land Binaries
 Severity: Medium-High to High
 Last updated: 2026-05-24

 Design: every rule binds <binary> + <abused-flag/verb> + <payload-shape>
 (URL, UNC, user-writable path, or cmd/PS payload) inside a SINGLE proximity-
 bounded regex. No standalone keyword OR branches. All invocation strings are
 matched ascii+wide because PowerShell stores them as UTF-16LE. Every rule
 short-circuits on PE / ELF headers (LOLBins live in scripts and logs, not in
 PE binaries) and caps filesize to keep scans cheap.

 Coverage:
   - certutil: -urlcache / -decode bound to URL or user-writable path
   - bitsadmin: /transfer bound to URL + user-writable destination
   - mshta: remote HTA / javascript: / vbscript: / UNC .hta
   - regsvr32: Squiblydoo (/i:URL + scrobj.dll, both orderings)
   - rundll32: javascript: (Squiblytwo), user-dir DLL, comsvcs MiniDump
   - msbuild: inline task XML bound to user-path .csproj/.proj invocation
   - installutil: /U from user-writable path
   - wmic: process call create bound to cmd/PS/LOLBin payload; /node: variant
   - cmstp: /ni /s bound to URL/UNC/user path; INF RunPreSetupCommands payload
   - mavinject / cdb / tracker / pcalua / presentationhost bound to abuse args
   - xwizard.exe: ONLY inside an execution context (cmd/c, Start-Process, ...)
   - ie4uinit.exe: ONLY -BaseSettings (legit -UserConfig/-ClearIconCache skipped)
   - forfiles: /c bound to cmd/PS/LOLBin spawn
   - hh.exe: bound to URL / UNC / mk:@MSITStore in user path
   - msdt: PCWDiagnostic + IT_LaunchMethod=ContextMenu (Follina)
   - wsl.exe: bound to -e/--exec/bash -c (Windows-only org)
   - cscript/wscript: bound to user-writable or UNC/HTTP source

 WSL rule assumes no Linux in the org (per Nati's environment).
================================================================================
*/

/* -----------------------------------------------------------------------------
   LOL_HIGH_Certutil_URLCache_Download
   certutil -urlcache -split -f <URL>  or  -verifyctl <URL>
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_Certutil_URLCache_Download
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_download"
        severity = "high"
        description = "certutil URL-cache download - bound: certutil + -urlcache/-verifyctl + http(s)/user-writable target"
        mitre = "T1105,T1218"
        reference = "https://lolbas-project.github.io/lolbas/Binaries/Certutil/"

    strings:
        $bound = /\bcertutil(\.exe)?\s+(-[A-Za-z?]+\s+){0,4}-(urlcache|verifyctl)\b[^\r\n]{0,200}(https?:\/\/|ftp:\/\/|\\\\[^\\\s'"`]{1,80}\\)[^\s'"`\r\n|&;]{4,300}/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 50MB
        and $bound
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_Certutil_Decode_Base64
   certutil -decode/-decodehex <encoded> <user-writable executable output>
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_Certutil_Decode_Base64
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_decode"
        severity = "high"
        description = "certutil -decode/-decodehex bound to executable output in user-writable path (LOLBAS)"
        mitre = "T1140,T1218"
        reference = "https://lolbas-project.github.io/lolbas/Binaries/Certutil/"

    strings:
        $bound = /\bcertutil(\.exe)?\s+(-[A-Za-z?]+\s+){0,4}-(decode|decodehex)\b[^\r\n]{0,200}["']?([A-Z]:\\(Users|ProgramData|Temp|Windows\\Temp|Users\\Public)\\|%TEMP%|%APPDATA%|%LOCALAPPDATA%|%PUBLIC%|\$env:(TEMP|APPDATA|LOCALAPPDATA|PUBLIC))[^"'\r\n]{1,256}\.(exe|dll|bat|ps1|vbs|hta|js|wsf|cmd|scr|jar|jse|vbe|cpl|msi|wsh|psm1)["']?/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and $bound
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_Bitsadmin_HTTP_Transfer
   bitsadmin /transfer bound to URL + user-writable destination.
   PowerShell Start-BitsTransfer variant proximity-bound.
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_Bitsadmin_HTTP_Transfer
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_download"
        severity = "high"
        description = "bitsadmin /transfer or Start-BitsTransfer - bound: URL source + user-writable destination"
        mitre = "T1105,T1197,T1218"
        reference = "https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/"

    strings:
        $bits_cli = /\bbitsadmin(\.exe)?\s+(\/[A-Za-z]+\s+){0,3}\/transfer\b[^\r\n]{0,200}(https?:\/\/|ftp:\/\/)[^\s"'\r\n]{4,200}[^\r\n]{0,80}["']?([A-Z]:\\(Users|ProgramData|Temp|Windows\\Temp|Users\\Public)\\|%TEMP%|%APPDATA%|%LOCALAPPDATA%|%PUBLIC%)/i ascii wide
        $ps_bits  = /Start-BitsTransfer\b[^;\r\n]{0,200}-Source\s+["']?(https?:\/\/|ftp:\/\/)[^"'\s\r\n]{4,256}["']?[^;\r\n]{0,200}-Destination\s+["']?([A-Z]:\\(Users|ProgramData|Temp|Windows\\Temp|Users\\Public)\\|%TEMP%|%APPDATA%|%LOCALAPPDATA%|%PUBLIC%|\$env:(TEMP|APPDATA|PUBLIC|LOCALAPPDATA))/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_Mshta_Remote_Or_Protocol
   mshta <URL> | javascript: | vbscript: | UNC .hta - all in single bound regex.
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_Mshta_Remote_Or_Protocol
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_execution"
        severity = "high"
        description = "mshta loading remote HTA, javascript:, vbscript:, or UNC .hta - each bound to mshta + payload"
        mitre = "T1218.005"
        reference = "https://lolbas-project.github.io/lolbas/Binaries/Mshta/"

    strings:
        $remote_hta = /\bmshta(\.exe)?\s+["']?(https?:\/\/|file:\/\/\/?\\\\)[^\s'"`\r\n|&;]{4,300}/i ascii wide
        $js_proto   = /\bmshta(\.exe)?\s+["']?javascript\s*:\s*[^\r\n]{4,400}/i ascii wide
        $vbs_proto  = /\bmshta(\.exe)?\s+["']?vbscript\s*:\s*[^\r\n]{4,400}/i ascii wide
        $unc_hta    = /\bmshta(\.exe)?\s+["']?\\\\[^\\\s'"`]{1,80}\\[^\s'"`\r\n]{1,200}\.hta\b/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_Regsvr32_Squiblydoo
   regsvr32 /i:http://... scrobj.dll  (both orderings)
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_Regsvr32_Squiblydoo
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_execution"
        severity = "high"
        description = "regsvr32 Squiblydoo - bound: regsvr32 + /i:URL + scrobj.dll within same string"
        mitre = "T1218.010"
        reference = "https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/"

    strings:
        $bound  = /\bregsvr32(\.exe)?\s+(\/[a-zA-Z]\s+){0,3}\/(i|n)\s*:\s*["']?(https?:\/\/|\\\\)[^\s'"`\r\n|&;]{4,300}["']?[^\r\n]{0,80}scrobj\.dll\b/i ascii wide
        $bound2 = /\bregsvr32(\.exe)?\s+(\/[a-zA-Z]\s+){0,3}scrobj\.dll\b[^\r\n]{0,200}\/(i|n)\s*:\s*["']?(https?:\/\/|\\\\)[^\s'"`\r\n|&;]{4,300}/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_Rundll32_Javascript_Squiblytwo
   rundll32 javascript:...RunHTMLApplication  OR  user-dir .dll with export.
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_Rundll32_Javascript_Squiblytwo
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_execution"
        severity = "high"
        description = "rundll32 Squiblytwo (javascript:+RunHTMLApplication) or rundll32 of user-writable .dll/.cpl/.ocx with export"
        mitre = "T1218.011"
        reference = "https://lolbas-project.github.io/lolbas/Binaries/Rundll32/"

    strings:
        $squiblytwo  = /\brundll32(\.exe)?\s+["']?javascript\s*:\s*[^\r\n]{4,400}(RunHTMLApplication|mshtml|GetObject\s*\(\s*["']script\s*:)/i ascii wide
        $userdir_dll = /\brundll32(\.exe)?\s+["']?([A-Z]:\\Users\\[^\\\s'"`]{1,80}\\|%APPDATA%|%LOCALAPPDATA%|%TEMP%|%PUBLIC%|\$env:(APPDATA|LOCALAPPDATA|TEMP|PUBLIC))[^\s'"`\r\n]{1,256}\.(dll|cpl|ocx)["']?\s*,\s*[A-Za-z@#_][A-Za-z0-9_@#]{1,64}/i ascii wide
        $exporthint  = /\brundll32(\.exe)?\s+["']?[A-Z]:\\(Users|ProgramData|Temp|Windows\\Temp|Users\\Public)\\[^\s'"`\r\n]{4,256}\.(dll|cpl|ocx)["']?\s*,\s*(DllRegisterServer|DllInstall|EntryPoint|RunDll)/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_Rundll32_Comsvcs_MiniDump
   rundll32 comsvcs.dll MiniDump <pid> <out> full  (LSASS dump primitive)
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_Rundll32_Comsvcs_MiniDump
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "credential_access"
        severity = "high"
        description = "rundll32 comsvcs.dll MiniDump - bound: rundll32 + comsvcs.dll + MiniDump + pid/lsass arg"
        mitre = "T1003.001,T1218.011"
        reference = "https://lolbas-project.github.io/lolbas/Binaries/Rundll32/"

    strings:
        $bound     = /\brundll32(\.exe)?\s+["']?[A-Z]?:?\\?(Windows\\?System32\\?)?comsvcs\.dll["']?\s*[, ]\s*(#?\+?24|MiniDump|MiniDumpW)\b[^\r\n]{0,200}(lsass|\$\w+|\d{2,6})/i ascii wide
        $ps_invoke = /(Start-Process|Invoke-Expression|iex)\b[^;\r\n]{0,200}rundll32[^;\r\n]{0,200}comsvcs\.dll[^;\r\n]{0,80}MiniDump/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_Msbuild_Inline_Task
   msbuild + UsingTask CodeTaskFactory bound to user-path .csproj/.proj CLI.
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_Msbuild_Inline_Task
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_execution"
        severity = "high"
        description = "MSBuild inline task - bound: CodeTaskFactory/RoslynCodeTaskFactory + msbuild CLI on user-writable project"
        mitre = "T1127.001,T1218"
        reference = "https://lolbas-project.github.io/lolbas/Binaries/Msbuild/"

    strings:
        $ut_factory = /<UsingTask\b[^>]{0,400}TaskFactory\s*=\s*["'](Code|RoslynCode)TaskFactory["']/i ascii wide
        $code_elem  = /<Code\s+Type\s*=\s*["'](Class|Method|Fragment)["']/i ascii wide
        $cli        = /\bmsbuild(\.exe)?\s+(\/\w+\s+){0,3}["']?([A-Z]:\\(Users|ProgramData|Temp|Windows\\Temp|Users\\Public)\\|%TEMP%|%APPDATA%|%PUBLIC%|\$env:(TEMP|APPDATA|PUBLIC|LOCALAPPDATA))[^\s'"`\r\n]{1,256}\.(csproj|proj|xml)["']?/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and (
            ($ut_factory and $code_elem)
            or ($ut_factory and $cli)
            or ($code_elem and $cli)
        )
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_InstallUtil_Uninstall_Bypass
   installutil /U bound to user-writable .exe/.dll path.
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_InstallUtil_Uninstall_Bypass
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_execution"
        severity = "high"
        description = "InstallUtil /U bound to user-writable .exe/.dll target (AppLocker bypass via Uninstall())"
        mitre = "T1218.004"
        reference = "https://lolbas-project.github.io/lolbas/Binaries/Installutil/"

    strings:
        $bound = /\binstallutil(\.exe)?\s+(\/\w+(\s|=)\S*\s+){0,3}\/U(ninstall)?\b\s+["']?([A-Z]:\\(Users|ProgramData|Temp|Windows\\Temp|Users\\Public)\\|%TEMP%|%APPDATA%|%PUBLIC%|\$env:(TEMP|APPDATA|PUBLIC|LOCALAPPDATA))[^\s'"`\r\n]{1,256}\.(exe|dll)["']?/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and $bound
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_WMIC_Process_Call_Create
   wmic process call create bound to cmd/PS/IEX/LOLBin payload (not arbitrary
   strings - explorer.exe respawn scripts used by IT admins must not fire).
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_WMIC_Process_Call_Create
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_execution"
        severity = "high"
        description = "wmic process call create - bound to cmd/c, powershell -, pwsh -, IEX, or LOLBin payload (local or /node:)"
        mitre = "T1047,T1218,T1021.006"
        reference = "https://lolbas-project.github.io/lolbas/Binaries/Wmic/"

    strings:
        $local  = /\bwmic(\.exe)?\s+(\/\w+:\S+\s+){0,2}process\s+(where\s+\S+\s+)?call\s+create\s+["']?(cmd(\.exe)?\s+\/[ckqr]\b|powershell(\.exe)?\s+-|pwsh(\.exe)?\s+-|Invoke-Expression\b|\biex\b|rundll32|regsvr32|mshta|certutil|bitsadmin|wscript|cscript)/i ascii wide
        $remote = /\bwmic(\.exe)?\s+\/node\s*:\s*["']?[^\s'"`]{1,80}["']?\s+(\/\w+:\S+\s+){0,2}process\s+(where\s+\S+\s+)?call\s+create\s+["']?(cmd(\.exe)?\s+\/[ckqr]\b|powershell(\.exe)?\s+-|pwsh(\.exe)?\s+-|Invoke-Expression\b|\biex\b|rundll32|regsvr32|mshta|certutil|bitsadmin|wscript|cscript)/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_Cmstp_Remote_INF
   cmstp /ni /s bound to remote/UNC/user-writable INF, plus INF content marker.
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_Cmstp_Remote_INF
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_execution"
        severity = "high"
        description = "cmstp /ni /s bound to remote/UNC/user-writable INF, or INF RunPreSetupCommands payload (LOLBAS UAC bypass)"
        mitre = "T1218.003,T1548.002"
        reference = "https://lolbas-project.github.io/lolbas/Binaries/Cmstp/"

    strings:
        $cli        = /\bcmstp(\.exe)?\s+(\/\w+\s+){0,3}\/ni\s+\/s\s+["']?(https?:\/\/|\\\\|[A-Z]:\\(Users|ProgramData|Temp|Windows\\Temp|Users\\Public)\\|%TEMP%|%APPDATA%|%PUBLIC%)/i ascii wide
        $inf_runpre = /\[RunPreSetupCommands(Section)?\][^\[]{0,400}(taskkill|cmd(\.exe)?\s+\/[ckq]|powershell|pwsh|rundll32|regsvr32|certutil|mshta)/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_Forfiles_Cmd_Spawn
   forfiles /c "cmd /c ..." or PowerShell/LOLBin spawn - parent process spoofing.
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_Forfiles_Cmd_Spawn
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_execution"
        severity = "medium"
        description = "forfiles /c bound to cmd /c, powershell/pwsh, or LOLBin spawn (parent process spoofing)"
        mitre = "T1202,T1218"
        reference = "https://lolbas-project.github.io/lolbas/Binaries/Forfiles/"

    strings:
        $bound = /\bforfiles(\.exe)?\s+\/p\s+["']?[^"'\r\n]{1,200}["']?\s+(\/m\s+\S+\s+)?\/c\s+["']?(cmd(\.exe)?\s+\/[ckqr]\b|powershell(\.exe)?\s|pwsh(\.exe)?\s|rundll32\s|regsvr32\s|mshta\s|certutil\s)/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and $bound
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_Hh_Exe_Remote_URL
   hh.exe <URL> | <UNC> | mk:@MSITStore: in user-writable path.
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_Hh_Exe_Remote_URL
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_execution"
        severity = "high"
        description = "hh.exe bound to remote URL, UNC .chm, or mk:@MSITStore in user-writable path (LOLBAS)"
        mitre = "T1218.001"
        reference = "https://lolbas-project.github.io/lolbas/Binaries/Hh/"

    strings:
        $url  = /\bhh(\.exe)?\s+["']?(https?:\/\/|\\\\[^\\\s'"`]{1,80}\\)[^\s'"`\r\n|&;]{4,300}/i ascii wide
        $msit = /\bhh(\.exe)?\s+["']?mk:@MSITStore:([A-Z]:\\(Users|ProgramData|Temp|Windows\\Temp|Users\\Public)\\|%TEMP%|%APPDATA%|%PUBLIC%)/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_Msdt_Follina_Pattern
   ms-msdt: PCWDiagnostic + IT_LaunchMethod=ContextMenu (CVE-2022-30190 Follina)
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_Msdt_Follina_Pattern
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_execution"
        severity = "high"
        description = "ms-msdt Follina (CVE-2022-30190) - bound: PCWDiagnostic + IT_LaunchMethod=ContextMenu / IT_BrowseForFile payload"
        mitre = "T1218,T1203"
        reference = "CVE-2022-30190 / Follina"

    strings:
        $proto_full = /ms-msdt\s*:\s*\/?\/?id\s*\/?\s*PCWDiagnostic\b[^\r\n]{0,400}IT_LaunchMethod\s*=\s*ContextMenu/i ascii wide
        $cli_full   = /\bmsdt(\.exe)?\s+(-|\/)?id\s+PCWDiagnostic\b[^\r\n]{0,400}IT_LaunchMethod\s*=\s*ContextMenu/i ascii wide
        $proto_br   = /ms-msdt\s*:\s*\/?\/?id\s*\/?\s*PCWDiagnostic\b[^\r\n]{0,400}IT_(Rebrowse|Browse)ForFile\s*=\s*[^\r\n]{1,200}\$\(/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_Ie4uinit_Pcalua_Xwizard_Misc
   Less-common LOLBAS - each binary bound to its abuse syntax only.
   - ie4uinit:  ONLY -BaseSettings  (-UserConfig / -ClearIconCache are legit
                Windows startup invocations recorded in ExplorerStartupLog.etl)
   - xwizard:   ONLY inside an execution context (cmd /c, Start-Process, &,
                start, schtasks /tr, Set-ItemProperty for Run-key, .lnk target)
                within 40 chars - bare `xwizard RunWizard {GUID}` in the
                SettingsCache.txt must NOT match.
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_Ie4uinit_Pcalua_Xwizard_Misc
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_execution"
        severity = "high"
        description = "Less-common LOLBAS bound to abuse syntax: ie4uinit -BaseSettings, pcalua -a script, xwizard inside exec context, presentationhost remote .xbap, mavinject inject, cdb -cf user path, tracker /d /c"
        mitre = "T1218"

    strings:
        $ie4u         = /\bie4uinit(\.exe)?\s+-BaseSettings\b/i ascii wide
        $pcalua       = /\bpcalua(\.exe)?\s+(-\w+\s+){0,2}-a\s+["']?[^"'\s\r\n]{1,256}\.(exe|bat|cmd|ps1|vbs|hta|js|wsf)\b/i ascii wide
        $xwizard      = /(cmd(\.exe)?\s+\/c\s+|Start-Process\s+["']?|powershell(\.exe)?\s+[^;\r\n]{0,80}|pwsh(\.exe)?\s+[^;\r\n]{0,80}|&\s*['"]?|\bstart\s+["']?|schtasks(\.exe)?[^\r\n]{0,200}\/tr\s+["']?|Set-ItemProperty[^\r\n]{0,200}|target\s*=\s*["']?)[^\r\n]{0,40}\bxwizard(\.exe)?\s+RunWizard\s+\{[0-9A-Fa-f-]{36}\}/i ascii wide
        $presentation = /\bPresentationHost(\.exe)?\s+["']?(https?:\/\/|\\\\)[^\s'"`\r\n]{4,256}\.xbap\b/i ascii wide
        $mavinject    = /\bmavinject(32)?(\.exe)?\s+\d{1,6}\s+(\/INJECTRUNNING|\/HMODULE=)\s+["']?[A-Z]:\\[^"'\r\n]{1,256}\.dll["']?/i ascii wide
        $cdb          = /\bcdb(\.exe)?\s+(-\w+\s+){0,3}-cf\s+["']?[A-Z]:\\(Users|ProgramData|Temp|Windows\\Temp|Users\\Public)\\[^"'\r\n]{1,256}\.(txt|wds|ini)["']?/i ascii wide
        $tracker      = /\btracker(\.exe)?\s+\/d\s+["']?[A-Z]:\\[^"'\r\n]{1,256}\.(dll|exe)["']?\s+\/c\b/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_WSL_Execution_In_NoUnix_Org
   wsl.exe bound to -e / --exec / bash -c / sh -c.  Bare `wsl` is NOT enough.
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_WSL_Execution_In_NoUnix_Org
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_execution"
        severity = "high"
        description = "wsl.exe bound to -e/--exec/bash -c/sh -c with payload (anomalous in this Windows-only org)"
        mitre = "T1218,T1059.004"
        reference = "https://lolbas-project.github.io/lolbas/Binaries/Wsl/"

    strings:
        $bash_c   = /\bwsl(\.exe)?\s+(-d\s+\S{1,40}\s+)?(--exec|-e|bash\s+-c|sh\s+-c)\s+["']?[^"'\r\n]{1,400}/i ascii wide
        $wsl_tool = /\bwsl(\.exe)?\s+(-d\s+\S{1,40}\s+)?(--exec|-e)\s+(curl|wget|nc|ncat|bash|sh|python3?|perl|ruby)\b/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_Wmic_Format_XSL_Remote
   wmic /format:<URL or UNC> - XSL execution.
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_Wmic_Format_XSL_Remote
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_execution"
        severity = "high"
        description = "wmic /format bound to remote URL or UNC XSL (LOLBAS XSL script execution)"
        mitre = "T1220"
        reference = "https://lolbas-project.github.io/lolbas/Binaries/Wmic/"

    strings:
        $bound = /\bwmic(\.exe)?\s+(\S+\s+){0,4}\/format\s*:\s*["']?(https?:\/\/|\\\\)[^\s'"`\r\n|&;]{4,300}/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and $bound
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_Cscript_Wscript_UserPath_Or_Remote
   wscript/cscript bound to user-writable script path OR remote URL/UNC source.
   System wizard scripts in System32 must NOT fire.
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_Cscript_Wscript_UserPath_Or_Remote
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lolbas_execution"
        severity = "medium"
        description = "wscript/cscript bound to user-writable script or UNC/HTTP source (.vbs/.js/.wsf/.vbe/.jse/.wsh)"
        mitre = "T1059.005,T1059.007,T1218"

    strings:
        $user_path = /\b(w|c)script(\.exe)?\s+(\/\w+(:\S+)?\s+){0,3}["']?([A-Z]:\\Users\\[^\\\s'"`]{1,80}\\(AppData|Downloads|Desktop|Documents)|[A-Z]:\\ProgramData\\|[A-Z]:\\Temp\\|[A-Z]:\\Windows\\Temp\\|[A-Z]:\\Users\\Public\\|%TEMP%|%APPDATA%|%LOCALAPPDATA%|%PUBLIC%|\$env:(TEMP|APPDATA|LOCALAPPDATA|PUBLIC))[^"'\r\n]{1,256}\.(vbs|vbe|js|jse|wsf|wsh)\b/i ascii wide
        $remote    = /\b(w|c)script(\.exe)?\s+(\/\w+(:\S+)?\s+){0,3}["']?(https?:\/\/|\\\\[^\\\s'"`]{1,80}\\)[^"'\r\n]{1,256}\.(vbs|vbe|js|jse|wsf|wsh)\b/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}
