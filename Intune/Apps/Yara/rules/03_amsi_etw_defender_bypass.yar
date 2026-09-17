/*
================================================================================
 03_amsi_etw_defender_bypass.yar
 Author: Nati
 Category: AMSI / ETW / Defender / ScriptBlock-Logging Bypass
 Severity: Medium-High to High
 Last updated: 2026-05-24

 Design principle (post-FP-storm revision):
   Every rule requires an ATTACK SHAPE — target function/symbol AND the
   patch/abuse verb bound together via proximity regex. Standalone keywords
   (amsiInitFailed alone, EtwEventWrite alone, Set-MpPreference alone) are
   forbidden because Defender's own data-collection scripts, Microsoft
   documentation in \ProgramData\Microsoft\, and ntdll-importing binaries
   legitimately contain those strings.

 Coverage (rule names preserved — Sentinel KQL depends on them):
   - AMSI reflection bypass (AmsiUtils + amsiInitFailed + SetValue bound)
   - AMSI memory patch (AmsiScanBuffer + VirtualProtect + patch bytes bound)
   - AMSI context/session reflection hijack (newer variants)
   - AMSI HWBP / LdrDllNotification bypass (binary-aware)
   - COR_PROFILER env hijack (var + CLSID + user-writable DLL bound)
   - ETW patching (EtwEventWrite + VirtualProtect + 0xC3/0xC2 ret bound)
   - ScriptBlock / Module logging disable (reg path + value 0 bound)
   - Defender Set-MpPreference disable (cmdlet + destructive flag bound)
   - Defender exclusion abuse (Add-MpPreference + user-writable path bound)
   - Defender process/service kill (kill verb + Defender binary bound)
   - Sysmon driver unload (verb + Sysmon name bound)
   - Constrained Language Mode escape (FullLanguage assignment from CLM ctx)
   - Tamper Protection bypass (reg path + value mod bound)
================================================================================
*/

/* -----------------------------------------------------------------------------
   AMSI_HIGH_Reflection_AmsiInitFailed_Bypass
   Matt Graeber AMSI bypass: AmsiUtils.amsiInitFailed reflection set $true.
   Requires the full class+field+SetValue($null,$true) chain bound.
   ----------------------------------------------------------------------------- */
rule AMSI_HIGH_Reflection_AmsiInitFailed_Bypass
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "amsi_bypass"
        severity = "high"
        description = "AMSI bypass: AmsiUtils GetField('amsiInitFailed').SetValue($null,$true) chain bound"
        mitre = "T1562.001,T1059.001"
        reference = "Matt Graeber 2016; canonical AMSI bypass PoC"

    strings:
        // Full chain: [Ref].Assembly.GetType('...AmsiUtils')...GetField('amsiInitFailed')...SetValue($null,$true)
        $bound_classic = /\[(Ref|System\.Reflection\.Assembly|Reflection\.Assembly)\][^\r\n]{0,80}\.Assembly[^\r\n]{0,80}GetType\s*\(\s*['"]System\.Management\.Automation\.AmsiUtils['"]\s*\)[^\r\n]{0,200}GetField\s*\(\s*['"]amsiInitFailed['"][^\r\n]{0,120}\.SetValue\s*\(\s*\$?null\s*,\s*\$?true\s*\)/is ascii wide

        // Obfuscated string-concat variant: 'amsi'+'Init'+'Failed' followed by SetValue($null,$true) within proximity
        $bound_obf_field = /['"]amsi['"]\s*\+\s*['"]Init['"]\s*\+\s*['"]Failed['"][^\r\n]{0,400}\.SetValue\s*\(\s*\$?null\s*,\s*\$?true\s*\)/is ascii wide

        // Obfuscated class-concat: 'Amsi'+'Utils' bound to GetField('amsiInitFailed') and SetValue($null,$true)
        $bound_obf_class = /['"]Amsi['"]\s*\+\s*['"]Utils['"][^\r\n]{0,400}GetField\s*\([^\r\n]{0,80}amsiInitFailed[^\r\n]{0,200}\.SetValue\s*\(\s*\$?null\s*,\s*\$?true\s*\)/is ascii wide

        // Split namespace: 'System.Management.Auto'+'mation.AmsiUtils' bound to SetValue($null,$true)
        $bound_obf_ns = /['"]System\.Management\.Auto['"]\s*\+\s*['"]mation\.[^\r\n]{0,200}\.SetValue\s*\(\s*\$?null\s*,\s*\$?true\s*\)/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and any of ($bound_*)
}

/* -----------------------------------------------------------------------------
   AMSI_HIGH_AmsiScanBuffer_Memory_Patch
   AMSI memory patching: AmsiScanBuffer target + VirtualProtect/Marshal.Copy
   verb + the actual patch byte sequence, all bound by proximity.
   ----------------------------------------------------------------------------- */
rule AMSI_HIGH_AmsiScanBuffer_Memory_Patch
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "amsi_bypass"
        severity = "high"
        description = "AMSI memory patch: AmsiScanBuffer + VirtualProtect/Marshal.Copy + ret/E_INVALIDARG byte stub bound"
        mitre = "T1562.001"
        reference = "Rasta-Mouse AMSI bypass; CyberArk research"

    strings:
        // AmsiScanBuffer target AND patch verb AND E_INVALIDARG stub (mov eax,0x80070057; ret) within proximity
        $bound_einval = /AmsiScanBuffer[^\r\n]{0,400}(VirtualProtect|Marshal\]::Copy|WriteProcessMemory)[^\r\n]{0,400}0x[bB]8\s*,\s*0x57\s*,\s*0x00\s*,\s*0x07\s*,\s*0x80\s*,\s*0x[cC]3/is ascii wide
        // Reverse order: patch bytes first, then AmsiScanBuffer target
        $bound_einval_rev = /0x[bB]8\s*,\s*0x57\s*,\s*0x00\s*,\s*0x07\s*,\s*0x80\s*,\s*0x[cC]3[^\r\n]{0,400}(VirtualProtect|Marshal\]::Copy|WriteProcessMemory)[^\r\n]{0,400}AmsiScanBuffer/is ascii wide

        // AmsiScanBuffer + patch verb + xor eax,eax / ret stub (0x31 0xC0 0xC3)
        $bound_xor = /AmsiScanBuffer[^\r\n]{0,400}(VirtualProtect|Marshal\]::Copy|WriteProcessMemory)[^\r\n]{0,400}0x31\s*,\s*0x[cC]0\s*,\s*0x[cC]3/is ascii wide

        // AmsiScanBuffer + patch verb + ret-only stub (0xC3) defined as byte array
        $bound_ret = /AmsiScanBuffer[^\r\n]{0,400}(VirtualProtect|Marshal\]::Copy|WriteProcessMemory)[^\r\n]{0,200}\[Byte\[\]\][^\r\n]{0,80}@?\(\s*0x[cC]3\s*\)/is ascii wide

        // GetProcAddress("AmsiScanBuffer") + VirtualProtect + any single-byte 0xC3 patch literal
        $bound_gpa = /GetProcAddress[^\r\n]{0,200}["']AmsiScanBuffer["'][^\r\n]{0,400}VirtualProtect[^\r\n]{0,400}0x[cC]3/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and any of ($bound_*)
}

/* -----------------------------------------------------------------------------
   AMSI_HIGH_AmsiContext_AmsiSession_Reflection
   AMSI context/session reflection hijack: GetField('amsiContext'|'amsiSession')
   bound to SetValue(IntPtr::Zero) or WriteIntPtr modification.
   ----------------------------------------------------------------------------- */
rule AMSI_HIGH_AmsiContext_AmsiSession_Reflection
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "amsi_bypass"
        severity = "high"
        description = "AMSI context/session reflection hijack: GetField('amsiContext'|'amsiSession') bound to IntPtr::Zero / WriteIntPtr"
        mitre = "T1562.001"

    strings:
        // AmsiUtils + GetField('amsiContext'|'amsiSession') + SetValue($null,[IntPtr]::Zero) bound
        $bound_setnull = /System\.Management\.Automation\.AmsiUtils[^\r\n]{0,200}GetField\s*\(\s*['"](amsiContext|amsiSession)['"][^\r\n]{0,200}\.SetValue\s*\(\s*\$?null\s*,\s*\[IntPtr\]::Zero\s*\)/is ascii wide
        // AmsiUtils + GetField('amsiContext'|'amsiSession') + Marshal::WriteIntPtr bound
        $bound_write   = /System\.Management\.Automation\.AmsiUtils[^\r\n]{0,200}GetField\s*\(\s*['"](amsiContext|amsiSession)['"][^\r\n]{0,200}\[(System\.)?Runtime\.InteropServices\.Marshal\]::WriteIntPtr\b/is ascii wide
        // AmsiUtils + GetField('amsiContext'|'amsiSession') + SetValue($null,0) integer-zero variant
        $bound_zero    = /System\.Management\.Automation\.AmsiUtils[^\r\n]{0,200}GetField\s*\(\s*['"](amsiContext|amsiSession)['"][^\r\n]{0,200}\.SetValue\s*\(\s*\$?null\s*,\s*0\s*\)/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and any of ($bound_*)
}

/* -----------------------------------------------------------------------------
   AMSI_HIGH_HWBP_Or_DllNotification_Bypass
   Hardware-breakpoint or LdrDllNotification AMSI bypass. May target compiled
   tools (binary patterns), so PE/ELF skip is intentionally OMITTED here.
   Requires the AMSI target symbol bound to the HWBP/notification primitive.
   ----------------------------------------------------------------------------- */
rule AMSI_HIGH_HWBP_Or_DllNotification_Bypass
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "amsi_bypass"
        severity = "high"
        description = "AMSI HWBP (Get/SetThreadContext + Dr0-3) or LdrDllNotification bound to AmsiScanBuffer target"
        mitre = "T1562.001"
        reference = "CCob / RastaMouse 2023 stealth AMSI bypass"

    strings:
        // HWBP path: AmsiScanBuffer target bound to SetThreadContext + Dr0-3 within proximity
        $bound_hwbp = /AmsiScanBuffer[^\r\n]{0,600}SetThreadContext[^\r\n]{0,400}(Dr[0-3]\b|ContextFlags\s*=\s*0x10010)/is ascii wide
        // HWBP reverse: SetThreadContext + Dr0-3 then AmsiScanBuffer
        $bound_hwbp_rev = /SetThreadContext[^\r\n]{0,400}(Dr[0-3]\b|ContextFlags\s*=\s*0x10010)[^\r\n]{0,600}AmsiScanBuffer/is ascii wide

        // LdrDllNotification path: register callback bound to AMSI/amsi.dll target
        $bound_ldr_amsi = /Ldr(Register)?DllNotification[^\r\n]{0,400}(AmsiScanBuffer|amsi\.dll)/is ascii wide
        $bound_ldr_amsi_rev = /(AmsiScanBuffer|amsi\.dll)[^\r\n]{0,400}Ldr(Register)?DllNotification/is ascii wide

    condition:
        filesize < 20MB
        and any of ($bound_*)
}

/* -----------------------------------------------------------------------------
   AMSI_HIGH_COR_PROFILER_Hijack
   COR_PROFILER env-var hijack: requires the env-var set + a CLSID + a
   user-writable DLL path, all in proximity. Drops standalone env-name match.
   ----------------------------------------------------------------------------- */
rule AMSI_HIGH_COR_PROFILER_Hijack
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "amsi_bypass,persistence"
        severity = "high"
        description = "COR_PROFILER hijack: env-var set + CLSID + user-writable DLL path bound"
        mitre = "T1574.012,T1562.001"
        reference = "https://attack.mitre.org/techniques/T1574/012/"

    strings:
        // SetEnvironmentVariable('COR_PROFILER',...) + CLSID + user-writable DLL within proximity
        $bound_ps = /\[(System\.)?Environment\]::SetEnvironmentVariable\s*\(\s*['"]COR_PROFILER['"][^\r\n]{0,400}\{[0-9A-Fa-f-]{36}\}[^\r\n]{0,400}[A-Za-z]:\\\\?(Users\\\\?[^\\\r\n]{1,80}\\\\?(AppData|Downloads|Desktop|Documents|Public)|ProgramData|Temp|Windows\\\\?Temp|Users\\\\?Public)\\\\?[^"'\r\n]{0,200}\.dll/is ascii wide

        // reg add HKCU\Environment /v COR_PROFILER + CLSID + user-writable DLL
        $bound_reg = /reg(\.exe)?\s+add\s+["']?HK(CU|LM)\\?Environment["']?\s+\/v\s+COR_PROFILER[^\r\n]{0,400}\{[0-9A-Fa-f-]{36}\}[^\r\n]{0,400}[A-Za-z]:\\\\?(Users|ProgramData|Temp|Windows\\\\?Temp|Public)[^"'\r\n]{0,200}\.dll/is ascii wide

        // .NET subkey COR_PROFILER_PATH pointing to user-writable DLL bound to COR_ENABLE_PROFILING=1
        $bound_pair = /COR_ENABLE_PROFILING\s*=\s*1[^\r\n]{0,400}COR_PROFILER_PATH(_32|_64)?\s*=\s*["']?[A-Za-z]:\\\\?(Users|ProgramData|Temp|Windows\\\\?Temp|Public)[^"'\r\n]{0,200}\.dll/is ascii wide
        $bound_pair_rev = /COR_PROFILER_PATH(_32|_64)?\s*=\s*["']?[A-Za-z]:\\\\?(Users|ProgramData|Temp|Windows\\\\?Temp|Public)[^"'\r\n]{0,200}\.dll[^\r\n]{0,400}COR_ENABLE_PROFILING\s*=\s*1/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and any of ($bound_*)
}

/* -----------------------------------------------------------------------------
   ETW_HIGH_EtwEventWrite_Patch
   ETW patching: requires EtwEventWrite/NtTraceEvent target AND VirtualProtect
   verb AND the patch byte (0xC3 ret or 0xC2 14 00 00 ret-imm) all bound.
   ----------------------------------------------------------------------------- */
rule ETW_HIGH_EtwEventWrite_Patch
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "etw_bypass"
        severity = "high"
        description = "ETW patch: EtwEventWrite/NtTraceEvent + VirtualProtect/Marshal.Copy + 0xC3/0xC2 ret byte bound"
        mitre = "T1562.006"
        reference = "Modexp ETW bypass; CyberArk; public PoCs"

    strings:
        // EtwEventWrite/NtTraceEvent target + VirtualProtect + ret byte (0xC3) within proximity
        $bound_ret = /(EtwEventWrite(Full)?|NtTraceEvent|EtwNotificationRegister)[^\r\n]{0,400}(VirtualProtect|Marshal\]::Copy|WriteProcessMemory)[^\r\n]{0,400}(0x[cC]3\b|\\x[cC]3|\bRET\b)/is ascii wide
        // Reverse: patch verb + ret byte then ETW target
        $bound_ret_rev = /(VirtualProtect|Marshal\]::Copy|WriteProcessMemory)[^\r\n]{0,400}(0x[cC]3\b|\\x[cC]3)[^\r\n]{0,400}(EtwEventWrite(Full)?|NtTraceEvent|EtwNotificationRegister)/is ascii wide

        // ETW target + VirtualProtect + ret-imm stub (0xC2 0x14 0x00 0x00)
        $bound_retimm = /(EtwEventWrite(Full)?|NtTraceEvent)[^\r\n]{0,400}(VirtualProtect|Marshal\]::Copy|WriteProcessMemory)[^\r\n]{0,400}0x[cC]2\s*,\s*0x14\s*,\s*0x00\s*,\s*0x00/is ascii wide

        // GetProcAddress("EtwEventWrite") + VirtualProtect bound (covers two-step patch)
        $bound_gpa = /GetProcAddress[^\r\n]{0,200}["'](EtwEventWrite(Full)?|NtTraceEvent)["'][^\r\n]{0,400}VirtualProtect[^\r\n]{0,400}0x[cC]3/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and any of ($bound_*)
}

/* -----------------------------------------------------------------------------
   LOG_HIGH_PS_ScriptBlock_Module_Logging_Disable
   ScriptBlock/Module logging disable: registry path + value=0 verb bound, or
   PSEtwLogProvider reflection chain with m_enabled flip bound.
   ----------------------------------------------------------------------------- */
rule LOG_HIGH_PS_ScriptBlock_Module_Logging_Disable
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "defense_evasion"
        severity = "high"
        description = "PS ScriptBlock/Module logging disable: registry value=0 bound, or PSEtwLogProvider m_enabled reflection bound"
        mitre = "T1562.002,T1562.001"

    strings:
        // Reg verb + ScriptBlock/Module logging path + Enable... value set to 0 in proximity
        $bound_reg_set = /(reg(\.exe)?\s+add|Set-ItemProperty|New-ItemProperty)\b[^\r\n]{0,200}(SOFTWARE\\\\?(Policies\\\\?)?Microsoft\\\\?Windows\\\\?PowerShell\\\\?(ScriptBlock|Module)Logging)[^\r\n]{0,200}Enable(ScriptBlock|Module|ScriptBlockInvocation)Logging[^\r\n]{0,80}(\/d\s+0\b|-Value\s+0\b|\s+0\s+\/f)/is ascii wide

        // Remove-ItemProperty of the Enable...Logging value (effective disable)
        $bound_reg_remove = /Remove-ItemProperty\b[^\r\n]{0,200}(SOFTWARE\\\\?(Policies\\\\?)?Microsoft\\\\?Windows\\\\?PowerShell\\\\?(ScriptBlock|Module)Logging)[^\r\n]{0,200}Enable(ScriptBlock|Module|ScriptBlockInvocation)Logging/is ascii wide

        // PSEtwLogProvider reflection: GetType('...PSEtwLogProvider') + GetField('m_enabled') + SetValue
        $bound_etwprov = /GetType\s*\(\s*['"]System\.Management\.Automation\.Tracing\.PSEtwLogProvider['"][^\r\n]{0,400}GetField\s*\(\s*['"](etwProvider|m_enabled)['"][^\r\n]{0,400}\.SetValue\s*\(/is ascii wide

        // cachedGroupPolicySettings tamper: Utils class + cachedGroupPolicySettings + EnableScriptBlockLogging bound
        $bound_cachedgp = /GetType\s*\(\s*['"]System\.Management\.Automation\.Utils['"][^\r\n]{0,400}cachedGroupPolicySettings[^\r\n]{0,400}EnableScriptBlock(Invocation)?Logging/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and any of ($bound_*)
}

/* -----------------------------------------------------------------------------
   DEF_HIGH_Defender_RealTime_Disable
   Set-MpPreference -Disable... $true bound, or registry equivalent under
   Windows Defender key bound to value=1 (disable semantics).
   ----------------------------------------------------------------------------- */
rule DEF_HIGH_Defender_RealTime_Disable
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "defender_tampering"
        severity = "high"
        description = "Defender disable: Set-MpPreference -Disable* $true bound, or Windows Defender reg key + value=1 bound"
        mitre = "T1562.001"

    strings:
        // Set-MpPreference + -Disable<area> + $true / 1 / Disabled / Never bound
        $bound_cmdlet = /\bSet-MpPreference\b[^\r\n]{0,120}-(DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableScriptScanning|DisableArchiveScanning|DisableIntrusionPreventionSystem|DisableEmailScanning|DisableBlockAtFirstSeen|DisableRemovableDriveScanning)\s+\$?(true|1)\b/i ascii wide

        // MAPSReporting 0 / SubmitSamplesConsent 2 telemetry-kill bound to Set-MpPreference
        $bound_telemetry = /\bSet-MpPreference\b[^\r\n]{0,120}-(MAPSReporting\s+0|SubmitSamplesConsent\s+2|PUAProtection\s+0)\b/i ascii wide

        // Registry verb + Windows Defender path + Disable... value name + value=1 bound
        $bound_reg = /(reg(\.exe)?\s+add|Set-ItemProperty|New-ItemProperty)\b[^\r\n]{0,200}SOFTWARE\\\\?(Policies\\\\?)?Microsoft\\\\?Windows\s*Defender(\\\\?(Real-Time\s*Protection|Features|Spynet))?\b[^\r\n]{0,200}(DisableAntiSpyware|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableScriptScanning)[^\r\n]{0,80}(\/d\s+1\b|-Value\s+1\b|\s+1\s+\/f)/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and any of ($bound_*)
}

/* -----------------------------------------------------------------------------
   DEF_HIGH_Defender_Exclusion_UserWritable
   Add-MpPreference -Exclusion<X> bound to a user-writable path/process.
   No standalone Add-MpPreference; the exclusion target must be present.
   ----------------------------------------------------------------------------- */
rule DEF_HIGH_Defender_Exclusion_UserWritable
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "defender_tampering"
        severity = "high"
        description = "Add-MpPreference -Exclusion* bound to user-writable path (Users/ProgramData/Temp/Public) or LOLBin process"
        mitre = "T1562.001"

    strings:
        // Add-MpPreference -ExclusionPath/Extension/IpAddress bound to user-writable dir
        $bound_path = /\bAdd-MpPreference\b[^\r\n]{0,120}-Exclusion(Path|Extension|IpAddress)\s+["']?(\$env:(TEMP|APPDATA|LOCALAPPDATA|PUBLIC|ProgramData)|%TEMP%|%APPDATA%|%LOCALAPPDATA%|%PUBLIC%|[A-Za-z]:\\\\?(Users\\\\?[^\\\r\n"']{1,80}\\\\?(AppData|Downloads|Desktop|Documents)|ProgramData|Temp|Windows\\\\?Temp|Users\\\\?Public))[^"'\r\n]{0,200}/i ascii wide

        // Set-MpPreference -ExclusionPath (bulk-set variant) bound to user-writable dir
        $bound_set_path = /\bSet-MpPreference\b[^\r\n]{0,120}-Exclusion(Path|Extension)\s+["']?(\$env:(TEMP|APPDATA|LOCALAPPDATA|PUBLIC|ProgramData)|%TEMP%|%APPDATA%|%LOCALAPPDATA%|%PUBLIC%|[A-Za-z]:\\\\?(Users\\\\?[^\\\r\n"']{1,80}|ProgramData|Temp|Windows\\\\?Temp|Users\\\\?Public))[^"'\r\n]{0,200}/i ascii wide

        // Add-MpPreference -ExclusionProcess bound to LOLBin process name
        $bound_proc = /\bAdd-MpPreference\b[^\r\n]{0,120}-ExclusionProcess\s+["']?(\*\.exe|powershell\.exe|pwsh\.exe|cmd\.exe|rundll32\.exe|regsvr32\.exe|mshta\.exe|wscript\.exe|cscript\.exe|certutil\.exe|bitsadmin\.exe|msbuild\.exe|installutil\.exe)["']?/i ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and any of ($bound_*)
}

/* -----------------------------------------------------------------------------
   DEF_HIGH_Defender_Process_Service_Kill
   Kill/stop/delete verb bound to a Defender service or process binary.
   ----------------------------------------------------------------------------- */
rule DEF_HIGH_Defender_Process_Service_Kill
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "defender_tampering"
        severity = "high"
        description = "Kill/stop/delete verb bound to Defender service or binary (WinDefend, MsMpEng, Sense, MDCoreSvc)"
        mitre = "T1562.001,T1489"

    strings:
        // taskkill /IM <Defender binary>
        $bound_taskkill = /\btaskkill(\.exe)?\b[^\r\n]{0,80}\/IM\s+(MsMpEng\.exe|SecHealthService\.exe|MpDefenderCoreService\.exe|MsSense\.exe|SenseIR\.exe|SenseNdr\.exe|SenseCM\.exe|NisSrv\.exe)/i ascii wide

        // Stop-Process -Name <Defender binary>
        $bound_stopproc = /\bStop-Process\b[^\r\n]{0,120}-Name\s+["']?(MsMpEng|SecHealthService|MpDefenderCoreService|MsSense|SenseIR|SenseNdr|SenseCM|NisSrv)["']?/i ascii wide

        // sc stop/delete <Defender service>
        $bound_sc = /\bsc(\.exe)?\b\s+(stop|delete|config)\s+["']?(WinDefend|WdNisSvc|WdFilter|WdBoot|Sense|MDCoreSvc|WdNisDrv|SecurityHealthService)["']?/i ascii wide

        // Stop-Service -Name <Defender service>
        $bound_stopsvc = /\bStop-Service\b[^\r\n]{0,120}["']?(WinDefend|WdNisSvc|WdFilter|WdBoot|Sense|MDCoreSvc|WdNisDrv|SecurityHealthService)["']?/i ascii wide

        // Set-Service ... -StartupType Disabled on Defender service
        $bound_setsvc = /\bSet-Service\b[^\r\n }]{0,200}["']?(WinDefend|WdNisSvc|Sense|MDCoreSvc)["']?[^\r\n]{0,80}-StartupType\s+Disabled\b/i ascii wide

        // Capability/feature removal bound to Defender
        $bound_dism = /\b(Remove-WindowsCapability|Disable-WindowsOptionalFeature|Uninstall-WindowsFeature)\b[^\r\n]{0,200}(Defender|Windows-Defender|Sense)/i ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and any of ($bound_*)
}

/* -----------------------------------------------------------------------------
   DEF_HIGH_Sysmon_Driver_Unload
   Sysmon-specific stop/unload verb bound to Sysmon service/binary name.
   ----------------------------------------------------------------------------- */
rule DEF_HIGH_Sysmon_Driver_Unload
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "defender_tampering"
        severity = "high"
        description = "Sysmon unload: sysmon -u force, fltmc unload SysmonDrv, sc stop/delete Sysmon bound"
        mitre = "T1562.001"

    strings:
        // sysmon.exe -u force (native uninstall)
        $bound_unload = /\bsysmon(64)?(\.exe)?\b\s+-u(\s+force)?\b/i ascii wide
        // fltmc unload SysmonDrv (minifilter unload)
        $bound_fltmc  = /\bfltmc(\.exe)?\b\s+(unload|detach)\s+["']?Sysmon(Drv)?["']?/i ascii wide
        // sc stop/delete Sysmon/SysmonDrv
        $bound_sc     = /\bsc(\.exe)?\b\s+(stop|delete|config)\s+["']?(Sysmon(64)?|SysmonDrv)["']?/i ascii wide
        // Stop-Service Sysmon
        $bound_stopsvc= /\bStop-Service\b[^\r\n]{0,120}["']?(Sysmon(64)?|SysmonDrv)["']?/i ascii wide
        // taskkill /IM Sysmon*.exe
        $bound_taskkill = /\btaskkill(\.exe)?\b[^\r\n]{0,80}\/IM\s+Sysmon(64)?\.exe/i ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and any of ($bound_*)
}

/* -----------------------------------------------------------------------------
   AMSI_HIGH_LanguageMode_FullEscape
   Constrained Language Mode escape: requires assignment to 'FullLanguage'
   from inside a constrained-language context indicator (SessionState +
   LanguageMode + reflection on private _languageMode field).
   ----------------------------------------------------------------------------- */
rule AMSI_HIGH_LanguageMode_FullEscape
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "defense_evasion"
        severity = "high"
        description = "Constrained Language Mode escape: SessionState/LanguageMode reflection bound to FullLanguage assignment"
        mitre = "T1059.001"

    strings:
        // ExecutionContext.SessionState...LanguageMode = 'FullLanguage' direct assignment bound
        $bound_assign = /\$ExecutionContext[^\r\n]{0,200}SessionState[^\r\n]{0,200}LanguageMode\s*=\s*['"]?FullLanguage['"]?/is ascii wide

        // Reflection: GetField('_languageMode' | '_LanguageMode') + SetValue(...,'FullLanguage' | 0) bound
        $bound_reflect = /GetField\s*\(\s*['"]_+[Ll]anguage(Mode)?['"][^\r\n]{0,400}\.SetValue\s*\([^\r\n]{0,200}(FullLanguage|\b0\b)/is ascii wide

        // SessionStateInternal reflection chain bound to FullLanguage
        $bound_internal = /SessionStateInternal[^\r\n]{0,400}LanguageMode[^\r\n]{0,200}FullLanguage/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and any of ($bound_*)
}

/* -----------------------------------------------------------------------------
   DEF_HIGH_TamperProtection_Bypass
   Direct registry write to disable Tamper Protection or set WinDefend Start=4
   (disabled) — registry path bound to value-modification verb + disable value.
   ----------------------------------------------------------------------------- */
rule DEF_HIGH_TamperProtection_Bypass
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "defender_tampering"
        severity = "high"
        description = "Tamper Protection / WinDefend Start / SmartScreen registry write bound to disable value"
        mitre = "T1562.001"

    strings:
        // Registry verb + Defender Features path + TamperProtection value name + 0/disable bound
        $bound_tp = /(reg(\.exe)?\s+add|Set-ItemProperty|New-ItemProperty)\b[^\r\n]{0,200}SOFTWARE\\\\?Microsoft\\\\?Windows\s*Defender\\\\?Features\b[^\r\n]{0,200}TamperProtection\b[^\r\n]{0,80}(\/d\s+0\b|-Value\s+0\b|\s+0\s+\/f)/is ascii wide

        // Registry verb + Services\WinDefend|Sense path + Start value + 4 (disabled) bound
        $bound_svc_disable = /(reg(\.exe)?\s+add|Set-ItemProperty|New-ItemProperty)\b[^\r\n]{0,200}SYSTEM\\\\?CurrentControlSet\\\\?Services\\\\?(WinDefend|Sense|WdNisSvc|WdFilter|MDCoreSvc)\b[^\r\n]{0,200}\bStart\b[^\r\n]{0,80}(\/d\s+4\b|-Value\s+4\b|\s+4\s+\/f)/is ascii wide

        // SmartScreen disable via registry bound
        $bound_smartscreen = /(reg(\.exe)?\s+add|Set-ItemProperty|New-ItemProperty)\b[^\r\n]{0,200}SmartScreenEnabled\b[^\r\n]{0,80}(["']?Off["']?|["']?Disabled["']?|\/d\s+Off\b|-Value\s+Off\b)/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and any of ($bound_*)
}
