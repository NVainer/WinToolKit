/* =============================================================================
   02_powershell_and_lolbas.yar
   -----------------------------------------------------------------------------
   Author : Nati
   Date   : 2026-10-14 (v3)
   Scope  : Attacker command lines and scripts as they sit on disk: in .ps1/.bat/
            .vbs/.js files, LNK arguments, scheduled-task XML, PowerShell
            history (ConsoleHost_history.txt), cached HTML/JS, IME logs.

   Every rule is text-only (PE/ELF skipped) and bound: verb + payload shape in
   one proximity window. Encoded commands are matched through YARA's
   `wide base64` modifier, which encodes the UTF-16LE form exactly the way
   powershell -EncodedCommand does, so no decoding step is needed.
   ============================================================================= */

/* -----------------------------------------------------------------------------
   PS_HIGH_Download_Cradle_IEX
   Fetch a remote payload and execute it in memory. The most common first
   command after a ClickFix paste or a dropper stage-1.
   ----------------------------------------------------------------------------- */
rule PS_HIGH_Download_Cradle_IEX
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "execution,c2_stager"
        severity    = "high"
        description = "PowerShell download cradle: WebClient.DownloadString/DownloadData, Invoke-WebRequest/irm/iwr/curl piped or wrapped into IEX, DownloadFile followed by execution, or any cradle verb pointed at a known payload-hosting domain"
        mitre       = "T1059.001,T1105,T1102"
        fp_notes    = "Known benign one-liners: Chocolatey install, Scoop install, 'irm https://aka.ms/install-powershell.ps1 | iex'. Those are developer/admin actions and should not appear on a regular user's disk."

    strings:
        $c_webclient_iex = /(\biex\b|Invoke-Expression)\s*\(?\s*\(?\s*(New-Object\s+(System\.)?Net\.WebClient|\[(System\.)?Net\.WebClient\]::new\s*\(\s*\))[^;\r\n]{0,60}\.Download(String|Data)\s*\(\s*['"]?https?:\/\//i ascii wide
        $c_piped_iex     = /\.Download(String|Data)\s*\(\s*['"]?https?:\/\/[^'"\)\r\n]{4,300}['"]?\s*\)\s*\)?\s*\|\s*(\biex\b|Invoke-Expression|&\s*\(\s*\$|\.\s*Invoke\s*\()/i ascii wide
        $c_iwr_iex       = /(\biex\b|Invoke-Expression)\s*\(?\s*\(?\s*(Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b|\bcurl\b|\bwget\b)\s+[^;\r\n]{0,80}https?:\/\//i ascii wide
        $c_iwr_piped     = /(Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b|\bcurl\b|\bwget\b)\s+[^;\r\n|]{0,200}https?:\/\/[^\s'"|]{4,300}[^;\r\n|]{0,100}\|\s*(\biex\b|Invoke-Expression|\.\s*Invoke\s*\(|&\s*\(\s*\$)/i ascii wide
        $c_content_iex   = /\.Content\s*\|\s*(\biex\b|Invoke-Expression)/i ascii wide
        $c_dlfile_exec   = /\.DownloadFile\s*\(\s*['"]https?:\/\/[^'"\r\n]{4,300}['"]\s*,\s*['"][^'"\r\n]{1,300}['"]\s*\)[^\r\n]{0,200}(Start-Process|\bsaps\b|Invoke-Item|&\s*['"$]|\.\s*Invoke\s*\(\s*\)|rundll32|regsvr32|cmd(\.exe)?\s*\/c|msiexec)/i ascii wide
        $c_abused_host   = /(\biex\b|Invoke-Expression|DownloadString|-urlcache|Start-BitsTransfer)[^\r\n]{0,200}https?:\/\/[^\s"'\r\n]{0,120}(raw\.githubusercontent\.com|gist\.githubusercontent\.com|cdn\.discordapp\.com\/attachments|media\.discordapp\.net|pastebin\.com\/raw|paste\.ee|transfer\.sh|0x0\.st|ngrok-free\.app|ngrok\.io|ngrok\.app|trycloudflare\.com|telegra\.ph|api\.telegram\.org|t\.me\/|tinyurl\.com|bit\.ly\/|is\.gd\/|rentry\.co|hastebin|filebin|anonfiles|gofile\.io|mega\.nz|r2\.dev|workers\.dev)/i ascii wide

        // Well-known developer-tool installers that use the same "irm | iex" shape.
        // Exact script URLs on vendor-controlled hosts only; nothing wildcarded.
        $known_installer = /(irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\s+(-useb\s+|-UseBasicParsing\s+|-Uri\s+)?["']?https:\/\/(claude\.ai\/install\.ps1|community\.chocolatey\.org\/install\.ps1|get\.scoop\.sh|aka\.ms\/install-powershell\.ps1|astral\.sh\/uv\/install\.ps1|bun\.sh\/install\.ps1|get\.pnpm\.io\/install\.ps1|raw\.githubusercontent\.com\/nvm-sh|rustup\.rs|install\.python-poetry\.org|public-cdn\.cloud\.unity3d\.com\/hub\/prod\/cli\/install\.ps1)/i ascii wide

    condition:
        filesize < 10MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and 1 of ($c_*)
        and not (
            // every "irm ... | iex" in the file is one of the allow-listed vendor installers, and nothing else matched
            for all i in (1..#c_iwr_piped) : ( $known_installer at @c_iwr_piped[i] )
            and not ( $c_webclient_iex or $c_piped_iex or $c_iwr_iex or $c_content_iex or $c_dlfile_exec or $c_abused_host )
        )
}

/* -----------------------------------------------------------------------------
   PS_HIGH_EncodedCommand_Malicious_Payload
   powershell -enc <base64> where the decoded UTF-16 script contains an
   execution/download/evasion marker. `wide base64` makes YARA search for the
   marker as it appears inside the blob; `base64wide` adds the case where the
   blob itself is stored as UTF-16 (task XML, LNK arguments).
   ----------------------------------------------------------------------------- */
rule PS_HIGH_EncodedCommand_Malicious_Payload
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "execution,obfuscation"
        severity    = "high"
        description = "-EncodedCommand blob (any prefix form -e/-ec/-enc) containing IEX/Invoke-Expression, DownloadString/File, WebClient, FromBase64String, TCPClient, AMSI, MpPreference, Reflection.Assembly, VirtualAlloc, -bxor or a nested hidden launcher; TCPClient/AMSI/Invoke-Mimikatz blobs fire even without the flag"
        mitre       = "T1059.001,T1027.010"
        fp_notes    = "Legit -enc usage by management agents carries plain cmdlets, not the markers above. Check the launching file (task XML, LNK, batch) before escalating."

    strings:
        $enc_flag = /\s-e(c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm|ncodedcomma|ncodedcomman|ncodedcommand)?\s+["']?[A-Za-z0-9+\/]{40,}={0,2}/i ascii wide

        $b_iex1   = "Invoke-Expression" wide base64 base64wide
        $b_iex2   = "invoke-expression" wide base64 base64wide
        $b_iex3   = "IEX"               wide base64 base64wide
        $b_iex4   = "iex"               wide base64 base64wide
        $b_iex5   = "Iex"               wide base64 base64wide
        $b_dls    = "DownloadString"    wide base64 base64wide
        $b_dlf    = "DownloadFile"      wide base64 base64wide
        $b_wc     = "Net.WebClient"     wide base64 base64wide
        $b_b64    = "FromBase64String"  wide base64 base64wide
        $b_mp1    = "Set-MpPreference"  wide base64 base64wide
        $b_mp2    = "Add-MpPreference"  wide base64 base64wide
        $b_refl   = "Reflection.Assembly" wide base64 base64wide
        $b_valloc = "VirtualAlloc"      wide base64 base64wide
        $b_bxor   = "-bxor"             wide base64 base64wide
        $b_hid1   = "-WindowStyle Hidden" wide base64 base64wide
        $b_hid2   = "-w hidden"         wide base64 base64wide

        $hard_tcp1  = "Net.Sockets.TCPClient" wide base64 base64wide
        $hard_tcp2  = "Net.Sockets.TcpClient" wide base64 base64wide
        $hard_amsi1 = "AmsiUtils"            wide base64 base64wide
        $hard_amsi2 = "amsiInitFailed"       wide base64 base64wide
        $hard_amsi3 = "AmsiScanBuffer"       wide base64 base64wide
        $hard_mimi  = "Invoke-Mimikatz"      wide base64 base64wide

    condition:
        filesize < 20MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and (
            ( $enc_flag and 1 of ($b_*) )
            or 1 of ($hard_*)
        )
}

/* -----------------------------------------------------------------------------
   RS_HIGH_PS_TCPClient_Stream_IEX_Loop   (name kept - referenced by KQL)
   PowerShell reverse shell: TCPClient(host,port) + stream + exec/IO loop,
   plus PowerCat and Nishang entry points.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_PS_TCPClient_Stream_IEX_Loop
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "reverse_shell"
        severity    = "high"
        description = "PS reverse shell: Net.Sockets.TCPClient(host,port) + GetStream + IEX/Process exec or Read/Write loop; PowerCat -c/-l -p; Nishang Invoke-PowerShellTcp/Udp/Icmp, Invoke-ConPtyShell"
        mitre       = "T1059.001,T1071.001"
        fp_notes    = "Admin port-scanner scripts that open TcpClient + GetStream + Read can match; not expected on regular-user devices."

    strings:
        $tcp      = /Net\.Sockets\.TcpClient\s*\(\s*['"]?[A-Za-z0-9\.\-]{3,120}['"]?\s*,\s*\$?\d{1,5}\s*\)/i ascii wide
        $tcp_new  = /\[(System\.)?Net\.Sockets\.TcpClient\]::new\s*\(\s*['"]?[A-Za-z0-9\.\-]{3,120}['"]?\s*,\s*\$?\d{1,5}/i ascii wide
        $stream   = /\.GetStream\s*\(\s*\)/i ascii wide
        $exec     = /(\biex\b|Invoke-Expression|\.\s*Invoke\s*\(|ProcessStartInfo|Start-Process\s+[^\r\n]{0,40}(cmd|powershell)|cmd(\.exe)?\s+\/[ck]|\[Diagnostics\.Process\]::Start)/i ascii wide
        $io       = /\.(Read|Write)\s*\(\s*\$\w+\s*,\s*0\s*,\s*\$?\w+(\.Length)?\s*\)/i ascii wide
        $powercat = /\bpowercat\b[^\r\n]{0,120}\s-(c|l)\b[^\r\n]{0,120}\s-p\s+\d{1,5}/i ascii wide
        $nishang  = /(Invoke-PowerShellTcp(OneLine)?|Invoke-PowerShellUdp|Invoke-PowerShellIcmp|Invoke-ConPtyShell)\b/i ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and (
            ( ( $tcp or $tcp_new ) and $stream and ( $exec or $io ) )
            or $powercat
            or $nishang
        )
}

/* -----------------------------------------------------------------------------
   PS_HIGH_AMSI_Bypass
   All common in-script AMSI defeats: amsiInitFailed reflection, AmsiScanBuffer
   / AmsiOpenSession patching, context nulling, hardware breakpoints,
   char-by-char token reassembly.
   ----------------------------------------------------------------------------- */
rule PS_HIGH_AMSI_Bypass
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "defense_evasion"
        severity    = "high"
        description = "AMSI bypass in script text: AmsiUtils+amsiInitFailed, AmsiScanBuffer/AmsiOpenSession + patch primitive, amsiContext/amsiSession nulling, amsi.dll + GetProcAddress/VirtualProtect + ret bytes, or 'a'+'m'+'s'+'i' reassembly next to reflection"
        mitre       = "T1562.001"

    strings:
        $utils_init    = /(AmsiUtils[\s\S]{0,600}amsiInitFailed|amsiInitFailed[\s\S]{0,600}AmsiUtils)/i ascii wide
        $scanbuf_patch = /(AmsiScanBuffer[\s\S]{0,800}(VirtualProtect|Marshal\]::Copy|WriteProcessMemory|SetThreadContext|LdrRegisterDllNotification|\bDr[0-3]\b)|(VirtualProtect|Marshal\]::Copy|WriteProcessMemory|SetThreadContext)[\s\S]{0,800}AmsiScanBuffer)/i ascii wide
        $open_session  = /AmsiOpenSession[\s\S]{0,600}(VirtualProtect|Marshal\]::Copy|WriteProcessMemory|0x[cC]3|0x74|0x75)/i ascii wide
        $context_null  = /AmsiUtils[\s\S]{0,600}(amsiContext|amsiSession)[\s\S]{0,300}(IntPtr\]::Zero|SetValue\s*\(\s*\$?null\s*,\s*0|WriteInt(Ptr|32))/i ascii wide
        $dll_patch     = /amsi\.dll[\s\S]{0,600}(GetProcAddress|VirtualProtect)[\s\S]{0,600}(0x[cC]3|0x80070057|0xB8|\\x[cC]3)/i ascii wide
        $char_reasm    = /(\[char\]\s*(65|0x41)\s*[\+,]\s*\[char\]\s*(109|0x6[Dd])\s*[\+,]\s*\[char\]\s*(115|0x73)\s*[\+,]\s*\[char\]\s*(105|0x69)|['"][Aa]['"]\s*\+\s*['"][Mm]['"]\s*\+\s*['"][Ss]['"]\s*\+\s*['"][Ii]['"]|['"]Amsi['"]\s*\+\s*['"]Utils['"]|['"]amsi['"]\s*\+\s*['"]Init['"]\s*\+\s*['"]Failed['"]|['"]Amsi['"]\s*\+\s*['"]Scan['"]\s*\+\s*['"]Buffer['"])/i ascii wide
        $reflect_ctx   = /(GetField|SetValue|NonPublic|BindingFlags|GetProcAddress|VirtualProtect)/i ascii wide

    condition:
        filesize < 10MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and ( $utils_init or $scanbuf_patch or $open_session or $context_null or $dll_patch or ( $char_reasm and $reflect_ctx ) )
}

/* -----------------------------------------------------------------------------
   PS_HIGH_Defender_Tamper
   Turning Defender off, excluding attacker folders, killing its services,
   wiping definitions, disabling SmartScreen / Tamper Protection via registry.
   ----------------------------------------------------------------------------- */
rule PS_HIGH_Defender_Tamper
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "defense_evasion"
        severity    = "high"
        description = "Set-MpPreference -Disable* $true / MAPS off / threat action allow, Add-MpPreference exclusions on user-writable paths, wildcard or LOLBin processes, registry DisableAntiSpyware/TamperProtection/service Start=4, Defender service stop/delete/kill, MpCmdRun -RemoveDefinitions, SmartScreen off, feature removal"
        mitre       = "T1562.001"
        fp_notes    = "Our own install.ps1 adds an exclusion for C:\\Program Files\\YARA\\yara64.exe; that path is not in the user-writable set and does not fire."

    strings:
        $disable     = /Set-MpPreference\b[^\r\n]{0,160}-(DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableScriptScanning|DisableArchiveScanning|DisableIntrusionPreventionSystem|DisableBlockAtFirstSeen|DisableEmailScanning|DisableRemovableDriveScanning|DisableCatchupFullScan|DisableTamperProtection)\s+\$?(true|1)\b/i ascii wide
        $maps        = /Set-MpPreference\b[^\r\n]{0,160}-(MAPSReporting\s+0|SubmitSamplesConsent\s+2|PUAProtection\s+0|EnableControlledFolderAccess\s+Disabled|EnableNetworkProtection\s+Disabled|(High|Severe|Moderate|Low)ThreatDefaultAction\s+(6|Allow)|ThreatIDDefaultAction_Actions\s+6)\b/i ascii wide
        $excl_path   = /(Add|Set)-MpPreference\b[^\r\n]{0,160}-Exclusion(Path|Extension)\s+["']?(\$env:(TEMP|TMP|APPDATA|LOCALAPPDATA|PUBLIC|USERPROFILE|ProgramData)|%(TEMP|TMP|APPDATA|LOCALAPPDATA|PUBLIC|USERPROFILE)%|[A-Za-z]:\\\\?(Users\\\\?[^\\\r\n"']{1,80}\\\\?(AppData|Downloads|Desktop|Documents)|ProgramData|Temp|Windows\\\\?Temp|Users\\\\?Public)|[A-Za-z]:\\\\?["'\s;]|\*|\.(exe|dll|ps1|bat|vbs|js|hta|scr|tmp|zip|dat)\b)/i ascii wide
        $excl_proc   = /(Add|Set)-MpPreference\b[^\r\n]{0,160}-ExclusionProcess\s+["']?[^"'\r\n]{0,120}(\*|powershell|pwsh|cmd\.exe|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|msbuild|installutil|msiexec|explorer\.exe|svchost|\\Users\\|AppData|\\Temp\\|ProgramData)/i ascii wide
        $reg_disable = /(reg(\.exe)?\s+add|Set-ItemProperty|New-ItemProperty|\[Microsoft\.Win32\.Registry\])[^\r\n]{0,200}(Windows\s*Defender|Services\\\\?(WinDefend|Sense|WdNisSvc|WdFilter|MDCoreSvc))[^\r\n]{0,200}(DisableAntiSpyware|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableScriptScanning|DisableAntiVirus|TamperProtection|\bStart\b)[^\r\n]{0,60}(\/d\s+(1|4)\b|-Value\s+(1|4)\b|\s+(1|4)\s+\/f|,\s*(1|4)\s*\))/i ascii wide
        $svc_kill    = /(sc(\.exe)?\s+(stop|delete|config)|Stop-Service|Set-Service|net(\.exe)?\s+stop|taskkill(\.exe)?[^\r\n]{0,60}\/IM|Stop-Process[^\r\n]{0,60}-Name)\s+["']?(WinDefend|WdNisSvc|WdFilter|WdBoot|Sense|MDCoreSvc|SecurityHealthService|MsMpEng(\.exe)?|MsSense(\.exe)?|SenseIR(\.exe)?|NisSrv(\.exe)?|MpDefenderCoreService(\.exe)?)\b/i ascii wide
        $mpcmdrun    = /MpCmdRun(\.exe)?\s+[^\r\n]{0,60}-RemoveDefinitions\s+-All/i ascii wide
        $smartscreen = /(reg(\.exe)?\s+add|Set-ItemProperty|New-ItemProperty)[^\r\n]{0,200}(SmartScreenEnabled|EnableSmartScreen)[^\r\n]{0,80}(["']?Off["']?|\/d\s+0\b|-Value\s+0\b)/i ascii wide
        $uninstall   = /(Uninstall-WindowsFeature|Remove-WindowsFeature|Disable-WindowsOptionalFeature|dism(\.exe)?[^\r\n]{0,80}\/Disable-Feature)[^\r\n]{0,120}Windows-Defender/i ascii wide

    condition:
        filesize < 10MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and any of them
}

/* -----------------------------------------------------------------------------
   PS_MED_Logging_ETW_Tamper
   Blinding PowerShell logging, ETW providers, event logs and the USN journal.
   ----------------------------------------------------------------------------- */
rule PS_MED_Logging_ETW_Tamper
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "defense_evasion"
        severity    = "medium"
        description = "ScriptBlock/Module/Transcription logging set to 0 or removed, PSEtwLogProvider or cachedGroupPolicySettings reflection, EtwEventWrite/NtTraceEvent patch, wevtutil cl / Clear-EventLog on security-relevant logs, auditpol /clear, fsutil usn deletejournal, AMSI/Threat-Intelligence ETW provider disable"
        mitre       = "T1562.002,T1562.006,T1070.001"

    strings:
        $sbl_reg     = /(reg(\.exe)?\s+add|Set-ItemProperty|New-ItemProperty)[^\r\n]{0,200}PowerShell\\\\?(ScriptBlockLogging|ModuleLogging|Transcription)[^\r\n]{0,200}(Enable(ScriptBlock|ScriptBlockInvocation|Module)Logging|EnableTranscripting)[^\r\n]{0,80}(\/d\s+0\b|-Value\s+0\b|\s+0\s+\/f)/i ascii wide
        $sbl_remove  = /Remove-ItemProperty[^\r\n]{0,200}PowerShell\\\\?(ScriptBlockLogging|ModuleLogging|Transcription)/i ascii wide
        $etwprov     = /PSEtwLogProvider[\s\S]{0,600}(etwProvider|m_enabled)[\s\S]{0,300}SetValue/i ascii wide
        $cachedgp    = /cachedGroupPolicySettings[\s\S]{0,600}(EnableScriptBlock(Invocation)?Logging|EnableModuleLogging|EnableTranscripting)/i ascii wide
        $etw_patch   = /(EtwEventWrite(Full)?|NtTraceEvent|EtwNotificationRegister)[\s\S]{0,600}(VirtualProtect|Marshal\]::Copy|WriteProcessMemory)[\s\S]{0,400}(0x[cC]3\b|0x[cC]2\b|\\x[cC]3)/i ascii wide
        $etw_patch_r = /(VirtualProtect|Marshal\]::Copy|WriteProcessMemory)[\s\S]{0,400}(0x[cC]3\b|0x[cC]2\b|\\x[cC]3)[\s\S]{0,600}(EtwEventWrite(Full)?|NtTraceEvent)/i ascii wide
        $wevtutil    = /wevtutil(\.exe)?\s+(cl|clear-log)\s+["']?(Security|System|Application|Microsoft-Windows-PowerShell\/Operational|Windows PowerShell|Microsoft-Windows-Sysmon\/Operational|Microsoft-Windows-TaskScheduler\/Operational|Microsoft-Windows-WMI-Activity\/Operational|Microsoft-Windows-Windows Defender\/Operational)/i ascii wide
        $clear_ps    = /Clear-EventLog\s+[^\r\n]{0,40}["']?(Security|System|Application|Windows PowerShell)/i ascii wide
        $auditpol    = /auditpol(\.exe)?\s+\/clear(\s+\/y)?/i ascii wide
        $usn         = /fsutil(\.exe)?\s+usn\s+deletejournal/i ascii wide
        $etw_prov    = /(Microsoft-Antimalware-Scan-Interface|2A576B87-09A7-520E-C21A-4942F0271D67|Microsoft-Windows-Threat-Intelligence|F4E1897C-BB5D-5668-F1D8-040F4D8DD344|Microsoft-Windows-PowerShell\b|A0C1853B-5C40-4B15-8766-3CF1C58F985A)[\s\S]{0,400}(Set-EtwTraceProvider|Stop-EtwTraceSession|Remove-EtwTraceProvider|logman[^\r\n]{0,40}(stop|delete|update)|wevtutil\s+sl[^\r\n]{0,80}\/e:false|-Enabled\s+\$false)/i ascii wide

    condition:
        filesize < 10MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and any of them
}

/* -----------------------------------------------------------------------------
   PS_MEDHIGH_Reflective_Load_InMemory
   In-memory .NET assembly loading and shellcode injection scaffolds, plus the
   msfvenom stager prologues in binary or text form.
   ----------------------------------------------------------------------------- */
rule PS_MEDHIGH_Reflective_Load_InMemory
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "execution,defense_evasion"
        severity    = "medium-high"
        description = "[Reflection.Assembly]::Load over FromBase64String/Gzip/Deflate/DownloadData/ReadAllBytes with EntryPoint/GetMethod Invoke; Add-Type DllImport kernel32/ntdll + VirtualAlloc + thread/APC primitive; 60+ byte shellcode array with copy+execute; PowerSploit injection cmdlets; msfvenom x86/x64 stager prologue"
        mitre       = "T1620,T1055,T1059.001"

    strings:
        $asm_load_b64   = /\[(System\.)?Reflection\.Assembly\]::\s*Load\s*\(\s*\[(System\.)?Convert\]::\s*FromBase64String/i ascii wide
        $asm_load_var   = /\[(System\.)?Reflection\.Assembly\]::\s*Load\s*\(\s*\$\w+\s*\)[\s\S]{0,400}(\.EntryPoint\s*\.\s*Invoke|\.GetMethod\s*\([^\)]{0,80}\)\s*\.\s*Invoke|\.GetType\s*\([^\)]{0,120}\)[\s\S]{0,200}\.Invoke\s*\()/i ascii wide
        $gzip_load      = /(GzipStream|DeflateStream|FromBase64String|DownloadData|ReadAllBytes)[\s\S]{0,800}\[(System\.)?Reflection\.Assembly\]::\s*Load\s*\(/i ascii wide
        $addtype_inject = /Add-Type\s+-(TypeDefinition|MemberDefinition)[\s\S]{0,2000}DllImport\s*\(\s*["'](kernel32|ntdll)(\.dll)?["'][\s\S]{0,1500}(VirtualAlloc(Ex)?|NtAllocateVirtualMemory|VirtualProtect)[\s\S]{0,1500}(CreateThread|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC|RtlCreateUserThread|SetThreadContext|EnumSystemLocales|CallWindowProc|EnumWindows)/i ascii wide
        $byte_array     = /\[Byte\[\]\]\s*\$\w+\s*=\s*(@\(\s*)?(0x[0-9A-Fa-f]{2}\s*,\s*){60,}/i ascii wide
        $copy_exec      = /(Marshal\]::Copy|RtlMoveMemory|memcpy|WriteProcessMemory)[\s\S]{0,600}(CreateThread|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC|SetThreadContext|\.Invoke\s*\()/i ascii wide
        $refl_cmdlets   = /(Invoke-ReflectivePEInjection|Invoke-Shellcode|Invoke-DllInjection|Invoke-SharpLoader|Invoke-PSInject|Invoke-Assembly\b)/i ascii wide
        $msf_x64_text   = /0x[fF][cC]\s*,\s*0x48\s*,\s*0x83\s*,\s*0x[eE]4\s*,\s*0x[fF]0\s*,\s*0x[eE]8/ ascii wide
        $msf_x86_text   = /0x[fF][cC]\s*,\s*0x[eE]8\s*,\s*0x8[0-9a-fA-F]\s*,\s*0x00\s*,\s*0x00\s*,\s*0x00\s*,\s*0x60/ ascii wide
        $msf_x64        = { FC 48 83 E4 F0 E8 ?? ?? ?? ?? 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 60 }
        $msf_x86        = { FC E8 8? 00 00 00 60 89 E5 31 C0 64 8B 50 30 8B 52 0C 8B 52 14 }

    condition:
        filesize < 10MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and (
            $asm_load_b64 or $asm_load_var or $gzip_load or $addtype_inject
            or ( $byte_array and $copy_exec )
            or $refl_cmdlets
            or $msf_x64_text or $msf_x86_text or $msf_x64 or $msf_x86
        )
}

/* -----------------------------------------------------------------------------
   PS_MED_Obfuscated_PowerShell
   Invoke-Obfuscation style token mangling bound to an execution sink.
   ----------------------------------------------------------------------------- */
rule PS_MED_Obfuscated_PowerShell
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "obfuscation"
        severity    = "medium"
        description = "Format-operator stacks, [char] chains, env-var char indexing, string reversal or -bxor loops bound to IEX/Invoke; backtick-broken keywords; .replace() chains into IEX; inline FromBase64String+GetString into IEX; -split/[char] reconstruction"
        mitre       = "T1027,T1059.001"

    strings:
        $sink          = /(\biex\b|Invoke-Expression|\.\s*Invoke\s*\(|&\s*\(\s*["'$]|\$ExecutionContext\.\s*InvokeCommand|\[ScriptBlock\]::\s*Create)/i ascii wide
        // 6+ placeholders AND at least one out-of-order pair ({k} directly before {0}).
        // Legitimate format strings count up ({0}{1}{2}...); Invoke-Obfuscation shuffles them.
        $fmt_stack     = /["'](\{\d{1,2}\}[^"'\r\n]{0,4}){6,}["']\s*-f\s/i ascii wide
        $fmt_shuffle   = /\{[1-9]\d?\}[^"'\r\n{]{0,4}\{0\}[^"'\r\n]{0,200}["']\s*-f\s/i ascii wide
        $char_chain    = /(\[char\]\s*(0x)?\d{1,3}\s*[\+,]\s*){8,}/i ascii wide
        $backtick      = /(I`+E`*X|I`*E`+X|Inv`+oke|In`+voke-Ex|-Expr`+ession|Down`+load|Web`+Client|Byp`+ass|Base`+64|FromBase`+64)/i ascii wide
        $envidx        = /(\$env:ComSpec|\$ShellId|\$PSHome|\$verbosepreference\.ToString\(\)|\$env:Public)\s*\[\s*\d{1,2}\s*[,\]]/i ascii wide
        $reverse       = /(\.ToCharArray\(\)\s*\[\s*-1\s*\.\.\s*-\d{1,4}\s*\]\s*-join|-join\s*\[char\[\]\]\s*\(\s*\d{2,3}\s*,)/i ascii wide
        $bxor_loop     = /-bxor\s+[^\r\n]{0,80}\}[^\r\n]{0,200}(\biex\b|Invoke-Expression|\[ScriptBlock\]::Create|\.Invoke\s*\()/i ascii wide
        $replace_chain = /(\.replace\s*\(\s*['"][^'"]{1,6}['"]\s*,\s*['"][^'"]{0,6}['"]\s*\)\s*){3,}[^\r\n]{0,120}(\biex\b|Invoke-Expression|\|\s*&)/i ascii wide
        $b64_inline    = /(\biex\b|Invoke-Expression)\s*\(?\s*\[(System\.)?Text\.Encoding\]::\s*(UTF8|ASCII|Unicode|Default)\s*\.\s*GetString\s*\(\s*\[(System\.)?Convert\]::\s*FromBase64String\s*\(\s*['"][A-Za-z0-9+\/=]{100,}/i ascii wide
        $b64_inline_r  = /\[(System\.)?Convert\]::\s*FromBase64String\s*\(\s*['"][A-Za-z0-9+\/=]{200,}['"]\s*\)\s*\)\s*\)?\s*\|\s*(\biex\b|Invoke-Expression)/i ascii wide
        $split_join    = /-split\s*['"][^'"]{1,3}['"]\s*\|\s*(ForEach|%)[^\r\n]{0,80}\[char\]\s*\[(int|byte|convert)\][^\r\n]{0,120}(-join|\s\|\s*(\biex\b|Invoke-Expression))/i ascii wide
        $ps_ctx        = /(powershell|pwsh|\$ExecutionContext|ScriptBlock|Invoke-[A-Z][a-z]+|FromBase64String|Net\.WebClient|\[char\]|\[Convert\]::|-enc(odedcommand)?\b)/i ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and (
            ( $sink and ( ( $fmt_stack and $fmt_shuffle ) or $char_chain or $envidx or $reverse ) )
            or ( #backtick >= 2 and $ps_ctx )
            or $bxor_loop or $replace_chain or $b64_inline or $b64_inline_r or $split_join
        )
}

/* -----------------------------------------------------------------------------
   PS_HIGH_Stealth_Flags_Remote_Payload
   The launcher line: powershell with stealth flags plus a remote/encoded
   payload, hidden launch of a script staged in the user profile, cmd "start
   /min" wrappers, conhost --headless proxying.
   ----------------------------------------------------------------------------- */
rule PS_HIGH_Stealth_Flags_Remote_Payload
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "execution"
        severity    = "high"
        description = "powershell/pwsh with -nop/-noni/-w hidden/-ep bypass/-sta + URL, IEX, download verb, FromBase64String, -enc blob or mshta http in one line; -w hidden + script in AppData/Temp/Public; start /min wrapper; conhost --headless launching a script host"
        mitre       = "T1059.001,T1564.003"
        fp_notes    = "Vendor scripts occasionally use -ExecutionPolicy Bypass with Invoke-WebRequest to a vendor URL. Check the URL host before escalating."

    strings:
        // One stealth flag + an in-memory execution / encoded payload ...
        $launch           = /(powershell|pwsh)(\.exe)?["']?\s+[^\r\n"']{0,200}-(nop|noprofile|noni|noninteractive|w(indowstyle)?\s+h(idden)?|ep\s+(bypass|unrestricted)|executionpolicy\s+(bypass|unrestricted)|exec\s+bypass|sta)\b[^\r\n]{0,300}(\biex\b|Invoke-Expression|DownloadString|FromBase64String|-e(c|n|nc|ncodedcommand)?\s+[A-Za-z0-9+\/]{40,}|mshta(\.exe)?\s+https?|-urlcache|Start-BitsTransfer|\|\s*iex\b)/i ascii wide
        // ... or a hidden window + any download. ("-NoProfile -ExecutionPolicy Bypass"
        // + Invoke-WebRequest -OutFile is how installers behave and is NOT matched.)
        $launch_hidden    = /(powershell|pwsh)(\.exe)?["']?\s+[^\r\n"']{0,200}-w(indowstyle)?\s+h(idden)?\b[^\r\n]{0,300}(https?:\/\/|Invoke-WebRequest|\birm\s|\biwr\s|DownloadFile|Net\.WebClient)/i ascii wide
        $hidden_userpath  = /(powershell|pwsh)(\.exe)?["']?\s+[^\r\n"']{0,200}-w(indowstyle)?\s+h(idden)?\b[^\r\n]{0,300}(\\Users\\[^\\\r\n"']{1,80}\\(AppData|Downloads|Desktop|Documents)|%(APPDATA|LOCALAPPDATA|TEMP|TMP|PUBLIC|USERPROFILE)%|\$env:(APPDATA|LOCALAPPDATA|TEMP|TMP|PUBLIC|USERPROFILE)|\\Users\\Public\\|\\Windows\\Temp\\)[^\r\n"']{0,160}\.(ps1|psm1|vbs|js|bat|cmd|txt|dat|log|tmp)\b/i ascii wide
        $cmd_start_hidden = /start\s+(\/min|""\s+\/b)\s+[^\r\n]{0,60}(powershell|pwsh|mshta|wscript|cscript)[^\r\n]{0,300}(https?:\/\/|\biex\b|-e(c|n|nc)?\s+[A-Za-z0-9+\/]{40,}|\\AppData\\|%APPDATA%|%TEMP%)/i ascii wide
        $conhost_headless = /conhost(\.exe)?\s+--headless\s+[^\r\n]{0,40}(powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32|curl)/i ascii wide

    condition:
        filesize < 10MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and any of them
}

/* -----------------------------------------------------------------------------
   LOL_HIGH_LOLBAS_Download_Execute
   One rule for the LOLBins that still matter on Windows 11 clients, each bound
   to its abuse syntax plus a remote source, scriptlet or user-writable target.
   (wmic is gone from 24H2+, kept only as a legacy string.)
   ----------------------------------------------------------------------------- */
rule LOL_HIGH_LOLBAS_Download_Execute
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "execution,defense_evasion"
        severity    = "high"
        description = "certutil -urlcache/-decode, bitsadmin /transfer, mshta http/javascript:, regsvr32 scrobj.dll /i:http (Squiblydoo) or SCT body, rundll32 javascript: or user-path DLL/renamed payload, msiexec /i http, curl|wget piped to a shell or -o payload then exec, wmic process call create, forfiles /c, cmstp /ni /s, msbuild/installutil from user paths"
        mitre       = "T1218,T1105,T1127,T1220"

    strings:
        $certutil_dl   = /\bcertutil(\.exe)?\s+(-[A-Za-z]+\s+){0,4}-(urlcache|verifyctl)\b[^\r\n]{0,200}https?:\/\//i ascii wide
        $certutil_dec  = /\bcertutil(\.exe)?\s+(-[A-Za-z]+\s+){0,4}-(decode|decodehex)\b[^\r\n]{0,200}\.(exe|dll|bat|ps1|vbs|hta|js|wsf|cmd|scr|msi|cpl)\b/i ascii wide
        $bitsadmin     = /\bbitsadmin(\.exe)?\s+(\/[A-Za-z]+\s+){0,3}\/transfer\b[^\r\n]{0,200}https?:\/\//i ascii wide
        $mshta_remote  = /\bmshta(\.exe)?\s+["']?(https?:\/\/|\\\\|javascript\s*:|vbscript\s*:)/i ascii wide
        $regsvr_sq     = /(\bregsvr32(\.exe)?\s+(\/[a-z]\s+){0,3}\/i\s*:\s*["']?(https?:\/\/|\\\\)[^\s"'\r\n]{4,300}[^\r\n]{0,80}scrobj\.dll|\bregsvr32(\.exe)?\s+[^\r\n]{0,120}scrobj\.dll[^\r\n]{0,200}\/i\s*:\s*["']?(https?:\/\/|\\\\))/i ascii wide
        $sct_body      = /<registration\s+[^>]{0,200}progid\s*=[\s\S]{0,2000}<script\s+language\s*=\s*["'](JScript|VBScript|JavaScript)["'][\s\S]{0,4000}(WScript\.Shell|Shell\.Application|ActiveXObject|MSXML2|ADODB\.Stream|powershell)/i ascii wide
        $rundll_js     = /\brundll32(\.exe)?\s+["']?(javascript|vbscript)\s*:/i ascii wide
        $rundll_upath  = /\brundll32(\.exe)?\s+["']?(\\Users\\[^\\\r\n"']{1,80}\\(AppData|Downloads|Desktop|Documents)|%(APPDATA|LOCALAPPDATA|TEMP|TMP|PUBLIC)%|\\ProgramData\\|\\Users\\Public\\|\\Windows\\Temp\\|\\Temp\\)[^\r\n"']{0,200}\.(dll|cpl|ocx|dat|txt|png|jpg|log|tmp|bin)["']?\s*,\s*[A-Za-z#@_][A-Za-z0-9_@#]{0,64}/i ascii wide
        $msiexec_remote= /\bmsiexec(\.exe)?\s+[^\r\n]{0,40}(\/i|\/package|\/a|\/q[bnr]?)\s+["']?https?:\/\//i ascii wide
        $curl_pipe     = /\b(curl|wget)(\.exe)?\s+[^\r\n|]{0,200}https?:\/\/[^\s|]{4,300}[^\r\n|]{0,120}\|\s*(powershell|pwsh|cmd)/i ascii wide
        $curl_out_exec = /\bcurl(\.exe)?\s+[^\r\n]{0,200}https?:\/\/[^\s"']{4,300}[^\r\n]{0,120}(-o|--output)\s+["']?[^\s"']{1,200}\.(exe|dll|bat|cmd|ps1|vbs|js|hta|msi|scr)\b[^\r\n]{0,200}(&&|&|;|\|)\s*(start|cmd|powershell|rundll32|regsvr32|mshta|msiexec|wscript|cscript|\S*\.exe)/i ascii wide
        $wmic_create   = /\bwmic(\.exe)?\s+[^\r\n]{0,80}process\s+(where\s+\S+\s+)?call\s+create\s+["']?(cmd|powershell|pwsh|mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript)/i ascii wide
        $forfiles      = /\bforfiles(\.exe)?\s+[^\r\n]{0,120}\/c\s+["']?(cmd(\.exe)?\s+\/[ckqr]|powershell|pwsh|rundll32|regsvr32|mshta|certutil)/i ascii wide
        $cmstp         = /\bcmstp(\.exe)?\s+(\/\w+\s+){0,3}\/ni\s+\/s\s+["']?(https?:\/\/|\\\\|\\Users\\|%TEMP%|%APPDATA%|\\ProgramData\\)/i ascii wide
        $msbuild       = /\bmsbuild(\.exe)?\s+[^\r\n]{0,200}(\\Users\\|%TEMP%|%APPDATA%|\\ProgramData\\|\\Temp\\)[^\r\n"']{0,160}\.(csproj|proj|xml|txt)\b/i ascii wide
        $installutil   = /\binstallutil(\.exe)?\s+[^\r\n]{0,120}\/u(ninstall)?\s+["']?(\\Users\\|%TEMP%|%APPDATA%|\\ProgramData\\|\\Temp\\)/i ascii wide

    condition:
        filesize < 10MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and any of them
}
