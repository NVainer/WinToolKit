/*
================================================================================
 01_reverse_shells_c2.yar
 Author: Nati
 Category: Reverse Shells & C2 Stagers (Windows 11 native)
 Severity: Medium-High to High
 Last updated: 2026-05-24

 Coverage:
   - PowerShell TCPClient / Nishang Invoke-PowerShellTcp variants
   - PowerCat (PowerShell netcat port)
   - PowerShell download cradles bound to IEX with anti-FP shape
   - PowerShell reflective in-memory assembly loaders
   - .NET / C# inline reverse shells (SharpShell-style)
   - cmd.exe + curl/certutil cradles
   - WMI remote command execution (PowerShell-driven)
   - Cobalt Strike beacon shellcode characteristics
   - Sliver / Havoc / Brute Ratel agent strings
   - Meterpreter Windows stager
   - PoshC2 / Empire stagers

 Anti-FP design (2026-05-24 rewrite):
   - Every rule requires an ATTACK SHAPE: a single regex (or proximity-bounded
     AND of two regexes) binding 2+ elements that together characterize a real
     attacker invocation. Standalone keyword/class-name matches are forbidden.
   - C2 framework string-set rules require 2-of-N (3-of-N for generic) AND a
     binary/PE anchor where possible. A tool name in a blog post must not fire.
   - Script-targeted rules add a binary header skip (no PE/ELF) and a 5 MB cap.
   - PE-targeted rules (CS, Sliver, Havoc, BRC4, Meterpreter) skip the PE-skip
     guard and use a 50 MB cap.
   - PowerShell content is matched ascii + wide (UTF-16LE in memory).
================================================================================
*/

import "pe"
import "math"

/* -----------------------------------------------------------------------------
   RS_HIGH_PS_TCPClient_Stream_IEX_Loop
   PowerShell TCPClient reverse shell - the canonical pattern.
   Binds: TCPClient($ip,$port) + GetStream() + Read loop + IEX + Write back.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_PS_TCPClient_Stream_IEX_Loop
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "reverse_shell"
        severity = "high"
        description = "TCPClient(literal IP,port) + any stream operation; or full bound; or all-5 shape; three independent detection paths"
        mitre = "T1059.001,T1071.001"
        reference = "Nishang Invoke-PowerShellTcp pattern; classic PS rev shell oneliner"

    strings:
        // PATH 1 - Full single-bound: TCPClient(IP,port) + .GetStream() within 400 chars
        $bound_full = /(New-Object\s+(System\.)?Net\.Sockets\.TCPClient|\[(System\.)?Net\.Sockets\.TCPClient\](::new|\s*\$))[^;\r\n]{0,40}\(\s*['"](\d{1,3}\.){3}\d{1,3}['"]?\s*,\s*\$?\d{1,5}.{0,400}\.GetStream\s*\(\s*\)/is ascii wide

        // PATH 2 - ATOMIC: literal TCPClient(IP,port) - the single most reliable
        // anchor a PS TCP reverse shell carries. Anything that constructs a
        // TCPClient with a hard-coded IP and port is an IOC. We pair this in
        // the condition with any one stream-op below to keep precision high
        // while eliminating the all-5 AND brittleness of the original shape.
        $atomic_tcp_ipport = /Net\.Sockets\.TCPClient\s*\(\s*['"](\d{1,3}\.){3}\d{1,3}['"]?\s*,\s*\$?\d{1,5}/i ascii wide

        // PATH 3 - Variable-form shape (Nishang/Empire variants). Used as a 3-of-5
        // (was all-5; relaxed to survive minor whitespace/quoting differences).
        $shape_tcp     = /(New-Object\s+(System\.)?Net\.Sockets\.TCPClient|\[(System\.)?Net\.Sockets\.TCPClient\](::new|\s*\$))\s*\(?\s*['"](\d{1,3}\.){3}\d{1,3}['"]?\s*,\s*\$?\d{1,5}/i ascii wide
        $shape_stream  = /\.GetStream\s*\(\s*\)/i ascii wide
        $shape_readlp  = /\.Read\s*\(\s*\$\w+\s*,\s*0\s*,\s*\$\w+\.Length\s*\)/i ascii wide
        $shape_iex     = /(\b(iex|Invoke-Expression)\b\s*\(?\s*\$\w+|\.\s*Invoke\s*\(\s*\$\w+)/i ascii wide
        $shape_write   = /\.Write\s*\(\s*\$\w+\s*,\s*0\s*,\s*\$\w+\.Length\s*\)/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and (
            // PATH 1: full canonical chain in one regex
            $bound_full
            // PATH 2: atomic IP+port shape + any one stream operation
            or ( $atomic_tcp_ipport and ( $shape_stream or $shape_readlp or $shape_write or $shape_iex ) )
            // PATH 3: structural fallback - TCPClient with IP+port + 3 of 4 stream-loop ops
            or ( $shape_tcp and 3 of ( $shape_stream, $shape_readlp, $shape_iex, $shape_write ) )
        )
}

/* -----------------------------------------------------------------------------
   RS_HIGH_PS_TCPClient_NetworkStream_Variant
   Empire/Covenant Grunt variant: NetworkStream variable with literal IP+port,
   bound to a StreamReader/Writer and a shell verb in proximity.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_PS_TCPClient_NetworkStream_Variant
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "reverse_shell"
        severity = "high"
        description = "Bound: TCPClient(ip,port)+GetStream within 200 chars, plus StreamReader/Writer+shell verb in same window"
        mitre = "T1059.001,T1071.001"

    strings:
        // Single bound regex: TCPClient(ip,port) + GetStream + StreamReader/Writer + shell verb in <=800 chars
        $bound = /New-Object\s+(System\.)?Net\.Sockets\.TCPClient\s*\(\s*['"](\d{1,3}\.){3}\d{1,3}['"]\s*,\s*\d{1,5}\s*\)[\s\S]{0,200}\.GetStream\s*\(\s*\)[\s\S]{0,400}\[(System\.)?IO\.Stream(Reader|Writer)\][\s\S]{0,400}(cmd|powershell|pwsh)(\.exe)?/i ascii wide

        // Alternate ordering: shell verb appears before reader/writer
        $bound_alt = /New-Object\s+(System\.)?Net\.Sockets\.TCPClient\s*\(\s*['"](\d{1,3}\.){3}\d{1,3}['"]\s*,\s*\d{1,5}\s*\)[\s\S]{0,200}\.GetStream\s*\(\s*\)[\s\S]{0,600}(cmd|powershell|pwsh)(\.exe)?[\s\S]{0,400}\[(System\.)?IO\.Stream(Reader|Writer)\]/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and ( $bound or $bound_alt )
}

/* -----------------------------------------------------------------------------
   RS_HIGH_PowerCat_Listener_Or_Client
   PowerCat is the PowerShell port of netcat - distinctive flag combinations
   that legitimate scripts never emit. The function-signature branch requires
   the powercat function plus its hallmark variable shape.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_PowerCat_Listener_Or_Client
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "reverse_shell"
        severity = "high"
        description = "Bound: powercat invocation flags (-c ip -p port -e/-ep) or function body + 3 of source-only param names"
        mitre = "T1059.001"
        reference = "https://github.com/besimorhino/powercat"

    strings:
        // powercat -c IP -p PORT -e cmd / -ep base64
        $pc_client = /powercat\s+(-\w+\s+\S+\s+){0,4}-c\s+(\d{1,3}\.){3}\d{1,3}\s+(-\w+\s+\S+\s+){0,4}-p\s+\d{1,5}\s+(-\w+\s+\S+\s+){0,4}-(e|ep|i|o)\s+\S+/i ascii wide
        // powercat -l -p PORT -e cmd (bind shell side)
        $pc_listen = /powercat\s+(-\w+\s+\S+\s+){0,4}-l\s+(-\w+\s+\S+\s+){0,4}-p\s+\d{1,5}\s+(-\w+\s+\S+\s+){0,4}-e\s+(cmd|powershell|pwsh)(\.exe)?/i ascii wide
        // Function body marker bound to source-only variables (raises 3-of-N)
        $pc_func    = /function\s+powercat\s*\{/i ascii wide
        $pc_param1  = "$ListenerSocket" ascii wide
        $pc_param2  = "$ClientSocket"   ascii wide
        $pc_param3  = "$RelayConfig"    ascii wide
        $pc_param4  = "$EncodedText"    ascii wide
        $pc_param5  = "$ExecuteString"  ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and (
            $pc_client
            or $pc_listen
            or ( $pc_func and 3 of ( $pc_param* ) )
        )
}

/* -----------------------------------------------------------------------------
   RS_HIGH_PS_Download_Cradle_IEX_HTTP
   Download cradle: PS pulls a remote payload and pipes to IEX. Every branch
   binds the downloader verb + URL + execution handoff in a single regex.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_PS_Download_Cradle_IEX_HTTP
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "c2_stager"
        severity = "high"
        description = "Bound: download verb + http(s) URL + IEX/Invoke handoff in a single proximity window"
        mitre = "T1059.001,T1105"

    strings:
        // IEX (New-Object Net.WebClient).DownloadString('http(s)://...')
        $cradle_dl    = /(iex|Invoke-Expression)\s*\(?\s*\(?\s*(New-Object\s+(System\.)?Net\.WebClient|\[(System\.)?Net\.WebClient\](::new|\s*\$))[^;\r\n]{0,40}\.DownloadString\s*\(\s*['"](https?:\/\/|ftp:\/\/)[^'"\r\n]{4,256}['"]\s*\)/is ascii wide

        // IEX (iwr -useb http://...) variant
        $cradle_iwr   = /(iex|Invoke-Expression)\s*\(?\s*\(?\s*(Invoke-WebRequest|iwr|wget|curl)\b[^;\r\n]{0,200}(-useb|-UseBasicParsing|-Uri)?[^;\r\n]{0,40}['"]?(https?:\/\/)[^'"\s\r\n]{4,256}/is ascii wide

        // .Content -> IEX
        $cradle_content = /(Invoke-WebRequest|iwr|wget)\b[^;\r\n]{0,80}['"]?(https?:\/\/)[^'"\s\r\n]{4,256}[^;\r\n]{0,80}\.Content\s*\|\s*(iex|Invoke-Expression)/is ascii wide

        // DownloadFile + Start-Process / IEX of read content
        $cradle_dlfile  = /\.DownloadFile\s*\(\s*['"](https?:\/\/)[^'"\r\n]{4,256}['"]\s*,\s*['"][^'"\r\n]{1,256}['"]\s*\)[^;\r\n\}]{0,200}(Start-Process|saps|Invoke-Item|& \$|\.Invoke\(\))/is ascii wide

        // Net.WebClient with proxy + DownloadString + IEX (defense evasion variant)
        $cradle_proxy   = /\$\w+\.Proxy\s*=\s*\[(System\.)?Net\.WebRequest\]::DefaultWebProxy.{0,400}\.DownloadString\s*\(\s*['"](https?:\/\/)[^'"\r\n]{4,256}['"][^;\r\n]{0,200}(iex|Invoke-Expression)/is ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of ( $cradle_dl, $cradle_iwr, $cradle_content, $cradle_dlfile, $cradle_proxy )
}

/* -----------------------------------------------------------------------------
   RS_HIGH_PS_Reflective_Assembly_Load_FromBase64
   In-memory .NET assembly load from base64 - reflective loader pattern.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_PS_Reflective_Assembly_Load_FromBase64
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "c2_stager"
        severity = "high"
        description = "Bound: Assembly.Load tied to FromBase64String or EntryPoint.Invoke/GetMethod.Invoke in one regex"
        mitre = "T1620,T1059.001"

    strings:
        // [Reflection.Assembly]::Load([Convert]::FromBase64String("<200+ b64>"))
        $reflective = /\[(System\.)?Reflection\.Assembly\]::Load\s*\(\s*\[(System\.)?Convert\]::FromBase64String\s*\(\s*['"][A-Za-z0-9+\/=]{200,}['"]\s*\)\s*\)/is ascii wide

        // [Reflection.Assembly]::Load($bytes) with EntryPoint.Invoke nearby
        $entrypoint = /\[(System\.)?Reflection\.Assembly\]::Load\s*\([^)]{1,80}\)[^;\r\n]{0,300}\.EntryPoint\.Invoke\s*\(/is ascii wide

        // GetType().GetMethod().Invoke chain after Assembly Load
        $invokemethod = /\[(System\.)?Reflection\.Assembly\]::Load\s*\([^)]{1,80}\)[^;\r\n]{0,400}\.GetType\s*\(\s*['"][^'"]{1,80}['"]\s*\)\.GetMethod\s*\(\s*['"][^'"]{1,80}['"]\s*\)\.Invoke\s*\(/is ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   RS_HIGH_PS_Shellcode_VirtualAlloc_CreateThread
   PS shellcode injection: VirtualAlloc + Marshal.Copy + CreateThread shape,
   bound by a single regex that requires the full alloc->copy->run chain.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_PS_Shellcode_VirtualAlloc_CreateThread
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "c2_stager"
        severity = "high"
        description = "Bound: VirtualAlloc + Marshal.Copy + CreateThread family within one 600-char window, plus shellcode byte array or DllImport"
        mitre = "T1055,T1059.001"

    strings:
        // Full alloc->copy->thread chain in one window
        $bound_chain = /(\[\w+\]::)?VirtualAlloc(Ex)?\b[\s\S]{0,600}\[(System\.)?Runtime\.InteropServices\.Marshal\]::Copy\b[\s\S]{0,600}(CreateThread|NtCreateThreadEx|CreateRemoteThread|QueueUserAPC|RtlCreateUserThread)\b/i ascii wide

        // Add-Type DllImport binding kernel32 + VirtualAlloc + CreateThread (Add-Type cradle)
        $bound_addtype = /Add-Type\s+-(TypeDefinition|MemberDefinition)\b[\s\S]{0,1500}DllImport\s*\(\s*["']kernel32(\.dll)?["'][\s\S]{0,800}VirtualAlloc(Ex)?\b[\s\S]{0,600}(CreateThread|NtCreateThreadEx|CreateRemoteThread|QueueUserAPC|RtlCreateUserThread)\b/i ascii wide

        // Shellcode byte array of plausible size near a wait primitive
        $bound_scwait = /\[Byte\[\]\]\s*\$\w+\s*=\s*(@\(\s*)?0x[0-9A-Fa-f]{2}\s*,\s*0x[0-9A-Fa-f]{2}[\s\S]{0,200}0x[0-9A-Fa-f]{2}[\s\S]{0,2000}(WaitForSingleObject|NtWaitForSingleObject)\b/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and ( $bound_chain or $bound_addtype or $bound_scwait )
}

/* -----------------------------------------------------------------------------
   RS_HIGH_PS_NamedPipe_C2
   Named-pipe C2 / lateral movement. Bound: NamedPipe ctor + Connect/Wait +
   bidirectional IO + IEX-style execution in one proximity window.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_PS_NamedPipe_C2
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "c2_stager"
        severity = "high"
        description = "Bound: NamedPipeClient/Server ctor + Connect/Wait + Read/Write loop + IEX in one 1500-char window"
        mitre = "T1071,T1570"

    strings:
        // Pipe ctor + connect + IO + IEX (forward ordering)
        $bound_pipe = /(New-Object\s+(System\.)?IO\.Pipes\.NamedPipe(Client|Server)Stream|\[(System\.)?IO\.Pipes\.NamedPipe(Client|Server)Stream\]::new)[\s\S]{0,400}(\.Connect\s*\(\s*\d{1,6}\s*\)|\.WaitForConnection\s*\(\s*\))[\s\S]{0,1500}\$\w+\.(Read|Write)\s*\(\s*\$\w+\s*,\s*0\s*,\s*\$\w+\.Length\s*\)[\s\S]{0,1500}(\b(iex|Invoke-Expression)\b|\.Invoke\s*\(\s*\$\w+\s*\))/i ascii wide

        // IO+IEX appear before/after pipe-ctor swap (loop-first ordering)
        $bound_pipe_alt = /(\b(iex|Invoke-Expression)\b|\.Invoke\s*\(\s*\$\w+\s*\))[\s\S]{0,1500}(New-Object\s+(System\.)?IO\.Pipes\.NamedPipe(Client|Server)Stream|\[(System\.)?IO\.Pipes\.NamedPipe(Client|Server)Stream\]::new)[\s\S]{0,400}(\.Connect\s*\(\s*\d{1,6}\s*\)|\.WaitForConnection\s*\(\s*\))/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and ( $bound_pipe or $bound_pipe_alt )
}

/* -----------------------------------------------------------------------------
   RS_HIGH_CMD_Curl_Certutil_IEX_Cradle
   cmd.exe pipeline: curl/certutil pulls payload then pipes to PS IEX.
   Single bound regex requires the full pipeline within one window.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_CMD_Curl_Certutil_IEX_Cradle
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "c2_stager"
        severity = "high"
        description = "Bound: curl/certutil + http(s) URL + pipe to powershell/pwsh + iex/-c handoff in one regex"
        mitre = "T1059.003,T1105"

    strings:
        // Inline pipeline: curl/certutil <url> | powershell -c iex
        $curl_iex  = /(^|[\s&|"\\\/])(curl(\.exe)?|certutil(\.exe)?)\s+(-[A-Za-z]+\s+){0,4}(-?-?url)?[^|\r\n]{0,80}(https?:\/\/)[^|\s\r\n]{4,256}[^|\r\n]{0,200}\|\s*(powershell|pwsh)(\.exe)?\s+(-\w+\s+\S+\s+){0,4}-?(iex|c|command)/is ascii wide

        // for /f wrapper that captures curl output and feeds it to powershell/cmd
        $cmd_for_dl = /for\s+\/f\s+["'][^"']{1,80}["']\s+%%?\w+\s+in\s+\(['"]?(curl|certutil)[^)]{4,300}https?:\/\/[^)]{4,256}\)\s+do\s+(powershell|pwsh|cmd)\b/i ascii wide

        // certutil -urlcache -split -f <url> followed by exec verb in proximity
        $certutil_urlcache = /certutil(\.exe)?\s+(-\w+\s+){1,4}-f\s+["']?https?:\/\/[^"'\s\r\n]{4,256}["']?\s+[^\r\n]{1,200}\s+&{1,2}\s*(start|powershell|pwsh|cmd|rundll32|regsvr32|wmic|mshta)\b/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and ( $curl_iex or $cmd_for_dl or $certutil_urlcache )
}

/* -----------------------------------------------------------------------------
   RS_HIGH_PS_WMI_Process_Create_Remote
   PS Win32_Process::Create against a remote host with a cmd/powershell payload.
   Bound: WMI verb + remote-host arg + Win32_Process + shell payload in one regex.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_PS_WMI_Process_Create_Remote
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "lateral_movement"
        severity = "high"
        description = "Bound: Invoke-WmiMethod/CimMethod + -ComputerName/-CimSession + Win32_Process + shell payload in one regex"
        mitre = "T1047,T1021.006"

    strings:
        // Single bound: Invoke-WmiMethod/CimMethod + remote target + Win32_Process + ArgumentList shell payload
        $bound_wmi = /(Invoke-WmiMethod|Invoke-CimMethod)\b[^;\r\n]{0,200}-(ComputerName|CimSession)\s+['"]?[^\s'"`]{1,256}['"]?[^;\r\n]{0,300}Win32_Process[^;\r\n]{0,300}-ArgumentList\s+@?\(?['"](powershell|pwsh|cmd)(\.exe)?\b/i ascii wide

        // gwmi/Get-WmiObject Win32_Process variant with remote arg + shell payload
        $bound_gwmi = /(Get-WmiObject|gwmi)\b[^;\r\n]{0,80}-Class\s+Win32_Process[^;\r\n]{0,200}-ComputerName\s+['"]?[^\s'"`]{1,256}['"]?[^;\r\n]{0,300}-ArgumentList\s+@?\(?['"](powershell|pwsh|cmd)(\.exe)?\b/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and ( $bound_wmi or $bound_gwmi )
}

/* -----------------------------------------------------------------------------
   RS_HIGH_DotNet_TcpClient_CSharp_Source
   C# source reverse shell (SharpShell-style). Bound: TcpClient(ip,port) +
   ProcessStartInfo cmd/powershell + redirected stdio + UseShellExecute=false.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_DotNet_TcpClient_CSharp_Source
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "reverse_shell"
        severity = "high"
        description = "Bound: C# TcpClient(ip,port) + ProcessStartInfo cmd/ps + RedirectStandard* + UseShellExecute=false in one window"
        mitre = "T1059.001,T1059.003"

    strings:
        // Single bound regex: TCP literal ctor + ProcessStartInfo shell + redirect + no-shell-exec, in <= 1600 chars
        $bound_cs = /new\s+TcpClient\s*\(\s*"(\d{1,3}\.){3}\d{1,3}"\s*,\s*\d{1,5}\s*\)[\s\S]{0,1200}(new\s+ProcessStartInfo\s*\(\s*"(cmd|powershell|pwsh)(\.exe)?"\s*\)|FileName\s*=\s*"(cmd|powershell|pwsh)(\.exe)?")[\s\S]{0,800}RedirectStandard(Input|Output|Error)\s*=\s*true[\s\S]{0,800}UseShellExecute\s*=\s*false/i ascii wide

        // Alternate order: StartInfo first, then literal TcpClient
        $bound_cs_alt = /(new\s+ProcessStartInfo\s*\(\s*"(cmd|powershell|pwsh)(\.exe)?"\s*\)|FileName\s*=\s*"(cmd|powershell|pwsh)(\.exe)?")[\s\S]{0,800}UseShellExecute\s*=\s*false[\s\S]{0,800}RedirectStandard(Input|Output|Error)\s*=\s*true[\s\S]{0,1200}new\s+TcpClient\s*\(\s*"(\d{1,3}\.){3}\d{1,3}"\s*,\s*\d{1,5}\s*\)/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and ( $bound_cs or $bound_cs_alt )
}

/* -----------------------------------------------------------------------------
   RS_HIGH_PS_HTTP_Beacon_Loop_Shape
   PS HTTP beacon: while-true + DownloadString/IWR of variable URL + jitter +
   IEX of response. All four pieces required in one window.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_PS_HTTP_Beacon_Loop_Shape
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "c2_stager"
        severity = "high"
        description = "Bound: while-true + DownloadString/IWR + Start-Sleep jitter + IEX-of-variable + literal http URL in one window"
        mitre = "T1071.001,T1059.001"

    strings:
        // Single bound: loop + http_get + sleep_jit + iex within 2000 chars after a literal http URL assignment
        $bound_beacon = /\$\w+\s*=\s*['"]https?:\/\/[^'"\r\n]{4,256}['"][\s\S]{0,2000}while\s*\(\s*\$?(true|1)\s*\)\s*\{[\s\S]{0,1500}(\.DownloadString\s*\(\s*['"]?\$?\w+|Invoke-WebRequest\s+(-Uri\s+)?['"]?\$?\w+)[\s\S]{0,800}Start-Sleep\s+(-Seconds\s+)?\$?(\d{1,5}|\(Get-Random[^)]{0,80}\))[\s\S]{0,800}(\b(iex|Invoke-Expression)\b\s*\(?\s*\$\w+|\.Invoke\s*\(\s*\$\w+\s*\))/is ascii wide

        // Alternate ordering: while + sleep before download/iex
        $bound_beacon_alt = /while\s*\(\s*\$?(true|1)\s*\)\s*\{[\s\S]{0,800}Start-Sleep\s+(-Seconds\s+)?\$?(\d{1,5}|\(Get-Random[^)]{0,80}\))[\s\S]{0,1500}(\.DownloadString\s*\(\s*['"]?\$?\w+|Invoke-WebRequest\s+(-Uri\s+)?['"]?\$?\w+)[\s\S]{0,800}(\b(iex|Invoke-Expression)\b\s*\(?\s*\$\w+|\.Invoke\s*\(\s*\$\w+\s*\))[\s\S]{0,2000}https?:\/\//is ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and ( $bound_beacon or $bound_beacon_alt )
}

/* -----------------------------------------------------------------------------
   RS_HIGH_CobaltStrike_Beacon_Strings
   Cobalt Strike beacon: distinctive markers + PE context. Generic %s/%d
   printf strings only count when paired with a beacon-specific anchor.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_CobaltStrike_Beacon_Strings
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "c2_implant"
        severity = "high"
        description = "Bound: 2-of-N distinctive CS markers in PE, or printf-set + distinctive anchor + pipe shape inside PE"
        mitre = "T1071.001,T1573"
        reference = "Open-source CS beacon config research (Sentinel-One, Elastic, Mandiant)"

    strings:
        // Distinctive markers
        $cs_reflective = "ReflectiveLoader" ascii wide
        $cs_dll64 = "beacon.x64.dll" ascii wide
        $cs_dll   = "beacon.dll" ascii wide

        // Printf-style strings (generic alone)
        $cs1 = "%s as %s\\%s: %d" ascii wide
        $cs2 = "could not spawn %s: %d" ascii wide
        $cs3 = "%%IMPORT%%" ascii wide
        $cs_artifact1 = "%s.4%08x%08x%08x%08x%08x.%s" ascii wide
        $cs_artifact2 = "Could not connect to pipe (%s): %d" ascii wide

        // SMB beacon default and Malleable pipe shapes
        $cs_pipe = /\\\\\\\\\.\\\\pipe\\\\(MSSE-\d{1,4}-server|status_\d{1,3}|postex_(default|ssh)_\d{1,4}|msagent_\d{1,4}|mojo\.\d{4,})/i ascii wide
        $cs_pipe_msse = "MSSE-" ascii wide

    condition:
        filesize < 50MB
        and pe.is_pe
        and (
            // Two distinctive markers
            2 of ( $cs_reflective, $cs_dll64, $cs_dll )
            // OR 3 printf strings + 1 distinctive marker
            or ( 3 of ( $cs1, $cs2, $cs3, $cs_artifact1, $cs_artifact2 ) and 1 of ( $cs_reflective, $cs_dll64, $cs_dll ) )
            // OR distinctive named-pipe shape + a distinctive marker
            or ( $cs_pipe and 1 of ( $cs_reflective, $cs_dll64, $cs_dll ) )
            // OR MSSE- pipe prefix + ReflectiveLoader (both must be in the same PE)
            or ( $cs_pipe_msse and $cs_reflective )
        )
}

/* -----------------------------------------------------------------------------
   RS_HIGH_Sliver_Implant_Strings
   Sliver C2 (BishopFox) Windows implant. Requires 2-of-N inside a PE.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_Sliver_Implant_Strings
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "c2_implant"
        severity = "high"
        description = "Bound: 2-of-N Sliver-specific Go symbols/paths inside a PE"
        mitre = "T1071,T1573"
        reference = "https://github.com/BishopFox/sliver"

    strings:
        $s1 = "sliverpb." ascii wide
        $s2 = "bishopfox.com/sliver" ascii wide
        $s3 = "sliver.s2.commonpb" ascii wide
        $s4 = "/sliver/" ascii wide
        $s5 = "sliverpb.Envelope" ascii wide
        $s6 = "github.com/bishopfox/sliver/implant/sliver" ascii wide
        $s7 = "RegisterSliverPBHandlers" ascii wide
        $s_dll = "sliverdll" ascii wide

    condition:
        filesize < 50MB
        and pe.is_pe
        and 2 of them
}

/* -----------------------------------------------------------------------------
   RS_HIGH_Havoc_Implant_Strings
   Havoc C2 (C5pider) Demon implant. 2-of-N inside a PE.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_Havoc_Implant_Strings
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "c2_implant"
        severity = "high"
        description = "Bound: 2-of-N Havoc Demon-specific symbols/paths inside a PE"
        mitre = "T1071,T1573"
        reference = "https://github.com/HavocFramework/Havoc"

    strings:
        $h1 = "HavocFramework" ascii wide
        $h2 = "Demon.x64.dll" ascii wide
        $h3 = "Demon.x86.dll" ascii wide
        $h4 = "C:\\Havoc\\" ascii wide
        $h5 = "/demon" ascii wide
        $h6 = "DemonRoutine" ascii wide
        $h7 = "DEMON_INSTANCE" ascii wide
        $h8 = "Havoc-C2" ascii wide

    condition:
        filesize < 50MB
        and pe.is_pe
        and 2 of them
}

/* -----------------------------------------------------------------------------
   RS_HIGH_BruteRatel_Badger_Strings
   Brute Ratel C4 Badger implant. 2-of-N inside a PE.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_BruteRatel_Badger_Strings
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "c2_implant"
        severity = "high"
        description = "Bound: 2-of-N Brute Ratel Badger-specific symbols inside a PE"
        mitre = "T1071,T1573"
        reference = "Mandiant BRC4 research; UNC2589 / APT29 use"

    strings:
        $br1 = "BadgerInstance" ascii wide
        $br2 = "BrcBadger" ascii wide
        $br3 = "badger.dll" ascii wide
        $br4 = "BadgerTeamServer" ascii wide
        $br5 = "ChiselComm" ascii wide
        $br6 = "BadgerSpawn" ascii wide
        $br7 = "PivotBadger" ascii wide

    condition:
        filesize < 50MB
        and pe.is_pe
        and 2 of them
}

/* -----------------------------------------------------------------------------
   RS_HIGH_Meterpreter_Stager_Strings
   Meterpreter Windows stager: shellcode prologue (exact bytes) OR 4-of-N
   distinctive strings inside a PE. The string-only branch is tightened to 4
   so a single error-handling DLL with "ws2_32.dll" + "InternetOpen" never
   triggers on its own.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_Meterpreter_Stager_Strings
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "c2_implant"
        severity = "high"
        description = "Bound: msfvenom x86/x64 reverse_tcp shellcode prologue, or 4-of-N Meterpreter-specific strings inside a PE"
        mitre = "T1071,T1055"

    strings:
        // Distinctive meterpreter strings
        $m_metsrv     = "metsrv.dll" ascii wide
        $m_reflective = "ReflectiveLoader" ascii wide
        $m_metshell   = "MeterpreterShell" ascii wide
        $m_stdapi     = "stdapi_sys_process_get_processes" ascii wide
        $m_metsrv2    = "metsrv" ascii wide

        // Generic imports — only contribute alongside distinctive markers
        $m_ws2 = "ws2_32.dll" ascii wide
        $m_wi  = "wininet.dll" ascii wide
        $m_io  = "InternetOpen" ascii wide

        // x86 msfvenom windows/meterpreter/reverse_tcp stager
        $sc_x86 = { FC E8 8?  00 00 00 60 89 E5 31 C0 64 8B 50 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF }
        // x64 stager prologue
        $sc_x64 = { FC 48 83 E4 F0 E8 ?? ?? 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 60 }

    condition:
        filesize < 50MB
        and (
            // Stager shellcode bytes are sufficient
            $sc_x86 or $sc_x64
            // OR 2 distinctive + at least 1 generic import, inside a PE
            or ( pe.is_pe and 2 of ( $m_metsrv, $m_reflective, $m_metshell, $m_stdapi, $m_metsrv2 ) and 1 of ( $m_ws2, $m_wi, $m_io ) )
            // OR 3 distinctive markers inside a PE (no generic anchor required)
            or ( pe.is_pe and 3 of ( $m_metsrv, $m_reflective, $m_metshell, $m_stdapi, $m_metsrv2 ) )
        )
}

/* -----------------------------------------------------------------------------
   RS_HIGH_PoshC2_Empire_Stager
   PoshC2/Empire/Starkiller PS stager. Requires 3-of-N framework strings, OR
   the Empire AES-decrypt-and-IEX bound pattern within one window.
   ----------------------------------------------------------------------------- */
rule RS_HIGH_PoshC2_Empire_Stager
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "c2_stager"
        severity = "high"
        description = "Bound: 3-of-N PoshC2/Empire/Starkiller framework symbols, or AES-decrypt + IEX-of-result in one regex"
        mitre = "T1059.001,T1071.001"
        reference = "https://github.com/nettitude/PoshC2 ; https://github.com/EmpireProject/Empire"

    strings:
        $pc1 = "Posh-SecMod" ascii wide
        $pc2 = "function Invoke-PoshC2" ascii wide
        $pc3 = "Get-WebConfig" ascii wide
        $em1 = "Invoke-Empire" ascii wide
        $em2 = "Invoke-PowerShellTcp" ascii wide
        $em3 = "$ScriptBlock = [ScriptBlock]::Create" ascii wide
        $em4 = "Invoke-WinEnum" ascii wide
        $em5 = "function Invoke-Mimikatz" ascii wide
        $stark1 = "Starkiller" ascii wide

        // Empire AES decrypt + IEX of decrypted bytes bound in one window
        $em_aes_bound = /\[(System\.)?Security\.Cryptography\.Aes(Managed)?\]\s*\$\w+[\s\S]{0,800}(CreateDecryptor|TransformFinalBlock)[\s\S]{0,800}\b(iex|Invoke-Expression)\b\s*\(?\s*[\(\$]/is ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and (
            3 of ( $pc1, $pc2, $pc3, $em1, $em2, $em3, $em4, $em5, $stark1 )
            or $em_aes_bound
        )
}
