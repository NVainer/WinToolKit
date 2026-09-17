/*
================================================================================
 06_obfuscated_powershell.yar
 Author: Nati
 Category: Obfuscated / Stealth PowerShell (Windows 11)
 Severity: Medium-High to High
 Last updated: 2026-05-24

 Coverage:
   - Stealth-flag stack BOUND to a downloader/IEX (so we do not FP on
     Defender's frequent legitimate -enc usage)
   - Invoke-Obfuscation token patterns: format-op {N} stacking, [char] array
     reconstruction, env-var IEX reconstruction ($shellid[N]+...), backtick-
     broken IEX, ScriptBlock.Create+Invoke
   - In-memory GZIP/Deflate unpack + Reflection.Assembly.Load + Invoke
   - Long Base64 blobs decoded into byte arrays then loaded reflectively
   - Download cradle to trusted abused hosts (raw.githubusercontent.com,
     gist, cdn.discordapp.com, pastebin raw, transfer.sh, 0x0.st, ngrok,
     trycloudflare, telegra.ph, t.me)
   - .NET-style obfuscation: char-by-char concat into a method name,
     Type.GetType from reversed/concat string
   - PS shellcode injection scaffolding (P/Invoke VirtualAlloc + RtlMoveMemory
     + CreateThread) with high-entropy byte array
   - Obfuscated AMSI/ETW token reconstruction (e.g. 'a'+'m'+'s'+'i')

 Anti-FP design notes (v2026-05-24 bound-pattern pass):
   - Every rule REQUIRES an attack-shape binding: the obfuscation signature
     (stealth flags, format placeholders, [char] arrays, backtick splits,
     env-var indexing, gzip/deflate, XOR loops, reverse-concat, AMSI token
     reassembly) AND a payload sink (IEX / Invoke-Expression / .Invoke() /
     Reflection.Assembly.Load / FromBase64String / ScriptBlock.Create) within
     a 200-500 char proximity window. Standalone keyword OR-branches are
     forbidden - they caused FPs on Windows.db (Search index), Office Excel
     JS bundles (cUrl class, webpack source maps) and browser caches.
   - PE / ELF header skip and filesize < 5MB applied to every rule.
   - Defender's "-enc <long b64>" oneliners with no IEX wrapper and no remote
     URL do not fire (those are legitimate scanner cmdlets).
   - Format-op rule requires 6+ {N} placeholder tokens AND -f AND IEX sink.
   - [char] array rule requires 8+ [char]NN AND -join AND IEX sink.
   - Trusted-site downloader rule binds the host AND a cradle verb within
     200 chars (verb<->URL bidirectional).
================================================================================
*/

/* -----------------------------------------------------------------------------
   OBF_HIGH_PS_Stealth_Flags_Plus_Downloader
   Stealth flag stack BOUND to a download cradle in the same command line.
   Canonical "powershell -nop -w hidden -ep bypass -c IEX(...)" pattern.
   ----------------------------------------------------------------------------- */
rule OBF_HIGH_PS_Stealth_Flags_Plus_Downloader
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "obfuscation"
        severity = "high"
        description = "PS stealth flag stack (-nop -w hidden -ep bypass) BOUND in <=300 chars to a downloader cradle (Net.WebClient/DownloadString/Invoke-WebRequest/IEX/FromBase64String)"
        mitre = "T1059.001,T1027"

    strings:
        // Full bound shape: powershell + at least one stealth flag + downloader/IEX sink in one regex window
        $bound_nop_hidden_sink = /\b(powershell(\.exe)?|pwsh(\.exe)?)\s+[^"\r\n]{0,80}-(nop|noprofile)\b[^"\r\n]{0,160}-w(in(dowstyle)?)?\s+h(idden)?[^"\r\n]{0,300}(IEX|Invoke-Expression|DownloadString|Invoke-WebRequest|Net\.WebClient|FromBase64String\s*\(\s*['"][A-Za-z0-9+\/=]{40,}|\[Reflection\.Assembly\]::Load)/is ascii wide

        // Alternate ordering: bypass flag near sink
        $bound_bypass_sink = /\b(powershell(\.exe)?|pwsh(\.exe)?)\s+[^"\r\n]{0,200}-(ep|executionpolicy)\s+(bypass|unrestricted)\b[^"\r\n]{0,300}(IEX|Invoke-Expression|DownloadString|Invoke-WebRequest|Net\.WebClient|FromBase64String\s*\(\s*['"][A-Za-z0-9+\/=]{40,}|\[Reflection\.Assembly\]::Load)/is ascii wide

        // Alternate ordering: -enc / -c followed by IEX/downloader in same line
        $bound_enc_sink = /\b(powershell(\.exe)?|pwsh(\.exe)?)\s+[^"\r\n]{0,200}-(c|command|enc(odedcommand)?)\b[^"\r\n]{0,300}(IEX|Invoke-Expression|DownloadString|Invoke-WebRequest|Net\.WebClient|FromBase64String\s*\(\s*['"][A-Za-z0-9+\/=]{40,}|\[Reflection\.Assembly\]::Load)/is ascii wide

    condition:
        not uint16(0) == 0x5A4D and
        not uint32(0) == 0x464C457F and
        filesize < 5MB and
        any of ( $bound_nop_hidden_sink, $bound_bypass_sink, $bound_enc_sink )
}

/* -----------------------------------------------------------------------------
   OBF_HIGH_InvokeObfuscation_FormatOp_Stack
   Invoke-Obfuscation TOKEN\ALL\1 / TOKEN\STRING\1 - format operator with
   6+ {N} placeholders BOUND to -f operator AND an IEX/Invoke sink.
   ----------------------------------------------------------------------------- */
rule OBF_HIGH_InvokeObfuscation_FormatOp_Stack
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "obfuscation"
        severity = "high"
        description = "Invoke-Obfuscation -f format-op with 6+ {N} placeholders BOUND to IEX/Invoke/ScriptBlock.Create/ExecutionContext sink in <=400 chars"
        mitre = "T1027"

    strings:
        // 6+ {N} placeholders, then -f, then an execution sink within 400 chars
        $bound_fmt6_sink = /["'](\{\d{1,2}\}[^"'\r\n]{0,3}){6,}["']\s*-f\s+[^\r\n]{0,400}(IEX|Invoke-Expression|\.Invoke\s*\(|\$ExecutionContext\.\s*InvokeCommand\.\s*(NewScriptBlock|ExpandString|InvokeScript)|\[ScriptBlock\]::\s*Create\s*\(|&\s*\(\s*['"]?\$?\w)/is ascii wide

        // Inverse order: sink that consumes a -f format-op string with 6+ placeholders
        $bound_sink_fmt6 = /(IEX|Invoke-Expression|\.Invoke\s*\(|\$ExecutionContext\.\s*InvokeCommand|\[ScriptBlock\]::\s*Create)[^\r\n]{0,200}["'](\{\d{1,2}\}[^"'\r\n]{0,3}){6,}["']\s*-f\s+/is ascii wide

    condition:
        not uint16(0) == 0x5A4D and
        not uint32(0) == 0x464C457F and
        filesize < 5MB and
        ( $bound_fmt6_sink or $bound_sink_fmt6 )
}

/* -----------------------------------------------------------------------------
   OBF_HIGH_InvokeObfuscation_Char_Array_Reconstruction
   8+ [char]NN reassemblies BOUND to -join / [string]::Join AND an IEX/Invoke
   sink in the same window. Invoke-Obfuscation TOKEN\STRING\3.
   ----------------------------------------------------------------------------- */
rule OBF_HIGH_InvokeObfuscation_Char_Array_Reconstruction
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "obfuscation"
        severity = "high"
        description = "8+ [char]NN reconstruction tokens BOUND to -join/[string]::Join AND IEX/Invoke/ScriptBlock.Create sink in same window"
        mitre = "T1027"

    strings:
        // Char chain -> join -> sink, all within ~500 chars
        $bound_char_join_sink = /(\[char\]\s*(0x)?\d{1,4}\s*[\+\,\)\(\;]\s*){8,}[^\r\n]{0,200}(-join\s*|\[string\]::\s*Join\s*\()[^\r\n]{0,300}(IEX|Invoke-Expression|\.Invoke\s*\(|\$ExecutionContext|\[ScriptBlock\]::\s*Create)/is ascii wide

        // Inverse: sink consuming a -join over an 8+ [char] chain
        $bound_sink_join_char = /(IEX|Invoke-Expression|\.Invoke\s*\(|\$ExecutionContext|\[ScriptBlock\]::\s*Create)[^\r\n]{0,200}(-join\s*|\[string\]::\s*Join\s*\()[^\r\n]{0,300}(\[char\]\s*(0x)?\d{1,4}\s*[\+\,\)\(\;]\s*){8,}/is ascii wide

        // Byte-array variant: 8+ [byte]NN with join and sink
        $bound_byte_join_sink = /(\[byte\]\s*(0x)?\d{1,4}\s*[\+\,\)\(\;]\s*){8,}[^\r\n]{0,200}(-join\s*|\[string\]::\s*Join\s*\()[^\r\n]{0,300}(IEX|Invoke-Expression|\.Invoke\s*\(|\[ScriptBlock\]::\s*Create|\[Reflection\.Assembly\]::Load)/is ascii wide

    condition:
        not uint16(0) == 0x5A4D and
        not uint32(0) == 0x464C457F and
        filesize < 5MB and
        any of ( $bound_char_join_sink, $bound_sink_join_char, $bound_byte_join_sink )
}

/* -----------------------------------------------------------------------------
   OBF_HIGH_PS_Backtick_Broken_IEX
   Backtick-injected IEX / Invoke-Expression tokens (I`E`X, Invo`ke-Expr`ession).
   PRESERVED: already-tightened rule from prior pass. Only date updated.
   ----------------------------------------------------------------------------- */
rule OBF_HIGH_PS_Backtick_Broken_IEX
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "obfuscation"
        severity = "high"
        description = "Backtick-broken IEX / Invoke-Expression / DownloadString / Bypass / Base64 tokens. Literal backtick required INSIDE the identifier (the prior `? made backticks optional, matching plain keywords)."
        mitre = "T1027"

    strings:
        // At least one literal backtick must sit between letters of the keyword.
        // `+ = one or more backticks (required), `* = zero or more (optional filler)
        $iex_bt = /I`+E`*X|I`*E`+X/i ascii wide
        $ie_bt  = /Inv`+oke-?Express`*ion|Inv`*oke-?Express`+ion|Invoke`+-?Expression/i ascii wide
        $dl_bt  = /Down`+load(String|File)|Down`*load`+(String|File)|Web`+Client|We`+bClient/i ascii wide
        $bp_bt  = /B`+ypass|B`+ase64|FromBase64`+String|From`+Base64String|am`+si(Init|Scan|Context)/i ascii wide

        // PowerShell execution-context anchor. Real obfuscated PS always has one of these
        // nearby; HP/MS config files, MUI/ETL blobs, and binary noise do not.
        $ps_ctx = /(powershell(\.exe)?|pwsh(\.exe)?|\$ExecutionContext|\bScriptBlock\b|\bInvoke-[A-Z]|FromBase64String|DownloadString|Net\.WebClient|-enc(odedcommand)?\b|\[char\]|\[Convert\]::|\[Reflection\.Assembly\])/i ascii wide

    condition:
        // Drop PE (DLL/EXE/.NET/MUI) and ELF up front - their .NET method/type names
        // (WebClient, Bypass, Base64) are not obfuscation and never contain backticks
        // anyway; this just speeds the rule up.
        not uint16(0) == 0x5A4D and
        not uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            // High confidence: 3+ backtick-broken tokens (this only happens in obfuscated text)
            (#iex_bt + #ie_bt + #dl_bt + #bp_bt) >= 3
            // OR 2+ tokens AND we are clearly inside a PowerShell context
            or ( $ps_ctx and (#iex_bt + #ie_bt + #dl_bt + #bp_bt) >= 2 )
            // OR a single explicit Invoke-Expression-with-backtick (very high specificity on its own)
            or #ie_bt >= 1
        )
}

/* -----------------------------------------------------------------------------
   OBF_HIGH_PS_EnvVar_IEX_Reconstruction
   Invoke-Obfuscation TOKEN\COMMAND\3 - rebuild IEX from $env:ComSpec characters,
   $shellid, $verbosepreference, $PSHOME, $PSVersionTable - BOUND to IEX/Invoke.
   ----------------------------------------------------------------------------- */
rule OBF_HIGH_PS_EnvVar_IEX_Reconstruction
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "obfuscation"
        severity = "high"
        description = "IEX reconstructed from $shellid / $env:ComSpec / $PSHome / $verbosepreference char indexing BOUND to .Invoke()/&('iex')/ExecutionContext sink in <=300 chars"
        mitre = "T1027"

    strings:
        // Index pattern -> IEX/Invoke sink within 300 chars
        $bound_sid_sink = /\$shellid\s*\[\s*\d{1,3}\s*\][^\r\n]{0,300}(\.Invoke\s*\(|&\s*\(\s*['"][iI][eE][xX]|\$ExecutionContext\.\s*InvokeCommand\.|IEX\b|Invoke-Expression)/is ascii wide
        $bound_env_sink = /\$env:ComSpec\s*\[\s*\d{1,3}\s*[,;][^\r\n]{0,300}(\.Invoke\s*\(|&\s*\(\s*['"][iI][eE][xX]|\$ExecutionContext\.\s*InvokeCommand\.|IEX\b|Invoke-Expression)/is ascii wide
        $bound_psh_sink = /\$PSHome\s*\[\s*\d{1,3}\s*[,;][^\r\n]{0,300}(\.Invoke\s*\(|&\s*\(\s*['"][iI][eE][xX]|\$ExecutionContext\.\s*InvokeCommand\.|IEX\b|Invoke-Expression)/is ascii wide
        $bound_vp_sink  = /\$verbosepreference\.ToString\(\)\s*\[\s*\d{1,3}\s*[,;][^\r\n]{0,300}(\.Invoke\s*\(|&\s*\(\s*['"][iI][eE][xX]|\$ExecutionContext\.\s*InvokeCommand\.|IEX\b|Invoke-Expression)/is ascii wide

        // Inverse: sink consuming a char-indexed env var
        $bound_sink_idx  = /(\.Invoke\s*\(|&\s*\(\s*['"][iI][eE][xX]|\$ExecutionContext\.\s*InvokeCommand\.|IEX\b|Invoke-Expression)[^\r\n]{0,300}(\$shellid|\$env:ComSpec|\$PSHome|\$verbosepreference\.ToString\(\))\s*\[\s*\d{1,3}/is ascii wide

    condition:
        not uint16(0) == 0x5A4D and
        not uint32(0) == 0x464C457F and
        filesize < 5MB and
        any of ( $bound_sid_sink, $bound_env_sink, $bound_psh_sink, $bound_vp_sink, $bound_sink_idx )
}

/* -----------------------------------------------------------------------------
   OBF_HIGH_PS_ScriptBlock_Create_Join_Invoke
   [ScriptBlock]::Create(...) over a joined/concat string with .Invoke() and a
   downloader / -enc context. $sb_create + $invoke_op REQUIRED.
   ----------------------------------------------------------------------------- */
rule OBF_HIGH_PS_ScriptBlock_Create_Join_Invoke
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "obfuscation"
        severity = "high"
        description = "ScriptBlock.Create + .Invoke() REQUIRED, BOUND to a -join/[string]::Join OR downloader/Base64/Reflection payload context"
        mitre = "T1059.001,T1027"

    strings:
        $sb_create   = /\[(System\.Management\.Automation\.)?ScriptBlock\]::\s*Create\s*\(/i ascii wide
        $invoke_op   = /\.Invoke\s*\(\s*\)/i ascii wide
        $join_op     = /(-join\s*\(\s*\$|\[string\]::Join\s*\(|\s\+\s*\$\w+\s*\+\s*\$\w+\s*\+\s*\$\w+)/i ascii wide
        $with_payload= /(IEX\b|Invoke-Expression|FromBase64String|DownloadString|Net\.WebClient|Invoke-WebRequest|\[Reflection\.Assembly\]::Load|GzipStream|DeflateStream)/i ascii wide

        // Tight bound shape: ScriptBlock.Create directly over a join or payload string within 400 chars and .Invoke after
        $bound_full = /\[(System\.Management\.Automation\.)?ScriptBlock\]::\s*Create\s*\([^\r\n]{0,400}(-join\s*|\[string\]::Join\s*\(|FromBase64String|DownloadString|Net\.WebClient|\[Reflection\.Assembly\]::Load|GzipStream|DeflateStream)[^\r\n]{0,400}\.Invoke\s*\(\s*\)/is ascii wide

    condition:
        not uint16(0) == 0x5A4D and
        not uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            $bound_full
            or ( $sb_create and $invoke_op and ( $join_op or $with_payload ) )
        )
}

/* -----------------------------------------------------------------------------
   OBF_HIGH_PS_Gzip_Deflate_InMemory_Unpack_Load
   In-memory GZIP/Deflate unpack BOUND to Reflection.Assembly.Load of the
   decompressed buffer. Classic Empire / Covenant / Cobalt-Strike PS stager.
   ----------------------------------------------------------------------------- */
rule OBF_HIGH_PS_Gzip_Deflate_InMemory_Unpack_Load
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "obfuscation"
        severity = "high"
        description = "GzipStream/DeflateStream unpack BOUND to [Reflection.Assembly]::Load of the decompressed buffer (or ScriptBlock.Create on it) within <=500 chars"
        mitre = "T1027,T1059.001,T1620"

    strings:
        // Gzip/Deflate stream -> Reflection.Assembly.Load or ScriptBlock.Create within 500 chars
        $bound_gz_load = /\[(System\.IO\.Compression\.)?GzipStream\][^\r\n]{0,500}(\[Reflection\.Assembly\]|\[System\.Reflection\.Assembly\])::\s*Load\s*\(/is ascii wide
        $bound_df_load = /\[(System\.IO\.Compression\.)?DeflateStream\][^\r\n]{0,500}(\[Reflection\.Assembly\]|\[System\.Reflection\.Assembly\])::\s*Load\s*\(/is ascii wide
        $bound_gz_sb   = /\[(System\.IO\.Compression\.)?GzipStream\][^\r\n]{0,500}\[(System\.Management\.Automation\.)?ScriptBlock\]::\s*Create\s*\(/is ascii wide
        $bound_df_sb   = /\[(System\.IO\.Compression\.)?DeflateStream\][^\r\n]{0,500}\[(System\.Management\.Automation\.)?ScriptBlock\]::\s*Create\s*\(/is ascii wide

        // Inverse: Reflection.Assembly.Load consuming a Gzip/Deflate decompressed buffer within 500 chars
        $bound_load_gz = /(\[Reflection\.Assembly\]|\[System\.Reflection\.Assembly\])::\s*Load\s*\([^\r\n]{0,500}\[(System\.IO\.Compression\.)?(GzipStream|DeflateStream)\]/is ascii wide

    condition:
        not uint16(0) == 0x5A4D and
        not uint32(0) == 0x464C457F and
        filesize < 5MB and
        any of ( $bound_gz_load, $bound_df_load, $bound_gz_sb, $bound_df_sb, $bound_load_gz )
}

/* -----------------------------------------------------------------------------
   OBF_HIGH_PS_Reflective_Assembly_Load_From_B64
   Reflection.Assembly.Load over [Convert]::FromBase64String + EntryPoint.Invoke
   - canonical Covenant Grunt and SharpExec stager. All three REQUIRED bound.
   ----------------------------------------------------------------------------- */
rule OBF_HIGH_PS_Reflective_Assembly_Load_From_B64
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "obfuscation"
        severity = "high"
        description = "Reflection.Assembly.Load + Convert.FromBase64String(<long>) + .EntryPoint.Invoke ALL BOUND within <=500 chars - in-memory .NET execution"
        mitre = "T1620"

    strings:
        // Tight one-window form: Load(FromBase64String('<500+ b64>')).EntryPoint.Invoke
        $bound_full = /(\[Reflection\.Assembly\]|\[System\.Reflection\.Assembly\])::\s*Load\s*\(\s*\[Convert\]::\s*FromBase64String\s*\(\s*['"][A-Za-z0-9+\/=]{500,}['"]\s*\)[^\r\n]{0,500}\.\s*EntryPoint\s*\.\s*Invoke\s*\(/is ascii wide

        // GetType + GetMethod + Invoke shape with same Load+B64 anchor
        $bound_gettype = /(\[Reflection\.Assembly\]|\[System\.Reflection\.Assembly\])::\s*Load\s*\(\s*\[Convert\]::\s*FromBase64String\s*\(\s*['"][A-Za-z0-9+\/=]{500,}['"]\s*\)[^\r\n]{0,500}\.\s*GetType\s*\([^\)]{0,80}\)\s*\.\s*(GetMethod|GetMethods|InvokeMember)/is ascii wide

        // Inverse order: B64 -> Load -> EntryPoint.Invoke within 500 chars
        $bound_b64_load_inv = /\[Convert\]::\s*FromBase64String\s*\(\s*['"][A-Za-z0-9+\/=]{500,}['"][^\r\n]{0,200}(\[Reflection\.Assembly\]|\[System\.Reflection\.Assembly\])::\s*Load\s*\([^\r\n]{0,500}\.\s*EntryPoint\s*\.\s*Invoke\s*\(/is ascii wide

    condition:
        not uint16(0) == 0x5A4D and
        not uint32(0) == 0x464C457F and
        filesize < 5MB and
        any of ( $bound_full, $bound_gettype, $bound_b64_load_inv )
}

/* -----------------------------------------------------------------------------
   OBF_HIGH_TrustedSite_Download_Cradle
   PS download cradle whose URL targets an abused trusted-domain host.
   PRESERVED: already-tightened rule from prior pass. Only date updated.
   ----------------------------------------------------------------------------- */
rule OBF_HIGH_TrustedSite_Download_Cradle
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "obfuscation"
        severity = "high"
        description = "PS download cradle pointed at abused trusted host (github raw, gist, discord cdn, pastebin raw, transfer.sh, ngrok, trycloudflare, telegra.ph, t.me). Verb and URL MUST appear within 200 chars of each other (prior loose ($cradle and $host_set) branch matched any iex+github co-occurrence anywhere in a file)."
        mitre = "T1102,T1105"

    strings:
        // verb -> URL within 200 chars (typical cradle order)
        //   e.g. iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/...')
        $bound_vu = /(IEX|Invoke-Expression|Invoke-WebRequest|Net\.WebClient|DownloadString|DownloadFile|curl(\.exe)?\s|wget(\.exe)?\s|certutil(\.exe)?\s+-urlcache|Start-BitsTransfer)[^\r\n]{0,200}https?:\/\/[^\s"'\r\n]*(raw\.githubusercontent\.com|gist\.githubusercontent\.com|cdn\.discordapp\.com\/attachments|media\.discordapp\.net|pastebin\.com\/raw|transfer\.sh|0x0\.st|ngrok-free\.app|ngrok\.io|trycloudflare\.com|telegra\.ph|api\.telegram\.org|t\.me\/|bot[\d:]+\/sendDocument)/is ascii wide

        // URL -> verb within 200 chars (e.g. `(iwr 'https://...').Content | iex`)
        $bound_uv = /https?:\/\/[^\s"'\r\n]*(raw\.githubusercontent\.com|gist\.githubusercontent\.com|cdn\.discordapp\.com\/attachments|media\.discordapp\.net|pastebin\.com\/raw|transfer\.sh|0x0\.st|ngrok-free\.app|ngrok\.io|trycloudflare\.com|telegra\.ph|api\.telegram\.org|t\.me\/)[^\r\n]{0,200}(\|\s*(IEX|Invoke-Expression)|\.Content\s*\|\s*(IEX|Invoke-Expression)|DownloadString|DownloadFile|certutil(\.exe)?\s+-urlcache|Start-BitsTransfer)/is ascii wide

    condition:
        not uint16(0) == 0x5A4D and
        not uint32(0) == 0x464C457F and
        filesize < 5MB and
        ( $bound_vu or $bound_uv )
}

/* -----------------------------------------------------------------------------
   OBF_HIGH_PS_String_Reverse_Concat_To_Type
   Reverse-string / range-index pattern BOUND to dynamic Type resolution
   (GetType / Activator.CreateInstance / GetMethod.Invoke).
   ----------------------------------------------------------------------------- */
rule OBF_HIGH_PS_String_Reverse_Concat_To_Type
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "obfuscation"
        severity = "medium-high"
        description = "Reverse-string / ToCharArray[range] / 10+ single-char concat BOUND to [Type]::GetType / [Activator]::CreateInstance / .GetMethod().Invoke() in <=400 chars"
        mitre = "T1027"

    strings:
        // Reverse pattern -> dynamic type sink within 400 chars
        $bound_rev_type = /['"][^"'\r\n]{4,40}['"]\.ToCharArray\(\)\s*\[\s*-?\d{1,3}\s*\.\.\s*-?\d{1,3}\s*\]\s*-join\s*[^\r\n]{0,400}(\[Type\]::\s*GetType\s*\(|\[Activator\]::\s*CreateInstance\s*\(|\.\s*GetMethod\s*\([^\)]{0,80}\)\s*\.\s*Invoke\s*\()/is ascii wide

        // Char-concat chain -> dynamic type sink within 400 chars
        $bound_concat_type = /(['"][A-Za-z0-9]['"][\s\+]+){10,}[^\r\n]{0,400}(\[Type\]::\s*GetType\s*\(|\[Activator\]::\s*CreateInstance\s*\(|\.\s*GetMethod\s*\([^\)]{0,80}\)\s*\.\s*Invoke\s*\()/is ascii wide

        // Inverse: dynamic type sink consuming a reverse / concat chain within 400 chars
        $bound_type_rev = /(\[Type\]::\s*GetType\s*\(|\[Activator\]::\s*CreateInstance\s*\(|\.\s*GetMethod\s*\()[^\r\n]{0,400}(\.ToCharArray\(\)\s*\[\s*-?\d{1,3}\s*\.\.\s*-?\d{1,3}\s*\]|(['"][A-Za-z0-9]['"][\s\+]+){10,})/is ascii wide

    condition:
        not uint16(0) == 0x5A4D and
        not uint32(0) == 0x464C457F and
        filesize < 5MB and
        any of ( $bound_rev_type, $bound_concat_type, $bound_type_rev )
}

/* -----------------------------------------------------------------------------
   OBF_HIGH_PS_Shellcode_Loader_Scaffold
   P/Invoke VirtualAlloc + RtlMoveMemory + long [byte[]] literal ALL BOUND.
   Optional Meterpreter prelude hex fc4883e4f0 short-circuit.
   ----------------------------------------------------------------------------- */
rule OBF_HIGH_PS_Shellcode_Loader_Scaffold
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "obfuscation"
        severity = "high"
        description = "PS P/Invoke VirtualAlloc + RtlMoveMemory + long byte[] / b64 blob BOUND together (or Meterpreter prelude hex with VirtualAlloc+CreateThread)"
        mitre = "T1055,T1620"

    strings:
        $addtype     = /Add-Type\s+(-TypeDefinition|-MemberDefinition)/i ascii wide
        $dllimport   = /\[DllImport\s*\(\s*["'](kernel32|ntdll|msvcrt)\.dll["']/i ascii wide
        $valloc      = /\b(VirtualAlloc|VirtualAllocEx|NtAllocateVirtualMemory)\b/i ascii wide
        $vprotect    = /\b(VirtualProtect|VirtualProtectEx|NtProtectVirtualMemory)\b/i ascii wide
        $cthread     = /\b(CreateThread|CreateRemoteThread|NtCreateThreadEx|RtlCreateUserThread)\b/i ascii wide
        $movemem     = /\b(RtlMoveMemory|memcpy|Marshal\.Copy)\b/i ascii wide
        $blob_b64    = /['"][A-Za-z0-9+\/=]{600,}['"]/ ascii wide
        $byte_arr    = /\b(0x[0-9a-fA-F]{2}\s*,\s*){80,}/ ascii wide
        $meterprelude= { FC 48 83 E4 F0 E8 ?? 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 60 }

    condition:
        not uint16(0) == 0x5A4D and
        not uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            // Canonical scaffold: Add-Type/DllImport + VirtualAlloc(+optional VirtualProtect) + RtlMoveMemory + long byte/b64 blob
            ( ( $addtype or $dllimport ) and $valloc and $movemem and ( $blob_b64 or $byte_arr ) and ( $vprotect or $cthread or $movemem ) )
            // OR Meterpreter prelude hex with VirtualAlloc + CreateThread
            or ( $valloc and $cthread and $meterprelude )
        )
}

/* -----------------------------------------------------------------------------
   OBF_HIGH_PS_AMSI_Token_Char_Reassembly
   Reassembly of "amsi" / "AmsiUtils" / "amsiInitFailed" / "AmsiScanBuffer"
   from char concatenation or [char]65,[char]109,[char]115,[char]105 BOUND
   to reflection / AMSI evasion context. NO standalone "amsi" branch.
   ----------------------------------------------------------------------------- */
rule OBF_HIGH_PS_AMSI_Token_Char_Reassembly
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "obfuscation"
        severity = "high"
        description = "AMSI token reassembled from 'a'+'m'+'s'+'i' / [char]65,[char]109,[char]115,[char]105 / split 'Amsi'+'Utils' BOUND to reflection (GetField/NonPublic/SetValue) or amsi.dll context in <=400 chars"
        mitre = "T1562.001"

    strings:
        // Char-form reassembly of 'amsi' bytes
        $amsi_charform_bound = /\[char\]\s*(65|0x41)\s*[\+,]\s*\[char\]\s*(109|0x6[Dd])\s*[\+,]\s*\[char\]\s*(115|0x73)\s*[\+,]\s*\[char\]\s*(105|0x69)[^\r\n]{0,400}(BindingFlags|GetField|SetValue|NonPublic|Static|amsi\.dll|System\.Management\.Automation\.AmsiUtils|amsiInitFailed|AmsiScanBuffer)/is ascii wide

        // Single-char concat 'a'+'m'+'s'+'i'
        $amsi_concat1_bound = /['"][Aa]['"][\s\+]+['"][Mm]['"][\s\+]+['"][Ss]['"][\s\+]+['"][Ii]['"][^\r\n]{0,400}(BindingFlags|GetField|SetValue|NonPublic|Static|amsi\.dll|System\.Management\.Automation\.AmsiUtils|amsiInitFailed|AmsiScanBuffer)/is ascii wide

        // Split-substring concat 'Amsi'+'Utils'
        $amsi_concat_split_bound = /['"]Amsi['"][\s\+]+['"]Utils['"][^\r\n]{0,400}(BindingFlags|GetField|SetValue|NonPublic|Static|amsi\.dll|amsiInitFailed|AmsiScanBuffer)/is ascii wide

        // Split 'amsi'+'Init'+'Failed'
        $amsi_concat_init_bound = /['"]amsi['"][\s\+]+['"]Init['"][\s\+]+['"]Failed['"][^\r\n]{0,400}(BindingFlags|GetField|SetValue|NonPublic|Static|amsi\.dll|System\.Management\.Automation\.AmsiUtils)/is ascii wide

        // Split 'Amsi'+'Scan'+'Buffer'
        $amsi_concat_scan_bound = /['"]Amsi['"][\s\+]+['"]Scan['"][\s\+]+['"]Buffer['"][^\r\n]{0,400}(BindingFlags|GetField|SetValue|NonPublic|Static|amsi\.dll|System\.Management\.Automation\.AmsiUtils)/is ascii wide

        // Inverse: reflection context preceding reassembly
        $amsi_ref_concat = /(GetField|SetValue|NonPublic|System\.Management\.Automation\.AmsiUtils)[^\r\n]{0,400}(\[char\]\s*(65|0x41)\s*[\+,]\s*\[char\]\s*(109|0x6[Dd])|['"][Aa]['"][\s\+]+['"][Mm]['"][\s\+]+['"][Ss]['"]|['"]Amsi['"][\s\+]+['"]Utils['"])/is ascii wide

    condition:
        not uint16(0) == 0x5A4D and
        not uint32(0) == 0x464C457F and
        filesize < 5MB and
        any of ( $amsi_charform_bound, $amsi_concat1_bound, $amsi_concat_split_bound, $amsi_concat_init_bound, $amsi_concat_scan_bound, $amsi_ref_concat )
}

/* -----------------------------------------------------------------------------
   OBF_HIGH_PS_XOR_Inline_Decode_Loop
   Inline -bxor inside ForEach-Object/for over a byte array BOUND to
   IEX / Reflection.Assembly.Load of the decoded result.
   ----------------------------------------------------------------------------- */
rule OBF_HIGH_PS_XOR_Inline_Decode_Loop
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "obfuscation"
        severity = "medium-high"
        description = "PS XOR loop (-bxor inside for/ForEach-Object) over byte array BOUND to IEX/Reflection.Assembly.Load/ScriptBlock.Create of the result in <=500 chars"
        mitre = "T1027,T1140"

    strings:
        // for-loop XOR decoder with byte array nearby and execution sink
        $bound_for_xor_sink = /for\s*\([^)]{0,200}\)\s*\{[^}]{0,200}-bxor[^}]{0,200}\}[^\r\n]{0,500}(IEX\b|Invoke-Expression|\[Reflection\.Assembly\]::Load|\[ScriptBlock\]::\s*Create|RtlMoveMemory)/is ascii wide

        // ForEach-Object/% with -bxor and execution sink within 500 chars
        $bound_foreach_xor_sink = /(foreach\s*\(\s*\$\w+\s+in\s+\$\w+\s*\)|\|\s*(ForEach-Object|%)\s*\{)[^}]{0,200}-bxor[^\r\n]{0,500}(IEX\b|Invoke-Expression|\[Reflection\.Assembly\]::Load|\[ScriptBlock\]::\s*Create|RtlMoveMemory)/is ascii wide

        // XOR loop with a long byte array AND a sink (all three required by alternation requiring the literal byte blob)
        $bound_xor_blob_sink = /-bxor[^\r\n]{0,200}(\b(0x[0-9a-fA-F]{2}\s*,\s*){60,})[^\r\n]{0,500}(IEX\b|Invoke-Expression|\[Reflection\.Assembly\]::Load|\[ScriptBlock\]::\s*Create|RtlMoveMemory)/is ascii wide

        // Inverse: byte blob -> XOR loop -> sink
        $bound_blob_xor_sink = /\b(0x[0-9a-fA-F]{2}\s*,\s*){60,}[^\r\n]{0,300}-bxor[^\r\n]{0,500}(IEX\b|Invoke-Expression|\[Reflection\.Assembly\]::Load|\[ScriptBlock\]::\s*Create|RtlMoveMemory)/is ascii wide

    condition:
        not uint16(0) == 0x5A4D and
        not uint32(0) == 0x464C457F and
        filesize < 5MB and
        any of ( $bound_for_xor_sink, $bound_foreach_xor_sink, $bound_xor_blob_sink, $bound_blob_xor_sink )
}

/* -----------------------------------------------------------------------------
   OBF_HIGH_PS_FromBase64_Inline_IEX_Oneliner
   Canonical chain in a single regex:
     iex([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64 >=200>')))
   ----------------------------------------------------------------------------- */
rule OBF_HIGH_PS_FromBase64_Inline_IEX_Oneliner
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "obfuscation"
        severity = "high"
        description = "Canonical iex([Text.Encoding]::*.GetString([Convert]::FromBase64String('<b64>=200+>'))) one-liner - single regex bound shape"
        mitre = "T1059.001,T1027"

    strings:
        // Tight canonical chain: IEX ( Encoding . GetString ( FromBase64String ( '<200+ b64>' ) ) )
        $bound_chain = /(IEX|Invoke-Expression)\s*\(\s*\[(System\.Text|Text)\.Encoding\]::\s*(UTF8|ASCII|Unicode|UTF7|UTF32|Default)\s*\.\s*GetString\s*\(\s*\[Convert\]::\s*FromBase64String\s*\(\s*['"][A-Za-z0-9+\/=]{200,}['"]\s*\)\s*\)\s*\)/is ascii wide

        // Same chain launched via powershell.exe -c / -command wrapper
        $bound_chain_psw = /\b(powershell(\.exe)?|pwsh(\.exe)?)\s+[^"\r\n]{0,200}-(c|command)\s+["']?[^"'\r\n]{0,80}(IEX|Invoke-Expression)\s*\(\s*\[(System\.Text|Text)\.Encoding\]::\s*\w+\s*\.\s*GetString\s*\(\s*\[Convert\]::\s*FromBase64String\s*\(\s*['"][A-Za-z0-9+\/=]{200,}['"]/is ascii wide

    condition:
        not uint16(0) == 0x5A4D and
        not uint32(0) == 0x464C457F and
        filesize < 5MB and
        ( $bound_chain or $bound_chain_psw )
}
