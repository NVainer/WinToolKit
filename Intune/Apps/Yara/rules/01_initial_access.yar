/* =============================================================================
   01_initial_access.yar
   -----------------------------------------------------------------------------
   Author : Nati
   Date   : 2026-10-14 (v3)
   Scope  : What actually lands on a regular user's Windows 11 laptop through
            mail, browser and chat: shortcut files, HTA/VBS/JS droppers,
            ClickFix lure pages, HTML/SVG smuggling, base64-wrapped executables,
            legacy macro documents, Equation Editor RTFs, OneNote containers.

   Dropped from v2 on purpose: PDF JavaScript (noisy, low value), XLL add-ins,
   ISO/IMG container heuristics (fired on every Windows ISO), CHM, MSI custom
   actions (every vendor MSI has one), SCT scriptlets (folded into LOLBAS).

   Every rule is anchored on the file format (magic bytes or a format marker)
   AND an execution primitive AND a payload shape.
   ============================================================================= */

/* -----------------------------------------------------------------------------
   IA_HIGH_LNK_ScriptHost_Payload
   Shortcut that launches a script host with a remote/encoded/hidden payload.
   LNK stores target path (ASCII+UTF-16) and arguments (UTF-16) as separate
   length-prefixed strings, so host and payload are matched independently.
   ----------------------------------------------------------------------------- */
rule IA_HIGH_LNK_ScriptHost_Payload
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "initial_access"
        severity    = "high"
        description = "LNK whose target/arguments launch a script host with a URL, encoded command, IEX/download verb, hidden window, script in user-writable path, or javascript:/vbscript: protocol"
        mitre       = "T1204.002,T1059.001,T1218"
        fp_notes    = "Start Menu shortcuts to powershell/cmd have no payload markers and do not fire. A hit in Recent/Downloads/Outlook attachments is phishing until proven otherwise."

    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

        // Script hosts (anywhere in the shortcut: LinkInfo, relative path or arguments)
        $h_ps      = "powershell" ascii wide nocase
        $h_pwsh    = "pwsh.exe"   ascii wide nocase
        $h_cmd     = "cmd.exe"    ascii wide nocase
        $h_mshta   = "mshta"      ascii wide nocase
        $h_wscript = "wscript"    ascii wide nocase
        $h_cscript = "cscript"    ascii wide nocase
        $h_rundll  = "rundll32"   ascii wide nocase
        $h_regsvr  = "regsvr32"   ascii wide nocase
        $h_msiexec = "msiexec"    ascii wide nocase
        $h_certutil= "certutil"   ascii wide nocase
        $h_bits    = "bitsadmin"  ascii wide nocase
        $h_conhost = "conhost"    ascii wide nocase
        $h_forfiles= "forfiles"   ascii wide nocase
        $h_curl    = "curl.exe"   ascii wide nocase

        // Payload shapes
        $p_url     = /https?:\/\/[^\s\x00"'<>]{6,200}/i ascii wide
        $p_enc     = /\s-e(c|n|nc|ncodedcommand)?\s+["']?[A-Za-z0-9+\/]{40,}/i ascii wide
        $p_verb    = /(\biex\b|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|FromBase64String|Invoke-WebRequest|\birm\s|\biwr\s|Start-BitsTransfer|-urlcache|\/transfer\s|Invoke-RestMethod)/i ascii wide
        $p_hidden  = /-w(indowstyle)?\s+h(idden)?\b/i ascii wide
        $p_proto   = /(javascript|vbscript)\s*:/i ascii wide
        $p_upath   = /(%(TEMP|TMP|APPDATA|LOCALAPPDATA|PUBLIC|USERPROFILE)%|\\Users\\[^\\\x00]{1,80}\\(AppData|Downloads|Desktop|Documents|Pictures)|\\ProgramData\\|\\Users\\Public\\|\\Windows\\Temp\\)[^\x00"']{0,200}\.(ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd|dll|scr|cpl)\b/i ascii wide
        $p_findstr = /findstr[^\x00]{0,200}\.(lnk|pdf|docx?|xlsx?|txt|jpg|png)\b[^\x00]{0,200}>/i ascii wide
        $p_sibling = /\s\.\\[^\x00"'\\]{1,80}\.(dll|bat|cmd|vbs|js|ps1|hta|exe)\b/i ascii wide

        // Vendor "Support"/"Marketplace" shortcuts open a URL through rundll32 (url.dll,
        // FileProtocolHandler and OEM variants) or "cmd /c start". A URL therefore only
        // counts next to a host that has no business opening web pages.
        $benign_urlhandler = /url\.dll\s*,\s*(FileProtocolHandler|OpenURL)/i ascii wide

    condition:
        $lnk_magic at 0
        and filesize < 20MB
        and 1 of ($h_*)
        and (
            1 of ($p_enc, $p_verb, $p_hidden, $p_proto, $p_upath, $p_findstr, $p_sibling)
            or ( $p_url and not $benign_urlhandler
                 and 1 of ($h_ps, $h_pwsh, $h_mshta, $h_wscript, $h_cscript, $h_regsvr, $h_msiexec, $h_certutil, $h_bits, $h_conhost, $h_forfiles, $h_curl) )
        )
}

/* -----------------------------------------------------------------------------
   IA_HIGH_HTA_Dropper
   HTML Application that creates a shell object and runs a LOLBin / script host.
   ----------------------------------------------------------------------------- */
rule IA_HIGH_HTA_Dropper
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "initial_access"
        severity    = "high"
        description = "HTA / inline VBScript-JScript page creating WScript.Shell or Shell.Application and running powershell, cmd, mshta, rundll32, regsvr32, certutil, bitsadmin, msiexec or schtasks"
        mitre       = "T1218.005,T1566.001"

    strings:
        $hta   = /<\s*HTA:APPLICATION\b/i ascii wide
        $lang  = /<\s*script\s+(type|language)\s*=\s*["']?(text\/)?(vbscript|jscript|javascript)/i ascii wide

        $shell_then_run = /(WScript\.Shell|Shell\.Application)["']\s*\)[\s\S]{0,400}\.\s*(Run|Exec|ShellExecute)\s*\(?\s*["'][^"'\r\n]{0,300}(powershell|pwsh|cmd(\.exe)?\s+\/[ck]|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|msiexec|wscript|cscript|schtasks)/i ascii wide
        $run_then_shell = /\.\s*(Run|Exec|ShellExecute)\s*\(?\s*["'][^"'\r\n]{0,300}(powershell|pwsh|cmd(\.exe)?\s+\/[ck]|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec)[\s\S]{0,400}(WScript\.Shell|Shell\.Application)/i ascii wide

    condition:
        filesize < 2MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and ( $hta or $lang )
        and ( $shell_then_run or $run_then_shell )
}

/* -----------------------------------------------------------------------------
   IA_HIGH_Script_Dropper_XMLHTTP_ADODB
   Classic VBS/JS/WSF stage-1: download with XMLHTTP, write with ADODB.Stream,
   execute via shell object. All four parts must be present.
   ----------------------------------------------------------------------------- */
rule IA_HIGH_Script_Dropper_XMLHTTP_ADODB
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "initial_access"
        severity    = "high"
        description = "Script downloader: MSXML2/WinHttp request + ADODB.Stream + SaveToFile + shell execution or URL"
        mitre       = "T1059.005,T1059.007,T1105"

    strings:
        $xmlhttp = /(MSXML2\.(Server)?XMLHTTP|Microsoft\.XMLHTTP|WinHttp\.WinHttpRequest)/i ascii wide
        $adodb   = /ADODB\.Stream/i ascii wide
        $save    = /\.\s*SaveToFile\s*\(?/i ascii wide
        $run     = /(WScript\.Shell|Shell\.Application|\.\s*ShellExecute\s*\(|\.\s*Run\s*\(\s*["']|\.\s*Exec\s*\(\s*["'])/i ascii wide
        $url     = /https?:\/\/[^\s"'<>\r\n]{6,200}/i ascii wide

    condition:
        filesize < 2MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and $xmlhttp and $adodb and $save and ( $run or $url )
}

/* -----------------------------------------------------------------------------
   IA_HIGH_ClickFix_Lure
   Fake CAPTCHA / "fix it" pages: JS writes a shell command to the clipboard,
   the victim pastes it into Win+R. Also catches the pasted command itself
   (it carries a fake "I am not a robot - reCAPTCHA Verification ID" comment).
   ----------------------------------------------------------------------------- */
rule IA_HIGH_ClickFix_Lure
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "initial_access"
        severity    = "high"
        description = "ClickFix: clipboard write (navigator.clipboard / execCommand copy / clipboardData) with a powershell/mshta/cmd/msiexec/curl command carrying a URL, IEX, -enc or hidden window; or such a command tagged with the fake reCAPTCHA verification comment"
        mitre       = "T1204.004,T1059.001"
        reference   = "ESET H1-2025: ClickFix second most common attack vector; Splunk fake-CAPTCHA analysis"
        fp_notes    = "A cached security article about ClickFix can match the second branch. Check the source URL of the cache entry before escalating."

    strings:
        $clip1 = /navigator\.clipboard\.writeText\s*\(/i ascii wide
        $clip2 = /execCommand\s*\(\s*["']copy["']\s*\)/i ascii wide
        $clip3 = /clipboardData\.setData\s*\(/i ascii wide

        // The pasted command itself. A URL alone is not enough (API docs with a
        // copy button show "powershell Invoke-WebRequest https://..." too); it
        // needs the ClickFix execution shape.
        $cmd   = /((powershell|pwsh)(\.exe)?[^\r\n"'`]{0,300}(\biex\b|Invoke-Expression|\birm\s|\biwr\s[^\r\n]{0,120}\|\s*\biex\b|-e(c|n|nc|ncodedcommand)?\s+[A-Za-z0-9+\/]{20,}|-w(indowstyle)?\s+h(idden)?|FromBase64String|mshta(\.exe)?\s+["']?https?:)|mshta(\.exe)?\s+["']?https?:\/\/|msiexec(\.exe)?\s+[^\r\n"'`]{0,60}\/(i|q[bn]?|package)\s+["']?https?:\/\/|cmd(\.exe)?\s*\/[ck]\s+[^\r\n"'`]{0,120}(curl|certutil|bitsadmin|mshta|powershell|msiexec)[^\r\n"'`]{0,200}https?:\/\/|conhost(\.exe)?\s+--headless\s+[^\r\n"'`]{0,200}https?:\/\/)/i ascii wide

        $fake_verify = /(I am not a robot|reCAPTCHA Verification ID|Verification ID\s*:|Cloudflare\s+(Ray\s+ID|verification)|Human verification|Verify you are human)/i ascii wide

    condition:
        filesize < 3MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and $cmd
        and ( 1 of ($clip*) or $fake_verify )
}

/* -----------------------------------------------------------------------------
   IA_HIGH_Embedded_Base64_Executable
   A Windows executable base64-encoded inside a text/script/HTML file. No
   legitimate document, script or web page on a user's machine carries one.
   Covers HTML smuggling, PowerShell/VBS droppers with embedded binaries,
   and .NET loaders staged as text.
   ----------------------------------------------------------------------------- */
rule IA_HIGH_Embedded_Base64_Executable
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "initial_access,obfuscation"
        severity    = "high"
        description = "Base64-encoded PE (DOS stub text or MZ header) inside a non-PE, non-ZIP file"
        mitre       = "T1027.009,T1027.006,T1105"
        fp_notes    = "Rare legit cases: PowerShell modules that embed a DLL as base64, certutil -encode output of an installer. Both are admin activity, not regular-user activity."

    strings:
        $stub_msvc   = "This program cannot be run in DOS mode" base64 base64wide
        $stub_borland= "This program must be run under Win32" base64 base64wide
        $mz_header   = "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" base64 base64wide

    condition:
        filesize < 50MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and not uint32(0) == 0x04034B50
        and any of them
}

/* -----------------------------------------------------------------------------
   IA_MEDHIGH_HTML_Smuggling_Download
   HTML/JS that reconstructs an archive or script client-side and forces a
   download with a dangerous extension.
   ----------------------------------------------------------------------------- */
rule IA_MEDHIGH_HTML_Smuggling_Download
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "initial_access"
        severity    = "medium-high"
        description = "HTML smuggling: markup + download attribute naming a zip/iso/script/exe + Blob/createObjectURL/msSaveOrOpenBlob + decoder + embedded base64 payload (ZIP magic or >4000-char blob)"
        mitre       = "T1027.006,T1566.001"

    strings:
        $html    = /<(!DOCTYPE\s+)?html\b/i ascii wide
        $script  = /<script\b/i ascii wide
        $dl1     = /\.download\s*=\s*["'][^"'\r\n]{1,120}\.(zip|rar|7z|iso|img|vhdx?|exe|js|jse|vbs|vbe|wsf|hta|lnk|msi|scr|bat|cmd|ps1|cpl)["']/i ascii wide
        $dl2     = /\bdownload\s*=\s*["'][^"'\r\n]{1,120}\.(zip|rar|7z|iso|img|vhdx?|exe|js|jse|vbs|vbe|wsf|hta|lnk|msi|scr|bat|cmd|ps1|cpl)["']/i ascii wide
        $blob    = /(new\s+Blob\s*\(|createObjectURL\s*\(|msSaveOrOpenBlob\s*\(|msSaveBlob\s*\()/i ascii wide
        $decode  = /(atob\s*\(|Uint8Array\s*\(|charCodeAt\s*\(|String\.fromCharCode|unescape\s*\()/i ascii wide
        $zip_b64 = "PK\x03\x04" base64 base64wide
        $b64blob = /["'][A-Za-z0-9+\/]{4000,}={0,2}["']/ ascii wide

    condition:
        filesize < 30MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and ( $html or $script )
        and ( $dl1 or $dl2 )
        and $blob and $decode
        and ( $zip_b64 or $b64blob )
}

/* -----------------------------------------------------------------------------
   IA_MED_SVG_Script_Smuggling
   Standalone SVG document carrying script with decoding/obfuscation and a
   redirect / download / write action (2024-2026 SVG phishing attachments).
   Anchored on the file starting with <?xml or <svg so inline SVG icons inside
   cached HTML pages cannot fire.
   ----------------------------------------------------------------------------- */
rule IA_MED_SVG_Script_Smuggling
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "initial_access"
        severity    = "medium"
        description = "Standalone SVG with <script>, a decoder/eval primitive, and a redirect/open/write/download action"
        mitre       = "T1027.006,T1566.001"

    strings:
        $svg    = /<svg\b[^>]{0,500}>/i ascii wide
        $script = /<script\b/i ascii wide
        $obf    = /(atob\s*\(|String\.fromCharCode|unescape\s*\(|eval\s*\(|Function\s*\(|decodeURIComponent\s*\(\s*escape)/i ascii wide
        $act    = /(location\.(href|replace|assign)\s*[=\(]|window\.open\s*\(|document\.write\s*\(|createObjectURL|\.download\s*=|<foreignObject|<iframe|<embed)/i ascii wide

    condition:
        filesize < 5MB
        and ( uint32(0) == 0x6D783F3C or uint32(0) == 0x6776733C or ( uint32(0) == 0x3CBFBBEF and ( uint8(4) == 0x3F or uint8(4) == 0x73 ) ) )
        and $svg and $script and $obf and $act
}

/* -----------------------------------------------------------------------------
   IA_MED_Office_Macro_AutoExec_Payload
   Legacy OLE Office document with a VBA project, an auto-exec entry point and
   an execution/download primitive. OOXML (.docm/.xlsm) is ZIP-compressed and
   invisible to YARA; Defender/MOTW macro blocking covers that path.
   ----------------------------------------------------------------------------- */
rule IA_MED_Office_Macro_AutoExec_Payload
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "initial_access"
        severity    = "medium"
        description = "OLE Word/Excel/PowerPoint file with VBA project + AutoOpen/Document_Open/Workbook_Open + Shell/WScript.Shell/URLDownloadToFile/XMLHTTP/ADODB/LOLBin string"
        mitre       = "T1566.001,T1059.005"
        fp_notes    = "VBA source is MS-OVBA compressed; keywords usually survive as literals but detection is best-effort. Corporate templates with auto-macros that only touch document fields do not carry the execution primitives."

    strings:
        $ole    = { D0 CF 11 E0 A1 B1 1A E1 }
        $word   = "WordDocument"        wide
        $xls    = "Workbook"            wide
        $ppt    = "PowerPoint Document" wide
        $vba1   = "_VBA_PROJECT"        wide
        $vba2   = "VBA_PROJECT_CUR"     wide
        $auto   = /\b(AutoOpen|Auto_Open|AutoExec|AutoClose|Auto_Close|Document_Open|Document_Close|Workbook_Open|Workbook_Activate|Workbook_BeforeClose|Workbook_Deactivate)\b/ ascii wide
        $pay    = /(\bShell\s*\(|WScript\.Shell|Shell\.Application|URLDownloadToFile|XMLHTTP|WinHttpRequest|ADODB\.Stream|powershell|cmd(\.exe)?\s*\/c|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|CallByName)/i ascii wide

    condition:
        $ole at 0
        and filesize < 40MB
        and ( $word or $xls or $ppt )
        and ( $vba1 or $vba2 )
        and $auto and $pay
}

/* -----------------------------------------------------------------------------
   IA_MEDHIGH_RTF_Equation_Editor_Exploit
   RTF with an embedded Equation Editor object (CVE-2017-11882 / CVE-2018-0802
   family). Equation Editor was removed in 2018; any RTF still carrying one is
   either an exploit document or a very old document worth a look.
   ----------------------------------------------------------------------------- */
rule IA_MEDHIGH_RTF_Equation_Editor_Exploit
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "initial_access"
        severity    = "medium-high"
        description = "RTF with Equation Editor OLE object: CLSID 0002CE02-...-46 or hex 'Equation.3' in objdata, or \\objclass Equation.3 with \\objupdate/\\objdata"
        mitre       = "T1203,T1566.001"
        reference   = "CVE-2017-11882, CVE-2018-0802"

    strings:
        $objupdate   = "\\objupdate" ascii nocase
        $objdata     = "\\objdata"   ascii nocase
        $objclass_eq = /\\objclass\s*Equation\.(2|3)/i ascii
        $eq_clsid    = /02CE020000000000C000000000000046/i ascii
        $eq_name_hex = /4571756174696f6e2e33/i ascii

    condition:
        uint32(0) == 0x74725C7B
        and filesize < 20MB
        and ( $eq_clsid or $eq_name_hex or ( $objclass_eq and ( $objupdate or $objdata ) ) )
}

/* -----------------------------------------------------------------------------
   IA_MEDHIGH_OneNote_Embedded_Script
   OneNote section file with an embedded executable, shortcut or script.
   FileDataStoreObject header = GUID(16) + cbLength(8) + unused(4) + reserved(8),
   so the embedded file's first bytes sit 20 bytes after the GUID ends.
   ----------------------------------------------------------------------------- */
rule IA_MEDHIGH_OneNote_Embedded_Script
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "initial_access"
        severity    = "medium-high"
        description = "OneNote .one with FileDataStoreObject whose payload starts with a PE, LNK, HTA/HTML, VBS/JS or batch marker"
        mitre       = "T1566.001,T1204.002"

    strings:
        $one_magic  = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
        $fds_pe     = { BD E3 16 E7 26 65 45 11 A4 C4 8D 4D 0B 7A 9E AC [20] 4D 5A }
        $fds_lnk    = { BD E3 16 E7 26 65 45 11 A4 C4 8D 4D 0B 7A 9E AC [20] 4C 00 00 00 01 14 02 00 }
        $fds_script = /\xBD\xE3\x16\xE7\x26\x65\x45\x11\xA4\xC4\x8D\x4D\x0B\x7A\x9E\xAC[\s\S]{20}[\s\S]{0,64}(<script|<html|<hta|HTA:APPLICATION|WScript\.Shell|CreateObject\s*\(|ActiveXObject|@echo off|powershell|cmd(\.exe)?\s*\/c|On Error Resume Next)/i

    condition:
        $one_magic at 0
        and filesize < 100MB
        and ( $fds_pe or $fds_lnk or $fds_script )
}
