/*
================================================================================
 07_initial_access.yar
 Author: Nati
 Category: Initial Access Lures & Stagers (Windows 11)
 Severity: Medium-High to High
 Last updated: 2026-05-24

 Coverage:
   - HTA droppers (WScript.Shell + .Run bound to PS/cmd/mshta payload)
   - VBA AutoExec macros (OLE magic + VB_Name + AutoExec sub + payload bound)
   - LNK shortcuts (LNK magic + PS/cmd/mshta cmdline + URL/user-path bound)
   - OneNote (.one) with embedded FileDataStoreObject + script-ext token
   - SCT/WSC scriptlets bound to regsvr32 + scrobj.dll (Squiblydoo)
   - XLL Excel add-ins (PE + xlAutoOpen + shellcode/HTTP API imports)
   - ISO/IMG/VHD container drops (LNK structural elements + sibling payload)
   - CHM compiled help with embedded <script> + WSH/PS payload bound
   - MSI installer with CustomAction + JScript/VBScript payload bound
   - SVG smuggling (SVG + base64 blob + JS click-trigger bound)
   - PDF with /OpenAction + (/JS or /Launch) bound
   - JS/VBS droppers (XMLHTTP + ADODB.Stream + SaveToFile + Run bound)
   - ClickFix/pastejack (clipboard.writeText + lure + PS cradle bound)

 Design principle:
   Every rule requires an ATTACK SHAPE = format magic (where applicable)
   + dropper structural element + payload-execution bound in proximity.
   Standalone keyword OR branches are forbidden.
================================================================================
*/

import "pe"
import "math"

/* -----------------------------------------------------------------------------
   IA_HIGH_HTA_WScript_Shell_Payload
   HTA <script> with WScript.Shell ActiveX creation AND .Run("...powershell|
   cmd|mshta...") bound in proximity. T1218.005 + T1566.001.
   ----------------------------------------------------------------------------- */
rule IA_HIGH_HTA_WScript_Shell_Payload
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "initial_access"
        severity = "high"
        description = "HTA with WScript.Shell ActiveX creation bound to .Run(powershell|cmd|mshta) payload"
        mitre = "T1218.005,T1566.001"

    strings:
        // ActiveX WScript.Shell creation bound within 200 chars to .Run/.Exec carrying a PS/cmd/mshta payload
        $wsh_run_bound = /(CreateObject\s*\(\s*["']WScript\.Shell["']\s*\)|new\s+ActiveXObject\s*\(\s*["']WScript\.Shell["']\s*\))[\s\S]{0,200}\.\s*(Run|Exec)\s*\(\s*["'][^"'\r\n]{0,400}(powershell|pwsh|cmd(\.exe)?\s+\/c|mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript)/i ascii wide

        // Reverse order: .Run/.Exec call bound to WScript.Shell handle (typical assigned-var pattern)
        $run_wsh_bound = /\.\s*(Run|Exec)\s*\(\s*["'][^"'\r\n]{0,400}(powershell|pwsh|cmd(\.exe)?\s+\/c|mshta|rundll32|regsvr32)[\s\S]{0,200}(WScript\.Shell|Shell\.Application)/i ascii wide

        $hta_marker    = /<\s*HTA:APPLICATION\b/i ascii wide
        $script_lang   = /<\s*script\s+language\s*=\s*["'](VBScript|JScript|JavaScript)["']/i ascii wide

    condition:
        filesize < 1MB
        and ( $hta_marker or $script_lang )
        and ( $wsh_run_bound or $run_wsh_bound )
}

/* -----------------------------------------------------------------------------
   IA_HIGH_VBA_AutoExec_Shell_Download
   OLE magic at offset 0 AND Attribute VB_Name AND AutoExec sub AND a payload
   import (Shell/URLDownloadToFile/MSXML2.XMLHTTP/InternetOpen/WinHttpRequest)
   bound in proximity. T1059.005 + T1566.001.
   ----------------------------------------------------------------------------- */
rule IA_HIGH_VBA_AutoExec_Shell_Download
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "initial_access"
        severity = "high"
        description = "VBA project (OLE+VB_Name) with AutoExec sub bound to Shell/URLDownload/XMLHTTP/InternetOpen/WinHttp payload"
        mitre = "T1059.005,T1566.001"

    strings:
        $magic_ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $vb_name   = "Attribute VB_Name" ascii wide

        // AutoExec sub bound within 1500 chars to a payload primitive
        $auto_payload_bound = /Sub\s+(AutoOpen|AutoExec|Auto_Open|AutoClose|Document_Open|Document_Close|Workbook_Open|Workbook_Activate|Workbook_BeforeClose)\s*\([\s\S]{0,1500}(Shell\s*\(|URLDownloadToFile|MSXML2\.(XMLHTTP|ServerXMLHTTP)|InternetOpen|WinHttp\.WinHttpRequest|WinHttpRequest)/i ascii wide

        // Reverse order: payload primitive declared above an AutoExec sub
        $payload_auto_bound = /(Declare\s+(PtrSafe\s+)?Function\s+\w+[\s\S]{0,400}(URLDownloadToFile|InternetOpen|WinHttp))[\s\S]{0,3000}Sub\s+(AutoOpen|AutoExec|Auto_Open|Document_Open|Workbook_Open)\s*\(/i ascii wide

    condition:
        filesize < 30MB
        and $magic_ole at 0
        and $vb_name
        and ( $auto_payload_bound or $payload_auto_bound )
}

/* -----------------------------------------------------------------------------
   IA_HIGH_LNK_Embedded_PS_Cmd_Mshta
   LNK magic at offset 0 AND embedded powershell|cmd /c|mshta|wscript|cscript|
   rundll32 command-line bound to payload context (URL, encoded blob, user-
   writable path). T1204.002 + T1059.001.
   ----------------------------------------------------------------------------- */
rule IA_HIGH_LNK_Embedded_PS_Cmd_Mshta
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "initial_access"
        severity = "high"
        description = "LNK shortcut with PS/cmd/mshta/wscript/rundll32 cmdline bound to URL, -enc blob, or user-writable payload path"
        mitre = "T1204.002,T1059.001"

    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

        // PS/cmd/mshta/wscript/cscript/rundll32 bound to URL within 300 chars
        $tool_url_bound = /(powershell(\.exe)?|pwsh(\.exe)?|cmd(\.exe)?\s+\/c|mshta(\.exe)?|wscript(\.exe)?|cscript(\.exe)?|rundll32(\.exe)?)\s+[^\r\n]{0,300}https?:\/\/[^\s"'<>\r\n]{6,160}/i wide

        // PS/cmd bound to encoded payload (-enc / IEX / FromBase64String / DownloadString) within 300 chars
        $tool_enc_bound = /(powershell(\.exe)?|pwsh(\.exe)?|cmd(\.exe)?\s+\/c)\s+[^\r\n]{0,300}(-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{40,}|IEX|Invoke-Expression|DownloadString|FromBase64String|Net\.WebClient)/i wide

        // PS/cmd/mshta/wscript/rundll32 bound to user-writable path with script/exe suffix
        $tool_path_bound = /(powershell(\.exe)?|pwsh(\.exe)?|cmd(\.exe)?\s+\/c|mshta(\.exe)?|wscript(\.exe)?|cscript(\.exe)?|rundll32(\.exe)?)\s+[^\r\n]{0,200}[A-Za-z]:\\(Users|ProgramData|Windows\\Temp|Temp)\\[^\r\n"']{1,160}\.(ps1|vbs|hta|js|wsf|bat|cmd|exe|scr|dll)/i wide

        // mshta with javascript:/vbscript: protocol (always malicious in LNK)
        $mshta_proto = /mshta(\.exe)?\s+(javascript:|vbscript:)/i wide

        // rundll32 with javascript: protocol
        $rundll_js   = /rundll32(\.exe)?\s+javascript:/i wide

    condition:
        $lnk_magic at 0
        and filesize < 5MB
        and ( $tool_url_bound or $tool_enc_bound or $tool_path_bound or $mshta_proto or $rundll_js )
}

/* -----------------------------------------------------------------------------
   IA_HIGH_OneNote_Embedded_Executable_Script
   OneNote magic at offset 0 AND FileDataStoreObject GUID AND a script/exec
   file-suffix reference bound. T1204.002 + T1566.001.
   ----------------------------------------------------------------------------- */
rule IA_HIGH_OneNote_Embedded_Executable_Script
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "initial_access"
        severity = "high"
        description = "OneNote .one (magic + FileDataStoreObject GUID) with embedded script/exec file-suffix bound"
        mitre = "T1204.002,T1566.001"

    strings:
        $one_magic = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
        $fds_guid  = { BD E3 16 E7 26 65 45 11 A4 C4 8D 4D 0B 7A 9E AC }

        // FileDataStoreObject GUID bound within 8KB to a script/exec file-suffix reference
        $fds_ext_bound = /\xBD\xE3\x16\xE7\x26\x65\x45\x11\xA4\xC4\x8D\x4D\x0B\x7A\x9E\xAC[\s\S]{0,8192}\.(ps1|vbs|hta|bat|cmd|js|wsf|lnk|scr|exe|jse|msi)\b/is

        // FileDataStoreObject GUID bound within 8KB to MZ-PE signature (embedded EXE)
        $fds_mz_bound  = /\xBD\xE3\x16\xE7\x26\x65\x45\x11\xA4\xC4\x8D\x4D\x0B\x7A\x9E\xAC[\s\S]{0,8192}\x4D\x5A\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00/s

    condition:
        $one_magic at 0
        and filesize < 50MB
        and $fds_guid
        and ( $fds_ext_bound or $fds_mz_bound )
}

/* -----------------------------------------------------------------------------
   IA_HIGH_SCT_WSC_Scriptlet_With_Scrobj
   .sct/.wsc XML scriptlet reference AND regsvr32 + scrobj.dll invocation
   bound in proximity. T1218.010 Squiblydoo.
   ----------------------------------------------------------------------------- */
rule IA_HIGH_SCT_WSC_Scriptlet_With_Scrobj
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "initial_access"
        severity = "high"
        description = "SCT/WSC scriptlet reference bound to regsvr32 /i: + scrobj.dll (Squiblydoo)"
        mitre = "T1218.010"

    strings:
        // regsvr32 /s /n /u /i:<scriptlet> ... scrobj.dll bound together (any order, 0-400 chars between)
        $regsvr_sct_remote = /regsvr32(\.exe)?\s+(\/[snu]\s+){0,3}\/i\s*:\s*https?:\/\/[^\s"'\r\n]{6,200}[\s\S]{0,200}scrobj\.dll/i ascii wide
        $regsvr_sct_local  = /regsvr32(\.exe)?\s+(\/[snu]\s+){0,3}\/i\s*:\s*["']?[A-Za-z]:\\[^"'\r\n]{1,200}\.(sct|wsc)["']?[\s\S]{0,200}scrobj\.dll/i ascii wide
        $regsvr_scrobj_first = /regsvr32(\.exe)?\s+[^\r\n]{0,200}scrobj\.dll[\s\S]{0,200}\/i\s*:\s*(https?:\/\/|["']?[A-Za-z]:\\)[^\s"'\r\n]{6,200}\.(sct|wsc)/i ascii wide

        // Scriptlet content (registration + script + payload) bound — for the SCT body itself
        $sct_body_bound = /<registration\s+[^>]{0,200}progid\s*=\s*["'][^"'\r\n]{2,80}["'][\s\S]{0,2000}<script\s+language\s*=\s*["'](JScript|VBScript|JavaScript)["'][\s\S]{0,4000}(new\s+ActiveXObject|WScript\.Shell|MSXML2|ADODB\.Stream|powershell|Invoke-WebRequest)/i ascii wide

    condition:
        filesize < 1MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $regsvr_sct_remote or $regsvr_sct_local or $regsvr_scrobj_first or $sct_body_bound )
}

/* -----------------------------------------------------------------------------
   IA_HIGH_XLL_AddIn_Suspicious_Imports
   PE magic at offset 0 AND xlAutoOpen export AND suspicious shellcode/HTTP
   API imports bound via pe module. T1137.006.
   PE skip intentionally OFF: XLL targets PE files.
   ----------------------------------------------------------------------------- */
rule IA_HIGH_XLL_AddIn_Suspicious_Imports
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "initial_access"
        severity = "high"
        description = "PE XLL add-in (MZ magic + xlAutoOpen export) with VirtualAlloc/CreateThread/WinHttp/URLDownloadToFile/Nt* imports"
        mitre = "T1137.006"

    condition:
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and pe.is_pe
        and pe.characteristics & pe.DLL
        and pe.exports("xlAutoOpen")
        and (
            pe.imports("KERNEL32.dll", "VirtualAlloc")
            or pe.imports("KERNEL32.dll", "VirtualAllocEx")
            or pe.imports("KERNEL32.dll", "CreateThread")
            or pe.imports("KERNEL32.dll", "CreateRemoteThread")
            or pe.imports("WININET.dll", "InternetOpenA")
            or pe.imports("WININET.dll", "InternetOpenW")
            or pe.imports("WININET.dll", "InternetOpenUrlA")
            or pe.imports("WINHTTP.dll", "WinHttpOpen")
            or pe.imports("WINHTTP.dll", "WinHttpConnect")
            or pe.imports("URLMON.dll", "URLDownloadToFileA")
            or pe.imports("URLMON.dll", "URLDownloadToFileW")
            or pe.imports("ntdll.dll", "NtAllocateVirtualMemory")
            or pe.imports("ntdll.dll", "NtProtectVirtualMemory")
            or pe.imports("ntdll.dll", "NtCreateThreadEx")
            or pe.imports("ntdll.dll", "NtWriteVirtualMemory")
            or pe.imports("ntdll.dll", "NtReadVirtualMemory")
        )
}

/* -----------------------------------------------------------------------------
   IA_HIGH_Container_Drop_PS_Cmd_DLL_Pair
   ISO9660 magic OR VHD footer OR LNK magic + sibling .lnk reference + sibling
   .dll/.exe payload reference bound. 2-of-N component match.
   T1204.002 + T1574.002.
   ----------------------------------------------------------------------------- */
rule IA_HIGH_Container_Drop_PS_Cmd_DLL_Pair
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "initial_access"
        severity = "high"
        description = "ISO/IMG/VHD container or LNK with sibling .dll/.exe/script reference bound (drop pair)"
        mitre = "T1204.002,T1574.002"

    strings:
        // ISO9660 primary volume descriptor magic "CD001" at sector 16 (offset 0x8001)
        $iso_magic1 = { 01 43 44 30 30 31 01 00 }   // type 0x01 + CD001 + version
        $iso_magic2 = "CD001" ascii

        // VHD footer (last 512 bytes start with "conectix")
        $vhd_footer = "conectix" ascii

        // LNK magic
        $lnk_magic  = { 4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

        // Sibling DLL/EXE/script reference via relative path
        $sibling_payload = /\.\\\\?[^"'\r\n\x00]{1,80}\.(dll|exe|cmd|bat|ps1|vbs|js)/i wide

        // rundll32 calling a sibling DLL via relative path (LNK-in-ISO pattern)
        $rundll_sibling  = /rundll32(\.exe)?\s+\.\\\\?[^,\r\n\x00]{1,120}\.dll/i wide

        // cmd /c invoking sibling script/exec
        $cmd_sibling     = /cmd(\.exe)?\s+\/c\s+\.\\\\?[^,\r\n\x00]{1,120}\.(cmd|bat|exe|ps1|vbs)/i wide

        // LNK target name reference (the LNK names a sibling payload)
        $lnk_target_ref  = /[^\\\/\r\n\x00]{1,60}\.lnk\x00/i wide

    condition:
        filesize < 200MB
        and (
            // ISO container: ISO9660 magic + LNK structural reference + sibling payload reference
            ( ( $iso_magic1 or $iso_magic2 ) and ( $lnk_magic or $lnk_target_ref ) and ( $sibling_payload or $rundll_sibling or $cmd_sibling ) )
            // VHD container: footer + LNK + sibling payload
            or ( $vhd_footer and ( $lnk_magic or $lnk_target_ref ) and ( $sibling_payload or $rundll_sibling or $cmd_sibling ) )
            // Standalone LNK with bound rundll32-sibling or cmd-sibling pattern (2 components from LNK side)
            or ( $lnk_magic at 0 and ( $rundll_sibling or $cmd_sibling ) and $sibling_payload )
        )
}

/* -----------------------------------------------------------------------------
   IA_HIGH_CHM_Embedded_Script
   ITSF magic at offset 0 AND embedded <script> block with WSH/PS payload
   bound. T1218.001.
   ----------------------------------------------------------------------------- */
rule IA_HIGH_CHM_Embedded_Script
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "initial_access"
        severity = "medium-high"
        description = "CHM (ITSF magic) with embedded <script> bound to WScript.Shell.Run + powershell/cmd/mshta payload"
        mitre = "T1218.001"

    strings:
        $chm_magic = "ITSF" ascii

        // <script ...> ... WScript.Shell .Run ... payload  bound within 4KB
        $script_wsh_payload = /<script\s+[^>]{0,200}language\s*=\s*["'](JScript|VBScript|JavaScript)["'][\s\S]{0,4000}(CreateObject\s*\(\s*["']WScript\.Shell["']\s*\)|new\s+ActiveXObject\s*\(\s*["']WScript\.Shell["']\s*\))[\s\S]{0,400}\.\s*Run\s*\(\s*["'][^"'\r\n]{0,300}(powershell|pwsh|cmd(\.exe)?\s+\/c|mshta|rundll32|certutil|bitsadmin)/is

        // HTML Help shortcut command (<PARAM name="Item1" value=",cmd.exe,...">) bound to payload
        $hh_shortcut_payload = /<OBJECT\s+[^>]{0,200}classid\s*=\s*["']clsid:52A2AAAE-085D-4187-97EA-8C30DB990436["'][\s\S]{0,2000}<PARAM\s+name\s*=\s*["']Item1["']\s+value\s*=\s*["'][^"'\r\n]{0,400}(powershell|pwsh|cmd\.exe|mshta|wscript|cscript|rundll32|certutil|bitsadmin)/is

    condition:
        $chm_magic at 0
        and filesize < 50MB
        and ( $script_wsh_payload or $hh_shortcut_payload )
}

/* -----------------------------------------------------------------------------
   IA_HIGH_MSI_CustomAction_Script
   MSI OLE magic AND CustomAction table marker AND JScript/VBScript/
   `powershell -enc` payload body bound. T1218.007.
   ----------------------------------------------------------------------------- */
rule IA_HIGH_MSI_CustomAction_Script
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "initial_access"
        severity = "high"
        description = "MSI (OLE magic) with CustomAction marker bound to JScript/VBScript/powershell -enc payload body"
        mitre = "T1218.007"

    strings:
        $ole_magic    = { D0 CF 11 E0 A1 B1 1A E1 }

        // CustomAction table/column marker bound within 4KB to a payload body
        $ca_payload_bound = /CustomAction[\s\S]{0,4000}(WScript\.Shell|Shell\.Application|MSXML2\.(XMLHTTP|ServerXMLHTTP)|ADODB\.Stream|powershell(\.exe)?\s+(-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{40,}|-NoP|-NonI|-W\s+Hidden|IEX|Invoke-Expression|DownloadString|FromBase64String|Net\.WebClient)|cmd(\.exe)?\s+\/c\s+(powershell|mshta|certutil|bitsadmin))/i ascii wide

        // Reverse: payload body bound back to CustomAction marker
        $payload_ca_bound = /(powershell(\.exe)?\s+(-e(nc(odedcommand)?)?|IEX|Invoke-Expression|DownloadString|FromBase64String)|WScript\.Shell|MSXML2\.XMLHTTP|ADODB\.Stream)[\s\S]{0,4000}CustomAction/i ascii wide

    condition:
        filesize < 50MB
        and $ole_magic at 0
        and ( $ca_payload_bound or $payload_ca_bound )
}

/* -----------------------------------------------------------------------------
   IA_HIGH_SVG_Smuggling_Embedded_Base64
   SVG smuggling: <svg> element containing a <script> that decodes a base64
   blob OF AN EXECUTABLE PAYLOAD (PE/ZIP/gzip/JS — never PNG/JPEG/GIF) and
   triggers a download or eval. T1027.006 + T1566.001.

   Anti-FP design:
     - The base64 payload-class anchor (TVqQ/TVoA = PE MZ, UEsDB/UEsFB = ZIP,
       H4sIA = gzip, KGZ1bmN0aW9u/aWZyYW1l/PHNjcmlwd = JS source) explicitly
       EXCLUDES PNG (iVBOR...), JPEG (/9j/), and GIF (R0lGOD) base64 prefixes
       that legitimately appear in Office SolutionPackages SVG icons and in
       Outlook EBWebView Service Worker caches.
     - All three elements (<svg>, <script>, base64 payload + atob/click) must
       live inside the same SVG block - the regex anchors at <svg> and stays
       within a 64KB intra-element window (real smuggling samples are 5-50KB).
   ----------------------------------------------------------------------------- */
rule IA_HIGH_SVG_Smuggling_Embedded_Base64
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "initial_access"
        severity = "high"
        description = "SVG element containing <script> with base64 of executable payload (PE/ZIP/gzip/JS - NOT image) bound to atob/Blob/click trigger"
        mitre = "T1027.006,T1566.001"

    strings:
        // <svg> ... <script> ... base64 EXECUTABLE payload ... atob/Blob, all inside one ~64KB SVG block
        $svg_payload_atob = /<svg\s+[^>]{0,400}xmlns\s*=\s*["']http:\/\/www\.w3\.org\/2000\/svg["'][\s\S]{0,16384}<script[^>]{0,200}>[\s\S]{0,8192}['"`](TVqQ|TVoA|UEsDB|UEsFB|H4sIA|KGZ1bmN0aW9u|PHNjcmlwd|aWZyYW1l|PCFET0NUWVBF)[A-Za-z0-9+\/]{500,}={0,2}['"`][\s\S]{0,4096}(window\.atob\s*\(|atob\s*\(|new\s+Blob\s*\(|URL\.createObjectURL)/is

        // <svg> ... <script> ... atob ... .download="*.exe|zip|hta|..." or createElement('a')+.click()
        $svg_atob_download = /<svg\s+[^>]{0,400}xmlns\s*=\s*["']http:\/\/www\.w3\.org\/2000\/svg["'][\s\S]{0,16384}<script[^>]{0,200}>[\s\S]{0,8192}atob\s*\([\s\S]{0,4096}(\.download\s*=\s*["'][^"']{1,80}\.(exe|zip|hta|vbs|bat|cmd|ps1|msi|jar|iso|img|lnk|wsf|jse|vbe)|document\.createElement\s*\(\s*["']a["']\s*\)[\s\S]{0,2048}\.click\s*\()/is

        // <svg> ... <script> ... eval(atob(...)) classic smuggling
        $svg_eval_atob = /<svg\s+[^>]{0,400}xmlns\s*=\s*["']http:\/\/www\.w3\.org\/2000\/svg["'][\s\S]{0,16384}<script[^>]{0,200}>[\s\S]{0,8192}(eval|Function|setTimeout|setInterval)\s*\(\s*(window\.)?atob\s*\(/is

    condition:
        filesize < 5MB
        and ( $svg_payload_atob or $svg_atob_download or $svg_eval_atob )
}

/* -----------------------------------------------------------------------------
   IA_HIGH_PDF_With_OpenAction_JS_Launch
   PDF magic at offset 0 AND /OpenAction AND (/JS|/JavaScript OR /Launch /F)
   bound. T1204.002.
   ----------------------------------------------------------------------------- */
rule IA_HIGH_PDF_With_OpenAction_JS_Launch
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "initial_access"
        severity = "medium-high"
        description = "PDF (%PDF- magic) with /OpenAction bound to /JS|/JavaScript or /Launch /F payload"
        mitre = "T1204.002"

    strings:
        $pdf_magic = "%PDF-" ascii

        // /OpenAction or /AA bound within 4KB to /JS or /JavaScript
        $oa_js_bound     = /\/(OpenAction|AA)\b[\s\S]{0,4096}\/(JS|JavaScript)\b/s

        // /OpenAction or /AA bound within 4KB to /Launch /F (launch file)
        $oa_launch_bound = /\/(OpenAction|AA)\b[\s\S]{0,4096}\/Launch\b[\s\S]{0,512}\/F\s*[\(<]/s

        // /JavaScript bound to a high-risk script primitive within 4KB
        $js_payload_bound = /\/(JS|JavaScript)\b[\s\S]{0,4096}(app\.launchURL|this\.exportDataObject|util\.byteToChar|eval\s*\(|unescape\s*\(|String\.fromCharCode)/s

    condition:
        $pdf_magic at 0
        and filesize < 100MB
        and ( ( $oa_js_bound and $js_payload_bound ) or $oa_launch_bound )
}

/* -----------------------------------------------------------------------------
   IA_HIGH_JS_VBS_Dropper_Toplevel_Stager
   MSXML2.XMLHTTP AND ADODB.Stream AND SaveToFile AND (Run|WScript.Shell)
   bound in proximity. T1059.005 + T1059.007 + T1105.
   ----------------------------------------------------------------------------- */
rule IA_HIGH_JS_VBS_Dropper_Toplevel_Stager
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "initial_access"
        severity = "high"
        description = "JS/VBS dropper: MSXML2.XMLHTTP + ADODB.Stream + SaveToFile + Run/WScript.Shell bound in proximity"
        mitre = "T1059.005,T1059.007,T1105"

    strings:
        // Full dropper chain bound within ~8KB
        $dropper_chain_a = /(MSXML2\.(XMLHTTP|ServerXMLHTTP)|Microsoft\.XMLHTTP|WinHttp\.WinHttpRequest)[\s\S]{0,8000}ADODB\.Stream[\s\S]{0,8000}\.\s*SaveToFile\s*\([\s\S]{0,8000}(WScript\.Shell|\.\s*Run\s*\(\s*["'])/is

        // Reverse: Shell.Run handle declared first, then XMLHTTP+ADODB+SaveToFile
        $dropper_chain_b = /(WScript\.Shell|Shell\.Application)[\s\S]{0,8000}(MSXML2\.(XMLHTTP|ServerXMLHTTP)|Microsoft\.XMLHTTP|WinHttp\.WinHttpRequest)[\s\S]{0,8000}ADODB\.Stream[\s\S]{0,8000}\.\s*SaveToFile\s*\(/is

        // Bound chain with URL present inside the proximity window
        $dropper_chain_url = /(MSXML2\.(XMLHTTP|ServerXMLHTTP)|WinHttp\.WinHttpRequest)[\s\S]{0,4000}https?:\/\/[^\s"'<>\r\n]{6,200}[\s\S]{0,4000}ADODB\.Stream[\s\S]{0,4000}\.\s*SaveToFile\s*\(/is

    condition:
        filesize < 1MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $dropper_chain_a or $dropper_chain_b or $dropper_chain_url )
}

/* -----------------------------------------------------------------------------
   IA_HIGH_ClickFix_Pastejack_Clipboard
   navigator.clipboard.writeText AND lure string ("verify you are human|press
   Win+R|fix CAPTCHA|prove humanity|enter the following") AND a PS payload
   (cmdline starting with powershell or containing iex/FromBase64String/
   -enc/-EncodedCommand) bound. T1059.001 + T1204.004.
   ----------------------------------------------------------------------------- */
rule IA_HIGH_ClickFix_Pastejack_Clipboard
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "initial_access"
        severity = "high"
        description = "ClickFix/pastejack: clipboard.writeText + human-verify lure + PS cradle (iex|FromBase64String|-enc|-EncodedCommand) bound"
        mitre = "T1059.001,T1204.004"

    strings:
        // clipboard.writeText bound within 8KB to lure text bound within 8KB to PS cradle
        $clip_lure_ps = /navigator\.clipboard\.writeText\s*\([\s\S]{0,8000}(verify\s+you\s+are\s+human|press\s+Win\s*\+\s*R|fix\s+CAPTCHA|prove\s+humanity|enter\s+the\s+following|I'?m\s+not\s+a\s+robot|Cloudflare\s+verification|Run\s+box|press\s+CTRL\s*\+\s*V)[\s\S]{0,8000}(powershell(\.exe)?|pwsh)[^"'`\r\n]{0,400}(IEX|Invoke-Expression|FromBase64String|-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{20,}|-EncodedCommand)/is

        // Reverse: PS cradle declared first (as a JS string constant), then writeText + lure
        $ps_clip_lure = /(powershell(\.exe)?|pwsh)[^"'`\r\n]{0,400}(IEX|Invoke-Expression|FromBase64String|-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{20,}|-EncodedCommand)[\s\S]{0,8000}navigator\.clipboard\.writeText\s*\([\s\S]{0,8000}(verify\s+you\s+are\s+human|press\s+Win\s*\+\s*R|fix\s+CAPTCHA|prove\s+humanity|enter\s+the\s+following|I'?m\s+not\s+a\s+robot|Cloudflare\s+verification)/is

        // execCommand('copy') variant bound to lure + PS cradle
        $exec_copy_lure_ps = /document\.execCommand\s*\(\s*["']copy["'][\s\S]{0,8000}(verify\s+you\s+are\s+human|press\s+Win\s*\+\s*R|fix\s+CAPTCHA|prove\s+humanity|enter\s+the\s+following)[\s\S]{0,8000}(powershell(\.exe)?|pwsh)[^"'`\r\n]{0,400}(IEX|FromBase64String|-e(nc)?\s+[A-Za-z0-9+\/=]{20,})/is

    condition:
        filesize < 1MB
        and not uint16(0) == 0x5A4D
        and not uint32(0) == 0x464C457F
        and ( $clip_lure_ps or $ps_clip_lure or $exec_copy_lure_ps )
}
