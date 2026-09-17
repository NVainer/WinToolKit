/*
================================================================================
 04_credential_access.yar
 Author: Nati
 Category: Credential Access (LSASS, DPAPI, SAM/SYSTEM, Kerberos, Browsers)
 Severity: Medium-High to High
 Last updated: 2026-05-24

 Coverage:
   - LSASS process memory dumping: procdump, comsvcs.dll, sqldumper, WerFault,
     ProcessHacker, nanodump, MiniDumpWriteDump P/Invoke
   - PowerShell Out-Minidump / direct NT API LSASS read
   - SAM / SYSTEM / SECURITY hive theft: reg save, esentutl /vss, vssadmin
   - NTDS.dit extraction (vssadmin create shadow + esentutl /y, ntdsutil ifm)
   - Mimikatz module strings: sekurlsa::, kerberos::, lsadump::, dpapi:: ...
   - DCSync / DCShadow
   - Kerberoasting / AS-REP roasting (Rubeus, Invoke-Kerberoast)
   - SharpHound / BloodHound collector
   - Browser credential theft (Chrome/Edge/Firefox creds + cookies SQLite paths)
   - LaZagne credential harvester
   - SharpDPAPI / DonPAPI DPAPI master key tools

 Design (2026-05-24 hardening):
   - Every rule requires an ATTACK SHAPE: tool name + tool-specific verb/arg
     OR credential-store path + decrypt/dump verb bound in one regex window.
   - Standalone tool-name / standalone keyword branches are forbidden.
   - Proximity-bounded regex with [^\r\n]{0,200} between elements.
   - PE/ELF header skip on all rules (these tools are usually script-driven;
     the binaries themselves are rarely on disk pre-exec). Two intentional
     exceptions retained for in-binary banner detection - see summary.
   - filesize cap: < 5MB for script-only rules, < 20MB where the rule can
     match inside a compiled .exe.
   - No path-meta refs (combine_rules.ps1 strips those tokens).
================================================================================
*/

import "pe"

/* -----------------------------------------------------------------------------
   CRED_HIGH_Procdump_LSASS
   procdump64.exe -ma lsass.exe (or by PID) -accepteula
   Bound: procdump binary + -ma flag + lsass|PID + dump-target within 200 chars.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_Procdump_LSASS
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "credential_access"
        severity = "high"
        description = "Sysinternals procdump dumping LSASS: procdump + -ma + lsass|PID + .dmp bound"
        mitre = "T1003.001"
        reference = "https://attack.mitre.org/techniques/T1003/001/"

    strings:
        // procdump <flags> -ma lsass[.exe]  OR  procdump <flags> -ma <pid> ... lsass|.dmp
        $bound_name = /\bprocdump(64)?(\.exe)?\b[^\r\n]{0,80}-ma\s+lsass(\.exe)?\b[^\r\n]{0,200}\.(dmp|bin)/i ascii wide
        $bound_pid  = /\bprocdump(64)?(\.exe)?\b[^\r\n]{0,80}-ma\s+\d{2,6}\b[^\r\n]{0,200}(lsass|\.dmp)/i ascii wide
        // Renamed procdump still uses -ma lsass.exe + .dmp output + -accepteula
        $bound_rename = /\b[A-Za-z0-9_.-]{1,64}\.exe\b[^\r\n]{0,80}-ma\s+lsass(\.exe)?\b[^\r\n]{0,200}\.(dmp|bin)\b[^\r\n]{0,200}-accepteula/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_Comsvcs_MiniDump_LSASS
   rundll32 comsvcs.dll MiniDump <lsass_pid> <out.dmp> full
   Bound: rundll32 + comsvcs.dll + MiniDump + PID + .dmp + full all in one regex.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_Comsvcs_MiniDump_LSASS
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "credential_access"
        severity = "high"
        description = "comsvcs.dll MiniDump export via rundll32 against LSASS PID + dump-path + full bound"
        mitre = "T1003.001"

    strings:
        // rundll32 comsvcs.dll MiniDump <pid> <path>.dmp full
        $bound = /\brundll32(\.exe)?\b[^\r\n]{0,80}comsvcs\.dll[^\r\n]{0,40}\s*,?\s*MiniDump\s+\d{2,6}\s+["']?[A-Z]:\\[^"'\r\n]{1,256}\.(dmp|bin)["']?\s+full/i ascii wide
        // PS one-liner: pipe Get-Process lsass into rundll32 comsvcs.dll MiniDump
        $ps_pipe = /Get-Process\b[^;\r\n]{0,80}lsass\b[^;\r\n]{0,200}rundll32(\.exe)?\b[^;\r\n]{0,80}comsvcs\.dll[^;\r\n]{0,40}MiniDump\b[^;\r\n]{0,80}full/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_MiniDumpWriteDump_PInvoke_LSASS
   P/Invoke or direct-syscall MiniDumpWriteDump against an LSASS handle.
   Bound: MiniDumpWriteDump + lsass + handle-acquisition primitive in proximity.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_MiniDumpWriteDump_PInvoke_LSASS
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "credential_access"
        severity = "high"
        description = "MiniDumpWriteDump P/Invoke or direct syscall bound to LSASS + OpenProcess|access-mask"
        mitre = "T1003.001"

    strings:
        // MiniDumpWriteDump <-> lsass + (OpenProcess | access-mask | dbghelp.dll) within 400 chars
        $bound_api = /MiniDumpWriteDump\b[^\r\n]{0,400}\blsass(\.exe)?\b[^\r\n]{0,400}(OpenProcess|PROCESS_(ALL_ACCESS|VM_READ|QUERY_(LIMITED_)?INFORMATION)|0x1F0FFF|dbghelp\.dll)/i ascii wide
        $bound_api_rev = /\blsass(\.exe)?\b[^\r\n]{0,400}MiniDumpWriteDump\b[^\r\n]{0,400}(OpenProcess|PROCESS_(ALL_ACCESS|VM_READ|QUERY_(LIMITED_)?INFORMATION)|0x1F0FFF|dbghelp\.dll)/i ascii wide
        // Out-Minidump (PowerSploit) targeting lsass / passed a Process object
        $bound_outmini = /Out-Minidump\b[^\r\n]{0,200}(lsass|Get-Process\s+(-Name\s+)?lsass)/i ascii wide
        // nanodump / SharpDump / HandleKatz bound to LSASS or to MiniDumpWriteDump verb
        $bound_nanodump = /\b(nanodump|SharpDump|HandleKatz|MalSeclogon)\b[^\r\n]{0,400}(lsass|MiniDumpWriteDump|MINIDUMP_TYPE|MiniDumpWithFullMemory)/i ascii wide
        // Direct syscall variant: NtReadVirtualMemory + lsass + MiniDump type
        $bound_syscall = /NtReadVirtualMemory\b[^\r\n]{0,400}\blsass(\.exe)?\b[^\r\n]{0,400}(MiniDumpWithFullMemory|MINIDUMP_TYPE|MiniDumpWriteDump)/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_Reg_Save_SAM_SYSTEM_SECURITY
   reg save HKLM\SAM|SYSTEM|SECURITY <out>
   Bound: reg save + hive + output-path-with-suffix all in one regex.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_Reg_Save_SAM_SYSTEM_SECURITY
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "credential_access"
        severity = "high"
        description = "reg save HKLM\\SAM|SYSTEM|SECURITY bound to output path (offline cred extraction)"
        mitre = "T1003.002,T1003.004"

    strings:
        // reg save <hive> <out-file>  - hive + output path bound
        $bound_sam      = /\breg(\.exe)?\s+save\s+(HKLM\\|HKEY_LOCAL_MACHINE\\)?SAM\b[^\r\n]{1,200}\.(hiv|hive|sav|save|bak|dat|reg|tmp)\b/i ascii wide
        $bound_system   = /\breg(\.exe)?\s+save\s+(HKLM\\|HKEY_LOCAL_MACHINE\\)?SYSTEM\b[^\r\n]{1,200}\.(hiv|hive|sav|save|bak|dat|reg|tmp)\b/i ascii wide
        $bound_security = /\breg(\.exe)?\s+save\s+(HKLM\\|HKEY_LOCAL_MACHINE\\)?SECURITY\b[^\r\n]{1,200}\.(hiv|hive|sav|save|bak|dat|reg|tmp)\b/i ascii wide
        // Bare reg save of a hive into user-writable dirs (no suffix constraint)
        $bound_writable = /\breg(\.exe)?\s+save\s+(HKLM\\|HKEY_LOCAL_MACHINE\\)?(SAM|SYSTEM|SECURITY)\b[^\r\n]{1,200}(%TEMP%|%APPDATA%|%PUBLIC%|%LOCALAPPDATA%|\$env:(TEMP|APPDATA|PUBLIC|LOCALAPPDATA)|C:\\Users\\[^\\\r\n]{1,80}\\(AppData|Downloads|Desktop|Documents)|C:\\ProgramData\\|C:\\Temp\\|C:\\Windows\\Temp\\)/i ascii wide
        // PowerShell reg.exe save wrapper bound to hive name
        $ps_save_bound  = /(Start-Process|Invoke-Expression|&\s*)\s*['"]?reg(\.exe)?['"]?[^;\r\n]{0,80}save[^;\r\n]{0,80}(HKLM\\|HKEY_LOCAL_MACHINE\\)?(SAM|SYSTEM|SECURITY)\b[^;\r\n]{0,200}\.(hiv|hive|sav|save|bak|dat|reg|tmp)/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and ( 2 of ( $bound_sam, $bound_system, $bound_security )
              or $bound_writable
              or $ps_save_bound )
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_VSS_Shadow_NTDS_SAM_Extract
   VSS shadow create + esentutl /y copy of NTDS.dit | SAM | SYSTEM | SECURITY
   Bound: shadow-create AND esentutl copy of cred target, OR ntdsutil ifm full.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_VSS_Shadow_NTDS_SAM_Extract
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "credential_access"
        severity = "high"
        description = "VSS shadow + esentutl/copy of NTDS.dit|SAM|SYSTEM|SECURITY, or ntdsutil ifm create full bound"
        mitre = "T1003.003,T1003.002"

    strings:
        // shadow create
        $vss_create   = /\b(vssadmin(\.exe)?\s+create\s+shadow\s+\/for=|wmic(\.exe)?\s+shadowcopy\s+call\s+create\b)/i ascii wide
        // esentutl /y bound to cred target (NTDS.dit / SAM / SYSTEM / SECURITY)
        $esentutl_bound = /\besentutl(\.exe)?\s+(\/[a-z]\s+){1,3}["']?[^"'\r\n]{0,200}(NTDS\.dit|System32\\config\\(SAM|SYSTEM|SECURITY)|HarddiskVolumeShadowCopy\d+)/i ascii wide
        // copy of shadow path -> cred target
        $copy_bound   = /\b(copy|xcopy|robocopy|Copy-Item)\b[^\r\n]{0,80}HarddiskVolumeShadowCopy\d+\\[^\r\n]{0,200}(NTDS\.dit|System32\\config\\(SAM|SYSTEM|SECURITY))/i ascii wide
        // ntdsutil "ifm create full <path>"  - full bound
        $ntdsutil_ifm = /\bntdsutil(\.exe)?\b[^\r\n]{0,200}["']?\s*(ac|activate)\s+i(nstance)?\s+ntds\s*["']?[^\r\n]{0,200}["']?\s*ifm\s*["']?[^\r\n]{0,80}create\s+full\s+["']?[A-Z]:\\/i ascii wide
        // diskshadow scripted mode invoked with /s <script>  bound to cred dirs in same file
        $diskshadow   = /\bdiskshadow(\.exe)?\s+\/s\s+["']?[^"'\r\n]{1,200}\.(txt|dsh|cmd)["']?[^\r\n]{0,400}(NTDS\.dit|System32\\config\\(SAM|SYSTEM|SECURITY))/i ascii wide
        // PS WMI shadowcopy create bound to target system drive
        $ps_volsnap   = /(Get-WmiObject|New-CimInstance|Invoke-CimMethod)\b[^;\r\n]{0,200}Win32_ShadowCopy[^;\r\n]{0,200}(Create|"C:\\")/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and ( ( $vss_create and ( $esentutl_bound or $copy_bound ) )
              or $ntdsutil_ifm
              or $diskshadow
              or ( $ps_volsnap and ( $esentutl_bound or $copy_bound ) ) )
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_Mimikatz_Module_Strings
   Mimikatz module signatures - require BOUND tool-name + module::verb
   in single regex, OR multiple distinct module verbs together.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_Mimikatz_Module_Strings
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "credential_access"
        severity = "high"
        description = "Mimikatz: bound tool-name + module::verb, or multiple module::verb co-occurrence"
        mitre = "T1003.001,T1003.002,T1003.004,T1003.005,T1003.006,T1558,T1555"
        reference = "Benjamin Delpy / gentilkiwi mimikatz"

    strings:
        // Bound: mimikatz binary/banner + tool-specific module::verb within 200 chars
        $bound_tool = /\bmimikatz(\.exe)?\b[^\r\n]{0,200}\b(sekurlsa::(logonpasswords|wdigest|tspkg|kerberos|msv|ekeys|pth|tickets|credman|backupkeys|dpapi|process|minidump)|lsadump::(dcsync|sam|secrets|cache|trust|lsa|backupkeys|setntlm|changentlm|netsync|dcshadow|zerologon)|kerberos::(ptt|ptc|ask|tgt|list|golden|silver|purge|hash|clist)|crypto::(capi|certificates|stores|keys|cng)|dpapi::(masterkey|credhist|cred|chrome|vault|protect|capi|cng|ssh|wifi|blob)|privilege::debug|misc::(memssp|skeleton|cmd|detours|sccm|lock|wp|aaddsbackupkey))/i ascii wide
        // Distinct module::verb (no tool name) - require >= 2 different modules
        $m_sekurlsa = /\bsekurlsa\s*::\s*(logonpasswords|tickets|pth|wdigest|kerberos|msv|tspkg|livessp|credman|backupkeys|ekeys|dpapi|process|minidump)\b/i ascii wide
        $m_kerberos = /\bkerberos\s*::\s*(list|ptt|ptc|golden|silver|tgt|ask|purge|hash|clist)\b/i ascii wide
        $m_lsadump  = /\blsadump\s*::\s*(sam|secrets|dcsync|cache|lsa|trust|backupkeys|setntlm|changentlm|netsync|dcshadow|zerologon)\b/i ascii wide
        $m_dpapi    = /\bdpapi\s*::\s*(masterkey|cred|chrome|protect|capi|cng|ssh|vault|wifi|blob)\b/i ascii wide
        $m_vault    = /\bvault\s*::\s*(list|cred)\b/i ascii wide
        $m_token    = /\btoken\s*::\s*(whoami|list|elevate|revert|run)\b/i ascii wide
        $m_misc     = /\bmisc\s*::\s*(memssp|skeleton|cmd|detours|sccm|lock|wp|aaddsbackupkey)\b/i ascii wide
        $m_crypto   = /\bcrypto\s*::\s*(certificates|keys|cng|capi|stores)\b/i ascii wide
        $m_priv     = /\bprivilege\s*::\s*debug\b/i ascii wide
        // Canonical banner artwork bound together (very specific, in-binary)
        $banner_bound = /\.#####\.\s*[\r\n][^\r\n]{0,80}mimikatz[^\r\n]{0,80}[\r\n][^\r\n]{0,200}gentilkiwi/i ascii wide

    condition:
        // Skip ELF only; PE skip OFF here because mimikatz BANNER lives inside the
        // mimikatz.exe binary itself - we want to catch the EXE on disk too.
        not uint32(0) == 0x464C457F
        and filesize < 20MB
        and ( $bound_tool
              or $banner_bound
              or 2 of ( $m_sekurlsa, $m_kerberos, $m_lsadump, $m_dpapi, $m_vault, $m_token, $m_misc, $m_crypto, $m_priv ) )
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_Mimikatz_PS_Invoke
   Invoke-Mimikatz (PowerSploit / Empire reflective PE loader).
   Bound: function name + dump arg, or reflective-PE marker + mimikatz module verb.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_Mimikatz_PS_Invoke
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "credential_access"
        severity = "high"
        description = "Invoke-Mimikatz: function + dump arg, or reflective PE injection bound to mimikatz module verb"
        mitre = "T1003.001"

    strings:
        // function Invoke-Mimikatz { ... } bound to a known module verb in same script
        $fn_bound  = /function\s+Invoke-Mimikatz\b[^\0]{0,4000}\b(sekurlsa|kerberos|lsadump|dpapi|crypto|privilege)\s*::/i ascii wide
        // Invoke-Mimikatz -DumpCreds / -DumpCerts / -Command "module::verb"
        $call_bound = /\bInvoke-Mimikatz\b[^\r\n]{0,200}(-DumpCreds|-DumpCerts|-Command\s+['"]?(sekurlsa|kerberos|lsadump|dpapi|crypto|privilege|vault|token|misc|ts)::)/i ascii wide
        // Reflective PE injection bound to mimikatz module command
        $reflect_bound = /(Invoke-ReflectivePEInjection|InvokeReflectivePEInjection)\b[^\0]{0,2000}\b(sekurlsa|kerberos|lsadump|dpapi|crypto|privilege)\s*::/i ascii wide
        // Base64 PEBytes blob bound to mimikatz command string in same script
        $b64_bound = /\$PEBytes(64|32)?\s*=\s*['"][A-Za-z0-9+\/=]{1000,}[^\0]{0,4000}\b(sekurlsa|kerberos|lsadump|dpapi)\s*::/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_Rubeus_Kerberoast
   Rubeus + subcommand + Kerberos-specific flag bound in single regex.
   PS-side: Invoke-Kerberoast/Get-DomainSPNTicket bound to KerberosRequestor API.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_Rubeus_Kerberoast
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "credential_access"
        severity = "high"
        description = "Rubeus subcommand + Kerberos flag bound, or PS Kerberoast wrapper + Kerberos API"
        mitre = "T1558.003,T1558.004,T1558.001,T1550.003"
        reference = "https://github.com/GhostPack/Rubeus"

    strings:
        // Rubeus(.exe) <subcmd> ... /user:|/domain:|/rc4:|/aes256:|/ticket:|/password:|/spn:|/impersonateuser:|/nopreauth
        $rubeus_bound = /\bRubeus(\.exe)?\b[^\r\n]{0,80}\b(kerberoast|asreproast|asktgt|asktgs|s4u|ptt|tgtdeleg|monitor|harvest|brute|renew|describe|hash|changepw|tgssub|dump)\b[^\r\n]{0,200}\/(user|domain|rc4|aes256|ticket|password|spn|impersonateuser|nopreauth|outfile|service|dc|enctype|nowrap|format):/i ascii wide
        // Rubeus banner artwork bound to subcmd line (in-binary catch)
        $rubeus_banner = /Rubeus\s+--\s+[A-Za-z][^\r\n]{0,80}[\r\n][^\r\n]{0,200}(harmj0y|GhostPack)/i ascii wide
        // PS Invoke-Kerberoast bound to KerberosRequestor API
        $ps_kerb_bound = /(Invoke-Kerberoast|Get-DomainSPNTicket)\b[^\0]{0,2000}KerberosRequestorSecurityToken/i ascii wide

    condition:
        not uint32(0) == 0x464C457F
        and filesize < 20MB
        and any of them
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_SharpHound_BloodHound_Collector
   Bound: collector binary/cmdlet + -CollectionMethod flag.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_SharpHound_BloodHound_Collector
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "discovery,credential_access"
        severity = "high"
        description = "SharpHound/AzureHound/Invoke-BloodHound bound to -CollectionMethod flag"
        mitre = "T1087.002,T1482,T1069.002"
        reference = "https://github.com/BloodHoundAD/SharpHound"

    strings:
        // SharpHound.exe / .ps1 + -CollectionMethod[s] <method>
        $sh_bound = /\bSharpHound(\.exe|\.dll|\.ps1)?\b[^\r\n]{0,200}-CollectionMethods?\s+(All|Default|DCOnly|Group|LocalGroup|GPOLocalGroup|Session|LoggedOn|Trusts|ACL|Container|RDP|ObjectProps|SPNTargets|UserRights|CARegistry|DCRegistry|CertServices)/i ascii wide
        // Invoke-BloodHound cmdlet + -CollectionMethod
        $ibh_bound = /\bInvoke-BloodHound\b[^\r\n]{0,200}-CollectionMethods?\s+(All|Default|DCOnly|Group|LocalGroup|GPOLocalGroup|Session|LoggedOn|Trusts|ACL|Container|RDP|ObjectProps|SPNTargets|UserRights|CARegistry|DCRegistry|CertServices)/i ascii wide
        // AzureHound + collection verb
        $azh_bound = /\bAzureHound(\.exe)?\b[^\r\n]{0,200}\b(list|connect|--tenant|--client|--secret|--username|--password|--refresh-token)/i ascii wide
        // SharpHound output artifact name pattern bound to "BloodHound" in same line
        $zip_bound = /\b20\d{12}_BloodHound\.zip\b[^\r\n]{0,200}(SharpHound|Invoke-BloodHound|BloodHound)/i ascii wide

    condition:
        not uint32(0) == 0x464C457F
        and filesize < 20MB
        and any of them
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_LaZagne_Credential_Harvester
   Bound: LaZagne tool name + tool-specific subcommand/module path.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_LaZagne_Credential_Harvester
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "credential_access"
        severity = "high"
        description = "LaZagne harvester bound to subcmd (all|browsers|mails|...) or to lazagne.softwares.* module path"
        mitre = "T1555,T1003"
        reference = "https://github.com/AlessandroZ/LaZagne"

    strings:
        // laZagne(.exe) <subcommand>
        $laz_cli_bound = /\b(laZagne|lazagne)(\.exe|\.py)?\s+(all|browsers|chats|mails|wifi|sysadmin|memory|windows|maven|svn|database|games|git|maven|php|wallet|cloud)\b[^\r\n]{0,200}(-vv|-v|-oN|-oJ|-output|-write-all|-quiet)?/i ascii wide
        // Python module trail bound to LaZagne package marker
        $laz_mod_bound = /lazagne\.softwares\.(browsers|chats|mails|wallet|wifi|sysadmin|memory|windows|database|games|git|svn|maven|php|cloud)\.[A-Za-z0-9_]{2,40}/i ascii wide
        // Output banner bound: "------------------- LaZagne" ... "passwords have been found"
        $laz_out_bound = /-----+\s*LaZagne[^\0]{0,2000}passwords have been found/i ascii wide
        // Author + config-write context bound
        $laz_author_bound = /AlessandroZ\b[^\0]{0,2000}lazagne(\.config|\\config\\write_output)/i ascii wide

    condition:
        not uint32(0) == 0x464C457F
        and filesize < 20MB
        and any of them
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_BrowserCredentialDB_Access
   Bound: browser cred-store path AND DPAPI/SQLite decrypt verb within one
   tight regex window so Windows.db indexed paths can't trigger.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_BrowserCredentialDB_Access
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "credential_access"
        severity = "high"
        description = "Browser cred DB path + DPAPI/SQLite decrypt verb bound in proximity (Chrome/Edge/Firefox)"
        mitre = "T1555.003"
        reference = "Stealer family TTP"

    strings:
        // Chrome/Edge Login Data path <-> CryptUnprotectData|ProtectedData.Unprotect|sqlite3_open within 400 chars
        $chrome_dpapi  = /(Google|Microsoft)\\(Chrome|Edge)\\User\s?Data\\(Default|Profile\s?\d+)\\Login\s?Data\b[^\0]{0,400}(CryptUnprotectData|ProtectedData\.Unprotect|sqlite3_open|System\.Data\.SQLite|Microsoft\.Data\.Sqlite)/i ascii wide
        $chrome_dpapi_rev = /(CryptUnprotectData|ProtectedData\.Unprotect|sqlite3_open|System\.Data\.SQLite|Microsoft\.Data\.Sqlite)\b[^\0]{0,400}(Google|Microsoft)\\(Chrome|Edge)\\User\s?Data\\(Default|Profile\s?\d+)\\Login\s?Data\b/i ascii wide
        // Cookies DB <-> decrypt verb
        $cookie_dpapi  = /(Google|Microsoft)\\(Chrome|Edge)\\User\s?Data\\(Default|Profile\s?\d+)\\(Network\\)?Cookies\b[^\0]{0,400}(CryptUnprotectData|ProtectedData\.Unprotect|sqlite3_open|AesGcm|encrypted_value)/i ascii wide
        // Local State + os_crypt encrypted_key + AES-GCM unwrap bound
        $local_state_bound = /(Google|Microsoft)\\(Chrome|Edge)\\User\s?Data\\Local\s?State\b[^\0]{0,400}(os_crypt|encrypted_key)\b[^\0]{0,400}(AesGcm|CryptUnprotectData|ProtectedData\.Unprotect|DPAPI_KEY_PREFIX)/i ascii wide
        // Firefox logins.json|key4.db + NSS_Init|PK11SDR_Decrypt
        $firefox_bound = /Mozilla\\Firefox\\Profiles\\[^\\\r\n]{1,80}\\(logins\.json|key4\.db|signons\.sqlite)\b[^\0]{0,400}(NSS_Init|PK11SDR_Decrypt|nss3\.dll|PK11_GetInternalKeySlot)/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_DPAPI_Masterkey_Tools
   Bound: SharpDPAPI/DonPAPI tool name + tool-specific subcommand.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_DPAPI_Masterkey_Tools
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "credential_access"
        severity = "high"
        description = "SharpDPAPI/DonPAPI bound: tool name + masterkeys|credentials|certificates|vaults|triage|chrome subcmd"
        mitre = "T1555.004,T1003.005"
        reference = "https://github.com/GhostPack/SharpDPAPI"

    strings:
        // SharpDPAPI(.exe) <subcmd>
        $sd_bound = /\bSharpDPAPI(\.exe|\.dll)?\b[^\r\n]{0,200}\b(masterkeys|credentials|certificates|vaults|rdg|backupkey|machinemasterkeys|machinecredentials|machinevaults|chrome|search|triage|blob)\b/i ascii wide
        // DonPAPI(.py|.exe) <subcmd / flag>
        $don_bound = /\bDonPAPI(\.py|\.exe)?\b[^\r\n]{0,200}(--target|--user|--password|--hashes|--no-vnc|--no-recent|--no-remoteops|--pvk|--masterkey)/i ascii wide
        // SharpDPAPI verbose output bound: "Master Keys for SID" + S-1-5-21
        $sd_out_bound = /Master Keys for SID\b[^\0]{0,400}S-1-5-21-\d+/i ascii wide
        // PS PInvoke CryptUnprotectData bound to masterkey path
        $ps_dpapi_bound = /CryptUnprotectData\b[^\0]{0,400}(Protect\\S-1-5-21-|Microsoft\\Protect\\S-1-5-|Crypto\\RSA\\S-1-5-21-)/i ascii wide

    condition:
        not uint32(0) == 0x464C457F
        and filesize < 20MB
        and any of them
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_Sqldumper_LSASS
   sqldumper.exe abused for LSASS via PssCaptureSnapshot - the magic dump-type
   flag 0x011XX is the binding element.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_Sqldumper_LSASS
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "credential_access"
        severity = "high"
        description = "sqldumper.exe LSASS dump bound: binary + PID + 0 + 0x011XX dump-type flag"
        mitre = "T1003.001,T1218"

    strings:
        // sqldumper(.exe) [flags] <pid> 0 0x01100|0x011XX
        $bound = /\bsqldumper(\.exe)?\b[^\r\n]{0,80}\d{2,6}\s+0\s+0x011[0-9a-f]{2}\b/i ascii wide
        // Variable-substituted PID variant
        $bound_var = /\bsqldumper(\.exe)?\b[^\r\n]{0,80}\$\w+\s+0\s+0x011[0-9a-f]{2}\b/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_WerFault_KProcessHacker_LSASS
   WerFault SilentProcessExit lsass.exe registry abuse, or KProcessHacker driver
   used for LSASS access. Bound: SilentProcessExit subkey + lsass.exe + dump
   value names; or KProcessHacker artifact + lsass/handle context.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_WerFault_KProcessHacker_LSASS
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "credential_access"
        severity = "high"
        description = "WerFault SilentProcessExit lsass.exe registry bound, or KProcessHacker driver bound to LSASS access"
        mitre = "T1003.001"

    strings:
        // WerFault -pss -s <N> -t <PID>  bound (the SilentProcessExit launcher line)
        $wer_cli = /\bWerFault(Secure)?(\.exe)?\b[^\r\n]{0,80}-pss\b[^\r\n]{0,40}-s\s+\d{1,3}\b[^\r\n]{0,40}-t\s+\d{2,6}/i ascii wide
        // SilentProcessExit registry path bound to lsass.exe + MonitorProcess|DumpType|GlobalFlag
        $silent_bound = /SOFTWARE\\Microsoft\\Windows\s?NT\\CurrentVersion\\SilentProcessExit\\lsass\.exe\b[^\0]{0,400}(GlobalFlag|MonitorProcess|DumpType|DumpFolder|ReportingMode)/i ascii wide
        // reg.exe add / PS Set-ItemProperty bound to SilentProcessExit\lsass.exe
        $silent_set = /(reg(\.exe)?\s+add|Set-ItemProperty|New-ItemProperty)\b[^\0]{0,200}SilentProcessExit\\lsass\.exe\b[^\0]{0,200}(GlobalFlag|MonitorProcess|DumpType)/i ascii wide
        // KProcessHacker driver bound to lsass / handle-acquisition context
        $kproc_bound = /(KProcessHacker[23]?\.sys|kphlib(\.dll)?)\b[^\0]{0,400}(lsass|KphOpenProcess|KphReadVirtualMemory)/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_PS_DbgHelp_Or_NTAPI_LSASS_Read
   Direct NT API LSASS handle + read.  Defender's own DataCollection .ps1
   mentions NtOpenProcess / UNICODE_STRING / OBJECT_ATTRIBUTES / seclogon as
   IOC text - so EVERY branch here requires those primitives bound to lsass
   in a tight regex window, plus a dynamic-invocation primitive.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_PS_DbgHelp_Or_NTAPI_LSASS_Read
{
    meta:
        author = "Nati"
        date = "2026-05-24"
        category = "credential_access"
        severity = "high"
        description = "PS direct NT API LSASS handle + read: NtOpenProcess|NtDuplicateObject + lsass + DynamicInvoke|Add-Type all bound"
        mitre = "T1003.001"

    strings:
        // NtOpenProcess <-> lsass + NtReadVirtualMemory in proximity
        $bound_ntopen = /NtOpenProcess\b[^\0]{0,400}\blsass(\.exe)?\b[^\0]{0,400}NtReadVirtualMemory/i ascii wide
        $bound_ntopen_rev = /NtReadVirtualMemory\b[^\0]{0,400}\blsass(\.exe)?\b[^\0]{0,400}NtOpenProcess/i ascii wide
        // NtOpenProcess + lsass + DynamicInvoke|Add-Type|GetDelegateForFunctionPointer
        $bound_dyn = /NtOpenProcess\b[^\0]{0,400}\blsass(\.exe)?\b[^\0]{0,400}(DynamicInvoke|GetDelegateForFunctionPointer|Add-Type\s+-TypeDefinition)/i ascii wide
        // NtDuplicateObject / DuplicateHandle  + lsass + dynamic-invoke primitive
        $bound_dup = /(NtDuplicateObject|DuplicateHandle)\b[^\0]{0,400}\blsass(\.exe)?\b[^\0]{0,400}(DynamicInvoke|GetDelegateForFunctionPointer|Add-Type\s+-TypeDefinition)/i ascii wide
        // MalSeclogon / seclogon-token-stealing class bound to lsass + handle-dup
        $bound_seclogon = /\b(MalSeclogon|seclogon(\.dll)?)\b[^\0]{0,400}\blsass(\.exe)?\b[^\0]{0,400}(NtOpenProcess|NtDuplicateObject|DuplicateHandle|MiniDumpWriteDump)/i ascii wide

    condition:
        not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and filesize < 5MB
        and any of them
}
