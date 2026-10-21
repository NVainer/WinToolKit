/* =============================================================================
   03_credential_access.yar
   -----------------------------------------------------------------------------
   Author : Nati
   Date   : 2026-10-14 (v3)
   Scope  : Credential theft on a cloud-joined client. The valuable things on
            disk are the ARTIFACTS (an LSASS dump, a SAM/SYSTEM copy, a Kerberos
            ticket, a dumped-password text file, a stealer log) and the TOOLS
            (mimikatz, browser credential dumpers) - not AD-replication tooling,
            which has nothing to replicate from a workstation.

   Dropped from v2: NTDS.dit/DCSync/ntdsutil (no DC here), sqldumper, WerFault
   SilentProcessExit tricks (registry-only, MDE telemetry), NT-API read
   scaffolds (noisy, covered by the dump-tool names), GPP cpassword.
   ============================================================================= */

/* -----------------------------------------------------------------------------
   CRED_HIGH_LSASS_Minidump_On_Disk
   A minidump whose module list is LSASS's. Task Manager, procdump, comsvcs,
   nanodump and friends all produce this. Nothing legitimate leaves it behind.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_LSASS_Minidump_On_Disk
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "credential_access"
        severity    = "high"
        description = "MDMP file containing lsass.exe plus lsasrv.dll (or wdigest.dll + kerberos.dll) module paths - an LSASS memory dump"
        mitre       = "T1003.001"
        fp_notes    = "A WER crash dump of lsass itself is possible but still worth a look (why did LSASS crash?)."

    strings:
        $lsass    = "lsass.exe"    wide nocase
        $lsasrv   = "lsasrv.dll"   wide nocase
        $wdigest  = "wdigest.dll"  wide nocase
        $kerberos = "kerberos.dll" wide nocase

    condition:
        uint32(0) == 0x504D444D
        and $lsass
        and ( $lsasrv or ( $wdigest and $kerberos ) )
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_Registry_Hive_Copy_SAM_SYSTEM_SECURITY
   Readable copy of a credential hive. The live hives are locked, so any
   readable regf file carrying their header name or key fingerprints was made
   by reg save, a shadow copy, esentutl /vss or a backup tool.
   (The global filter SKIP_SYSTEM_DATASTORES lets exactly these through.)
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_Registry_Hive_Copy_SAM_SYSTEM_SECURITY
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "credential_access"
        severity    = "high"
        description = "regf hive whose header path ends in System32\\Config\\SAM|SYSTEM|SECURITY, or whose key names fingerprint SYSTEM (ControlSet001), SECURITY (PolSecretEncryptionKey) or SAM (Domains+Builtin+Aliases)"
        mitre       = "T1003.002,T1003.004"
        fp_notes    = "Benign: C:\\Windows.old\\...\\config\\* for ~10 days after a feature update; RegBack copies if periodic backup was enabled. Anything under a user profile, Temp, Public or ProgramData is theft."

    strings:
        $hive_sam      = "System32\\Config\\SAM"      wide nocase
        $hive_system   = "System32\\Config\\SYSTEM"   wide nocase
        $hive_security = "System32\\Config\\SECURITY" wide nocase
        // nk-cell anchored key names ("nk" + 74 header bytes + name); plain words
        // also occur inside value data of SOFTWARE / NTUSER hives.
        $sys_ccs       = /nk[\s\S]{74}ControlSet001/          ascii
        $sec_polkey    = /nk[\s\S]{74}PolSecretEncryptionKey/ ascii
        $sam_rxact     = /nk[\s\S]{74}RXACT/                  ascii
        $sam_domains   = /nk[\s\S]{74}Domains/                ascii

    condition:
        uint32(0) == 0x66676572
        and filesize > 8KB
        and (
            $hive_sam in (0x30..0x70)
            or $hive_system in (0x30..0x70)
            or $hive_security in (0x30..0x70)
            or $sys_ccs
            or $sec_polkey
            or ( $sam_rxact and $sam_domains )
        )
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_Kerberos_Ticket_File
   KRB-CRED (.kirbi) on disk, raw or as the base64 blob Rubeus/mimikatz print.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_Kerberos_Ticket_File
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "credential_access"
        severity    = "high"
        description = "Raw KRB-CRED (ASN.1 APPLICATION 22, bytes 76 82) with a service/krbtgt name, or a base64 kirbi blob (doIE/doIF/doIG/doIH...) in a text file"
        mitre       = "T1550.003,T1558"

    strings:
        $krbtgt   = "krbtgt"   ascii
        $cifs     = "cifs"     ascii
        $host     = "host"     ascii
        $ldap     = "ldap"     ascii
        $http     = "HTTP"     ascii
        $mssql    = "MSSQLSvc" ascii
        // The base64 form must START a token (line start, whitespace, quote, '=', ':', ',').
        // "doIE" also occurs mid-stream inside large base64 image blobs (SVG/CSS data URIs);
        // a 4-character sequence in a 2 MB blob is a coin flip, a token boundary is not.
        $b64kirbi = /(^|[\s"'=:,>\(\[])doI[EFGH][A-Za-z0-9+\/]{500,}/ ascii wide

    condition:
        ( uint16(0) == 0x8276 and filesize < 64KB and 1 of ($krbtgt, $cifs, $host, $ldap, $http, $mssql) )
        or ( filesize < 20MB and not uint16(0) == 0x5A4D and $b64kirbi )
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_Dumped_Credentials_Text
   Output files of credential dumpers and stealers.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_Dumped_Credentials_Text
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "credential_access,collection"
        severity    = "high"
        description = "mimikatz logonpasswords output (* Username / * NTLM / Authentication Id / msv), pwdump/secretsdump lines (3+), empty-LM hash constant (3+), infostealer URL/Username/Password blocks (3+), LaZagne summary line, Rubeus/Impacket kerberoast hash lines"
        mitre       = "T1003,T1555,T1558.003"
        fp_notes    = "A user's own plaintext password note in URL/Username/Password layout can match the stealer branch; that is still a finding."

    strings:
        $mk_user       = /\*\s*Username\s*:\s*[^\r\n]{1,80}/ ascii wide
        $mk_ntlm       = /\*\s*NTLM\s*:\s*[a-fA-F0-9]{32}/ ascii wide
        $mk_auth       = /Authentication Id\s*:\s*0\s*;\s*\d+/ ascii wide
        $mk_msv        = /\bmsv\s*:\s*[\r\n]/ ascii wide
        $pwdump        = /[^:\r\n]{1,64}:\d{1,10}:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::/ ascii wide
        $emptylm       = "aad3b435b51404eeaad3b435b51404ee" ascii wide nocase
        $stealer_block = /(URL|Host(name)?|Site)\s*:\s*https?:\/\/[^\r\n]{1,200}\r?\n\s*(User(name)?|Login|Email)\s*:\s*[^\r\n]{1,120}\r?\n\s*(Pass(word)?|PWD)\s*:\s*[^\r\n]{1,120}/i ascii wide
        $lazagne_out   = /\[\+\]\s+\d+\s+passwords?\s+(have been|has been|were) found/i ascii wide
        $roast_hash    = /\$krb5(tgs|asrep)\$(23|17|18)\$[^\r\n]{20,}/ ascii wide

    condition:
        filesize < 50MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and (
            ( $mk_user and $mk_ntlm )
            or ( $mk_auth and $mk_msv )
            or #pwdump >= 3
            or #emptylm >= 3
            or #stealer_block >= 3
            or $lazagne_out
            or $roast_hash
        )
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_Mimikatz
   The binary, the PowerShell wrapper, the command strings, or the command
   base64-encoded inside an -EncodedCommand blob.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_Mimikatz
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "credential_access"
        severity    = "high"
        description = "sekurlsa::logonpasswords, 2+ mimikatz module::command strings, mimikatz+gentilkiwi, mimidrv/mimilib/mimilsa, Invoke-Mimikatz with -DumpCreds/-Command, pypykatz, or the logonpasswords command base64-encoded"
        mitre       = "T1003.001,T1003.002,T1558"
        fp_notes    = "A cached blog post that quotes 'sekurlsa::logonpasswords' matches. The path of the hit (browser cache vs. user folder) decides."

    strings:
        $m_logon  = "sekurlsa::logonpasswords" ascii wide nocase
        $m_mod    = /\b(sekurlsa|lsadump|kerberos|dpapi|crypto|privilege|token|misc|vault|ts)::(logonpasswords|wdigest|tspkg|msv|ekeys|pth|tickets|credman|dpapi|minidump|sam|secrets|cache|dcsync|dcshadow|lsa|trust|backupkeys|ptt|ptc|golden|silver|purge|list|ask|tgt|masterkey|cred|chrome|vault|capi|cng|certificates|keys|debug|elevate|whoami|memssp|skeleton|cmd|detours|sccm)\b/ ascii wide nocase
        $m_name   = "mimikatz"   ascii wide nocase
        $m_kiwi   = "gentilkiwi" ascii wide nocase
        $m_drv    = /mimi(drv|lib|lsa)\.(sys|dll)\b/ ascii wide nocase   // PE-only: defensive content (SGRM assertions, Sysmon configs) names the driver too
        $m_ps     = "Invoke-Mimikatz" ascii wide nocase
        $m_ps_arg = /(-DumpCreds|-DumpCerts|-Command\s+['"]?(sekurlsa|lsadump|kerberos|privilege|dpapi))/ ascii wide nocase
        $m_pypy   = "pypykatz" ascii wide nocase
        $m_b64    = "sekurlsa::logonpasswords" base64 base64wide
        $m_b64w   = "sekurlsa::logonpasswords" wide base64 base64wide

    condition:
        filesize < 60MB
        and not uint32(0) == 0x464C457F
        and (
            $m_logon
            or #m_mod >= 2
            or ( $m_name and $m_kiwi )
            or ( uint16(0) == 0x5A4D and $m_drv )
            or ( $m_ps and $m_ps_arg )
            or ( $m_pypy and $m_name )
            or $m_b64 or $m_b64w
        )
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_LSASS_Dump_Command
   The command lines and tool names that produce an LSASS dump.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_LSASS_Dump_Command
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "credential_access"
        severity    = "high"
        description = "procdump -ma lsass|pid, comsvcs.dll MiniDump, MiniDumpWriteDump near lsass, Out-Minidump lsass, nanodump/SharpDump/HandleKatz/MalSeclogon/dumpert/PPLdump/lsassy/SafetyKatz, rdrleakdiag /fullmemdmp, createdump against lsass, SilentProcessExit\\lsass.exe, lsass.dmp file names"
        mitre       = "T1003.001"

    strings:
        $procdump   = /\bprocdump(64)?(\.exe)?\b[^\r\n]{0,80}\s-ma\s+(lsass(\.exe)?|\d{2,6})\b/i ascii wide
        $procdump2  = /\s-ma\s+lsass(\.exe)?\b[^\r\n]{0,120}\.dmp/i ascii wide
        $comsvcs    = /comsvcs(\.dll)?["']?\s*,?\s*(#\+?24|MiniDump(W)?)\s+[^\r\n]{0,120}(lsass|\$\w+|\d{2,6})/i ascii wide
        $comsvcs_ps = /Get-Process\s+(-Name\s+)?lsass[^\r\n]{0,120}comsvcs/i ascii wide
        $mdwd       = /(MiniDumpWriteDump[\s\S]{0,600}\blsass(\.exe)?\b|\blsass(\.exe)?\b[\s\S]{0,600}MiniDumpWriteDump)/i ascii wide
        $outmini    = /(Out-Minidump\b[^\r\n]{0,200}lsass|lsass[^\r\n]{0,200}Out-Minidump)/i ascii wide
        // Tool names only count when invoked (followed by an argument) - Microsoft's
        // own code-integrity block policies list the same names as FileName attributes.
        $tools      = /\b(nanodump|SharpDump|HandleKatz|MalSeclogon|MirrorDump|PPLdump|PPLBlade|LsassSilentProcessExit|SafetyKatz|lsassy|EDRSandBlast|PPLKiller)(\.exe|\.py|\.ps1)?\s+[-\/\d"'\\]/i ascii wide
        $rdrleak    = /rdrleakdiag(\.exe)?\s+[^\r\n]{0,80}\/fullmemdmp/i ascii wide
        $createdump = /createdump(\.exe)?[^\r\n]{0,120}\blsass\b/i ascii wide
        $wer_silent = /SilentProcessExit\\\\?lsass\.exe/i ascii wide
        $lsass_dmp  = /\blsass(\.exe)?[_\-\.]?\d{0,6}\.dmp\b/i ascii wide
        $sipolicy   = "<SiPolicy" ascii wide

    condition:
        filesize < 10MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and not $sipolicy
        and 1 of ($procdump, $procdump2, $comsvcs, $comsvcs_ps, $mdwd, $outmini, $tools, $rdrleak, $createdump, $wer_silent, $lsass_dmp)
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_Browser_Credential_Theft_Tool
   Tools and scripts that decrypt Chrome/Edge/Firefox credential stores -
   the infostealer core and the post-exploitation equivalents.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_Browser_Credential_Theft_Tool
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "credential_access"
        severity    = "high"
        description = "LaZagne, HackBrowserData, SharpDPAPI/SharpChrome/ChromeKatz/DonPAPI, App-Bound-Encryption decryptors; or a script/small PE combining browser Login Data / Local State / Firefox key4.db paths with DPAPI/AES-GCM/NSS decryption and an exfil channel"
        mitre       = "T1555.003,T1539"
        fp_notes    = "Password managers' browser importers are large signed apps; the PE branch is capped at 15 MB and requires an exfil marker (Telegram, Discord webhook, SMTP, UploadFile, ftp)."

    strings:
        $t_lazagne  = "lazagne"            ascii wide nocase
        $t_hbd      = "hack-browser-data"  ascii wide nocase
        $t_sharp    = /(SharpDPAPI|SharpChrome|SharpChromium|ChromeKatz|CookieKatz|DonPAPI|ChromeDump)\b/ ascii wide
        $t_abe      = /(chrome_decrypt|App-Bound Encryption|app_bound_encrypted_key|IElevator|GoogleChromeElevator|C4Bomb)/ ascii wide
        $path_login = /\\User Data\\(Default|Profile \d+)\\(Login Data|Web Data|Network\\Cookies|Cookies)/i ascii wide
        $path_state = /\\User Data\\Local State/i ascii wide
        $ff_profile = /\\Mozilla\\Firefox\\Profiles\\[^\\\r\n]{1,80}\\(logins\.json|key4\.db|cookies\.sqlite)/i ascii wide
        $decrypt    = /(CryptUnprotectData|ProtectedData\]?::?Unprotect|AesGcm|os_crypt|encrypted_key|PK11SDR_Decrypt|NSS_Init|sqlite3_open|Microsoft\.Data\.Sqlite|System\.Data\.SQLite)/i ascii wide
        $exfil      = /(api\.telegram\.org|discord(app)?\.com\/api\/webhooks|SmtpClient|UploadFile|UploadString|ftp:\/\/|Invoke-WebRequest|Net\.WebClient|HttpClient)/i ascii wide
        $exfil_pe   = /(api\.telegram\.org|discord(app)?\.com\/api\/webhooks|SmtpClient|UploadFile|UploadString|ftp:\/\/)/i ascii wide

    condition:
        filesize < 40MB
        and not uint32(0) == 0x464C457F
        and (
            ( $t_lazagne and ( $path_login or $decrypt ) )
            or $t_hbd
            or ( $t_sharp and ( $path_login or $decrypt ) )
            or ( $t_abe and $path_state )
            or ( not uint16(0) == 0x5A4D and ( $path_login or $ff_profile ) and $decrypt and $exfil )
            or ( uint16(0) == 0x5A4D and filesize < 15MB and $path_login and $path_state and $decrypt and $exfil_pe )
        )
}

/* -----------------------------------------------------------------------------
   CRED_HIGH_Hive_Theft_Command
   Commands that copy the credential hives out of the locked originals.
   ----------------------------------------------------------------------------- */
rule CRED_HIGH_Hive_Theft_Command
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "credential_access"
        severity    = "high"
        description = "reg save/export HKLM\\SAM|SYSTEM|SECURITY, shadow-copy path + config\\SAM|SYSTEM|SECURITY, esentutl /vss on hives, vssadmin/wmic/Win32_ShadowCopy/diskshadow next to a hive path, secretsdump -sam/-system/LOCAL, Invoke-PowerDump/Get-PassHashes/Invoke-NinjaCopy"
        mitre       = "T1003.002,T1003.004,T1006"

    strings:
        $reg_save    = /\breg(\.exe)?\s+(save|export)\s+["']?(HKLM|HKEY_LOCAL_MACHINE)\\\\?(SAM|SYSTEM|SECURITY)\b/i ascii wide
        $vss_copy    = /(HarddiskVolumeShadowCopy\d+|GLOBALROOT\\\\?Device)[^\r\n]{0,200}(System32\\\\?config\\\\?(SAM|SYSTEM|SECURITY)|NTDS\\\\?ntds\.dit)/i ascii wide
        $esentutl    = /\besentutl(\.exe)?\s+[^\r\n]{0,120}(System32\\\\?config\\\\?(SAM|SYSTEM|SECURITY)|\/vss)/i ascii wide
        $vssadmin    = /(vssadmin(\.exe)?\s+create\s+shadow|wmic(\.exe)?\s+shadowcopy\s+call\s+create|Win32_ShadowCopy[^\r\n]{0,80}Create|diskshadow(\.exe)?\s+\/s)/i ascii wide
        $hive_target = /System32\\\\?config\\\\?(SAM|SYSTEM|SECURITY)\b/i ascii wide
        $secretsdump = /secretsdump(\.py|\.exe)?\s+[^\r\n]{0,80}(-sam|-system|-security|-ntds|LOCAL)\b/i ascii wide
        $ps_dump     = /(Invoke-PowerDump|Get-PassHashes|Invoke-DCSync|Invoke-NinjaCopy)\b/i ascii wide

    condition:
        filesize < 10MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and ( $reg_save or $vss_copy or $esentutl or ( $vssadmin and $hive_target ) or $secretsdump or $ps_dump )
}
