/* =============================================================================
   04_known_offensive_tools.yar
   -----------------------------------------------------------------------------
   Author : Nati
   Date   : 2026-10-14 (v3)
   Scope  : Tooling that has exactly one reason to be on a regular user's
            laptop. Matched by self-identifying strings (tool names, Go import
            paths, .NET namespaces, command verbs) with a 2-of-N or
            name+argument bind so a blog post quoting a tool name cannot fire.

   Dropped from v2: Havoc and Brute Ratel string rules. Both implants hash
   their API names and ship no stable plaintext markers; the old strings were
   guesses. PrintNightmare / SpoolFool / PetitPotam / RBCD / DCSync /
   ADCS: domain-controller era tooling with nothing to attack on a cloud-joined
   workstation. Impacket, Rubeus, SharpHound, NetExec are kept in one compact
   rule because attackers still drop them on the first box they land on.
   ============================================================================= */

import "pe"

/* -----------------------------------------------------------------------------
   TOOL_HIGH_CobaltStrike_Beacon
   ----------------------------------------------------------------------------- */
rule TOOL_HIGH_CobaltStrike_Beacon
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "c2_implant"
        severity    = "high"
        description = "Cobalt Strike beacon: 2+ beacon-specific format strings / DLL names / pipe names inside a PE, or a stageless beacon's default pipe name next to ReflectiveLoader"
        mitre       = "T1071.001,T1055"

    strings:
        $s_dll1   = "beacon.dll"      ascii wide
        $s_dll2   = "beacon.x64.dll"  ascii wide
        $s_runas  = "%s as %s\\%s: %d" ascii wide
        $s_spawn  = "could not spawn %s: %d" ascii wide
        $s_spawn2 = "could not spawn %s (token): %d" ascii wide
        $s_x64    = "%d is an x64 process (can't inject x86 content)" ascii wide
        $s_x86    = "%d is an x86 process (can't inject x64 content)" ascii wide
        $s_ps     = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')" ascii wide
        $s_ps2    = "powershell -nop -exec bypass -EncodedCommand \"%s\"" ascii wide
        $s_imp    = "%%IMPORT%%" ascii wide
        $s_pipe   = "Could not connect to pipe (%s): %d" ascii wide
        $s_tok    = "Failed to impersonate token from %d (%u)" ascii wide
        $s_ppid   = "ppid %d is in a different desktop session" ascii wide
        $s_art    = "%s.4%08x%08x%08x%08x%08x.%s" ascii wide
        $s_refl   = "ReflectiveLoader" ascii wide
        $pipe_def = /\\\\\.\\pipe\\(MSSE-\d{1,4}-server|postex_[0-9a-f]{4}|postex_ssh_[0-9a-f]{4}|msagent_[0-9a-f]{2,4}|status_[0-9a-f]{2,4}|mojo\.5688\.8052\.\d+)/ ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 50MB
        and (
            2 of ($s_*)
            or ( $pipe_def and $s_refl )
        )
}

/* -----------------------------------------------------------------------------
   TOOL_HIGH_Sliver_Implant
   ----------------------------------------------------------------------------- */
rule TOOL_HIGH_Sliver_Implant
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "c2_implant"
        severity    = "high"
        description = "Sliver (BishopFox) implant: 2+ Go package paths / protobuf names in a PE"
        mitre       = "T1071,T1573"

    strings:
        $s1 = "sliverpb"                     ascii wide
        $s2 = "bishopfox/sliver"             ascii wide
        $s3 = "sliver/implant"               ascii wide
        $s4 = "sliver/protobuf"              ascii wide
        $s5 = "github.com/bishopfox/sliver"  ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 60MB and 2 of them
}

/* -----------------------------------------------------------------------------
   TOOL_HIGH_Metasploit_Meterpreter
   ----------------------------------------------------------------------------- */
rule TOOL_HIGH_Metasploit_Meterpreter
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "c2_implant"
        severity    = "high"
        description = "Meterpreter: metsrv / extension server names / stdapi command strings inside a PE (2+), or msfvenom reverse stager prologue bytes in any file under 20 MB"
        mitre       = "T1071,T1055"

    strings:
        $m1 = "metsrv.dll"          ascii wide
        $m2 = "metsrv.x64.dll"      ascii wide
        $m3 = "ext_server_stdapi"   ascii wide
        $m4 = "ext_server_priv"     ascii wide
        $m5 = "ext_server_kiwi"     ascii wide
        $m6 = "stdapi_sys_process_execute" ascii wide
        $m7 = "core_channel_open"   ascii wide
        $m8 = "MeterpreterShell"    ascii wide
        $m9 = "metsrv"              ascii wide
        $sc_x86 = { FC E8 8? 00 00 00 60 89 E5 31 C0 64 8B 50 30 8B 52 0C 8B 52 14 8B 72 28 }
        $sc_x64 = { FC 48 83 E4 F0 E8 ?? ?? ?? ?? 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 60 }

    condition:
        filesize < 20MB
        and (
            ( uint16(0) == 0x5A4D and 2 of ($m*) )
            or $sc_x86 or $sc_x64
        )
}

/* -----------------------------------------------------------------------------
   TOOL_HIGH_Offensive_PowerShell_Framework
   PowerSploit / Empire / Nishang / PowerView / PowerUp / Inveigh / PowerSharpPack
   function definitions or 2+ invocations in one file.
   ----------------------------------------------------------------------------- */
rule TOOL_HIGH_Offensive_PowerShell_Framework
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "offensive_tool"
        severity    = "high"
        description = "Definition of a known offensive PowerShell function (PowerSploit, Empire, Nishang, PowerView, PowerUp, Inveigh, PowerSharpPack, PrivescCheck) or 2+ distinct invocations of them"
        mitre       = "T1059.001,T1087,T1003"
        fp_notes    = "Detection-engineering content (KQL/Sigma files) lists these names; such files belong on analyst machines only."

    strings:
        $def = /function\s+(Invoke-Mimikatz|Invoke-PowerShellTcp|Invoke-PowerShellUdp|Invoke-Shellcode|Invoke-ReflectivePEInjection|Invoke-DllInjection|Invoke-TokenManipulation|Invoke-NinjaCopy|Invoke-WmiCommand|Get-Keystrokes|Get-GPPPassword|Invoke-AllChecks|Invoke-PrivescAudit|Get-ServiceUnquoted|Write-HijackDll|Find-PathDLLHijack|Invoke-ServiceAbuse|Get-DomainUser|Get-NetUser|Get-NetSession|Invoke-UserHunter|Invoke-ShareFinder|Find-LocalAdminAccess|Invoke-Kerberoast|Get-DomainSPNTicket|Invoke-Inveigh|Invoke-InveighRelay|Invoke-TheHash|Invoke-SMBExec|Invoke-WMIExec|Invoke-SMBClient|Invoke-PSInject|Invoke-BloodHound|Invoke-SharpHound|Invoke-Seatbelt|Invoke-Rubeus|Invoke-Certify|Invoke-SafetyKatz|Invoke-SharpUp|Invoke-PowerDump|Invoke-Phant0m|Invoke-ConPtyShell|Invoke-WinEnum|Invoke-PrivescCheck|Invoke-SharpLoader|Invoke-Empire|Invoke-PoshC2|Get-System|Invoke-PsExec|Invoke-CredentialInjection|Out-Minidump|Invoke-Portscan|Get-MicrophoneAudio|Get-TimedScreenshot|Invoke-EgressCheck|Invoke-EventVwrBypass|Invoke-FodhelperBypass|Invoke-SluiBypass|powercat)\b/i ascii wide
        $use = /\b(Invoke-Mimikatz|Invoke-PowerShellTcp|Invoke-Shellcode|Invoke-ReflectivePEInjection|Invoke-TokenManipulation|Invoke-NinjaCopy|Get-Keystrokes|Get-GPPPassword|Invoke-AllChecks|Invoke-PrivescAudit|Get-ServiceUnquoted|Invoke-ServiceAbuse|Get-DomainUser|Get-NetUser|Get-NetSession|Invoke-UserHunter|Invoke-ShareFinder|Find-LocalAdminAccess|Invoke-Kerberoast|Invoke-Inveigh|Invoke-TheHash|Invoke-SMBExec|Invoke-WMIExec|Invoke-PSInject|Invoke-BloodHound|Invoke-SharpHound|Invoke-Seatbelt|Invoke-Rubeus|Invoke-Certify|Invoke-SafetyKatz|Invoke-SharpUp|Invoke-PowerDump|Invoke-Phant0m|Invoke-ConPtyShell|Invoke-PrivescCheck|Invoke-EventVwrBypass|Invoke-FodhelperBypass|Invoke-SluiBypass|Get-System\s+-Technique)\b/i ascii wide

    condition:
        filesize < 10MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and ( $def or #use >= 2 )
}

/* -----------------------------------------------------------------------------
   TOOL_HIGH_AD_Attack_Toolkit
   Compiled or scripted AD/lateral-movement tooling: Rubeus, SharpHound,
   Seatbelt, Certify, Impacket (PyInstaller exes carry the package name),
   NetExec/CrackMapExec, Kerbrute, KrbRelayUp, Whisker, plus pass-the-hash
   command shapes.
   ----------------------------------------------------------------------------- */
rule TOOL_HIGH_AD_Attack_Toolkit
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "offensive_tool,lateral_movement"
        severity    = "high"
        description = "Rubeus + Kerberos verb, SharpHound/AzureHound + CollectionMethod, Seatbelt/Certify/Whisker + GhostPack, impacket + example-script names, NetExec/CrackMapExec invocation, kerbrute/KrbRelayUp/SharpRDP/SharpWMI names, --hashes LM:NT pass-the-hash shape"
        mitre       = "T1558,T1087.002,T1550.002,T1021"

    strings:
        $rubeus      = "Rubeus" ascii wide
        $rubeus_verb = /\b(asktgt|asktgs|kerberoast|asreproast|s4u|ptt|tgtdeleg|monitor|harvest|dump|triage|klist|renew|golden|silver|diamond|brute|changepw|createnetonly)\b[^\r\n]{0,120}\/(user|domain|rc4|aes256|aes128|ticket|password|spn|impersonateuser|nowrap|luid|outfile|dc|format|service):/i ascii wide
        $ghostpack   = "GhostPack" ascii wide
        $sharphound  = /SharpHound(\.exe|\.ps1)?/ ascii wide
        $azurehound  = "azurehound" ascii wide nocase
        $collection  = /(-|--)CollectionMethods?\s+(All|Default|DCOnly|Group|LocalGroup|Session|LoggedOn|Trusts|ACL|ObjectProps|SPNTargets|UserRights|CARegistry|DCRegistry|CertServices)/i ascii wide
        $bh_zip      = /\d{14}_BloodHound\.zip/ ascii wide
        $seatbelt    = "Seatbelt" ascii wide
        $certify     = /\bCertify(\.exe)?\s+(find|request|cas|download|pkiobjects)\b/i ascii wide
        $certipy     = /\bcertipy(-ad)?(\.exe|\.py)?\s+(find|req|auth|relay|shadow|ca|account|template|forge|ptt)\b/i ascii wide
        $whisker     = /\bWhisker(\.exe)?\s+(add|list|remove|clear)\b/i ascii wide
        $impacket    = "impacket" ascii wide nocase
        $impacket_ex = /(\b(secretsdump|wmiexec|smbexec|dcomexec|atexec|ntlmrelayx|GetUserSPNs|GetNPUsers|ticketer|lookupsid|samrdump|getTGT|getST|rpcdump|findDelegation)\b|\bpsexec\.(py|exe)\b)/ ascii wide
        $nxc         = /\b(nxc|netexec|crackmapexec|cme)(\.exe|\.py)?\s+(smb|winrm|ldap|rdp|mssql|ssh|ftp|wmi|vnc)\s+[^\r\n]{3,200}(-u\s|--username|-p\s|--password|-H\s|--hashes|-M\s|--continue-on-success|--shares|--sam|--lsa|--ntds)/i ascii wide
        $other_tools = /\b(kerbrute|KrbRelayUp|KrbRelay|SharpRDP|SharpWMI|SharpSecDump|SharpKatz|SharpSpray|DomainPasswordSpray|Invoke-SMBAutoBrute|PowerUpSQL|SharpSQL|ADRecon\.ps1|Snaffler|Group3r|SharpGPOAbuse|PetitPotam|Coercer|SpoolSample)\b/ ascii wide
        $pth         = /(--hashes\s+[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b|\s-H\s+[a-fA-F0-9]{32}\b|\/rc4:[a-fA-F0-9]{32}\b|\/ntlm:[a-fA-F0-9]{32}\b)/ ascii wide

    condition:
        filesize < 60MB
        and not uint32(0) == 0x464C457F
        and (
            ( $rubeus and ( $rubeus_verb or $ghostpack ) )
            or ( ( $sharphound or $azurehound ) and ( $collection or $ghostpack or $bh_zip ) )
            or ( $seatbelt and $ghostpack )
            or $certify or $certipy or $whisker
            or ( $impacket and $impacket_ex )
            or $nxc
            or ( $other_tools and ( uint16(0) == 0x5A4D or $pth or $impacket or $ghostpack ) )
            or ( $pth and ( $impacket_ex or $rubeus or $nxc ) )
        )
}

/* -----------------------------------------------------------------------------
   TOOL_HIGH_Entra_Attack_Toolkit
   Identity attack tooling for an Entra-only tenant: AADInternals, ROADtools,
   TokenTactics, GraphRunner, TeamFiltration, MSOLSpray, EvilTokens/TokenSmith,
   PRT and token-cache theft, scripted device-code flows.
   ----------------------------------------------------------------------------- */
rule TOOL_HIGH_Entra_Attack_Toolkit
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "cloud_identity,credential_access"
        severity    = "high"
        description = "AADInternals, ROADtools (roadrecon/roadtx/.roadtools_auth), TokenTactics Invoke-RefreshTo*Token, GraphRunner, TeamFiltration, MSOLSpray/o365spray, TokenSmith/EvilTokens, PRT theft (Get-AADIntUserPRTToken/ROADtoken/RequestAADRefreshToken+BrowserCore), WAM/OneAuth token-cache copying, PowerShell device-code flow against login.microsoftonline.com"
        mitre       = "T1528,T1078.004,T1606,T1539"
        fp_notes    = "AADInternals is also used by Entra admins for legitimate troubleshooting. On a regular user's device it is not."

    strings:
        $aadint      = /\b(AADInternals|Get-AADInt[A-Za-z]{3,40}|Export-AADInt[A-Za-z]{3,40}|Invoke-AADInt[A-Za-z]{3,40})\b/ ascii wide
        $road1       = "roadrecon"       ascii wide nocase
        $road2       = "roadtx"          ascii wide nocase
        $road3       = "roadtools_auth"  ascii wide nocase
        $road4       = "ROADtools"       ascii wide
        $road5       = "roadlib"         ascii wide nocase
        $tt_fn       = /Invoke-RefreshTo(MSGraph|AzureManagement|Teams|OfficeManagement|OfficeApps|Outlook|OneDrive|SharePoint|Yammer|Intune|Family|AzureCoreManagement|DODMSGraph|MAM|Substrate|Graph|Office)Token\b/i ascii wide
        $tt_name     = "TokenTactics" ascii wide
        $graphrunner = /(Invoke-GraphRunner|Get-GraphTokens|Invoke-SearchMailbox|Invoke-SearchSharePointAndOneDrive|Invoke-DumpApps|Invoke-InjectOAuthApp|Invoke-ImmersiveFileReader|GraphRunner\.ps1)\b/ ascii wide
        $teamfilt    = "TeamFiltration" ascii wide
        $spray       = /\b(Invoke-MSOLSpray|o365spray|MSOLSpray|Invoke-AzureAdPasswordSprayAttack|TREVORspray|Oh365UserFinder)\b/ ascii wide
        $tokensmith  = /\b(TokenSmith|Get-TokenSmithToken|EvilTokens|eviltokens\.py)\b/ ascii wide
        $prt_tool    = /(Get-AADIntUserPRTToken|ROADtoken\b|RequestAADRefreshToken[\s\S]{0,300}BrowserCore|BrowserCore(\.exe)?[\s\S]{0,300}RequestAADRefreshToken)/ ascii wide
        $prt_theft   = /(sekurlsa::cloudap|dpapi::cloudapkd|x-ms-RefreshTokenCredential[\s\S]{0,200}(Invoke-WebRequest|Invoke-RestMethod|curl))/i ascii wide
        $cache_theft = /(\\Microsoft\\TokenBroker\\Cache\\|\\Microsoft\\OneAuth\\|\\Microsoft\\IdentityCache\\|\.tbres\b|msal_token_cache\.bin)[^\r\n]{0,200}(Copy-Item|ReadAllBytes|Compress-Archive|robocopy|xcopy|CryptUnprotectData|Unprotect|UploadFile|Invoke-WebRequest|Invoke-RestMethod)/i ascii wide
        $devicecode  = /(Invoke-RestMethod|Invoke-WebRequest|\birm\b|\biwr\b|curl)[^\r\n]{0,200}login\.microsoftonline\.com\/(common|organizations|consumers|[0-9a-f-]{36})\/oauth2(\/v2\.0)?\/devicecode/i ascii wide

    condition:
        filesize < 30MB
        and not uint32(0) == 0x464C457F
        and (
            $aadint
            or 2 of ($road*)
            or ( #tt_fn >= 1 and ( #tt_fn >= 2 or $tt_name ) )
            or $graphrunner
            or $teamfilt
            or $spray
            or $tokensmith
            or $prt_tool
            or $prt_theft
            or $cache_theft
            or $devicecode
        )
}

/* -----------------------------------------------------------------------------
   TOOL_HIGH_Potato_LPE_Family
   Local privilege escalation PoCs that get dropped right after initial access.
   ----------------------------------------------------------------------------- */
rule TOOL_HIGH_Potato_LPE_Family
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "privilege_escalation"
        severity    = "high"
        description = "Potato family / PrintSpoofer / KrbRelayUp name inside a PE or next to its command-line arguments or impersonation primitives"
        mitre       = "T1134.001,T1068"

    strings:
        $name = /\b(JuicyPotato(NG)?|PrintSpoofer(64|32)?|GodPotato|SweetPotato|RoguePotato|SigmaPotato|EfsPotato|SharpEfsPotato|CoercedPotato|RemotePotato0?|MultiPotato|DeadPotato|BadPotato|LocalPotato|RasmanPotato|KrbRelayUp|PrintNotifyPotato|GenericPotato)\b/ ascii wide
        $args = /(\s-c\s+["']?(cmd|powershell|whoami|net\s)|\s-cmd\s+["']|\s-p\s+["']?[A-Za-z]:\\|\s-t\s+[tu\*]\s|\s-l\s+\d{2,5}\b|\s-r\s+\d{1,3}\.\d{1,3}|\s-e\s+["']?cmd|\s-i\s+-c\s)/i ascii wide
        $prim = /(SeImpersonatePrivilege|ImpersonateNamedPipeClient|CoGetInstanceFromIStorage|RpcImpersonateClient|CreateProcessWithTokenW|CreateProcessAsUser|IStorageTrigger|OXIDResolver)/ ascii wide

    condition:
        filesize < 20MB
        and not uint32(0) == 0x464C457F
        and $name
        and ( uint16(0) == 0x5A4D or $args or $prim )
}

/* -----------------------------------------------------------------------------
   TOOL_MEDHIGH_Vulnerable_Driver_BYOVD
   Signed-but-exploitable drivers that EDR killers (Terminator, AuKill,
   EDRSandBlast, BlackByte, RansomHub...) bring with them. Matched on the
   driver's own OriginalFilename (UTF-16 in VS_VERSION_INFO) plus a kernel
   import, so a user-mode blocklist DLL naming them cannot fire.
   ----------------------------------------------------------------------------- */
rule TOOL_MEDHIGH_Vulnerable_Driver_BYOVD
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "defense_evasion,privilege_escalation"
        severity    = "medium-high"
        description = "PE kernel driver whose OriginalFilename is one of the drivers most abused for EDR killing (RTCore64, DBUtil, zam64/zamguard, truesight, gdrv, iqvw64e, aswArPot, kprocesshacker, PROCEXP152, AsIO, MsIo64, viragt64, WinRing0, mhyprot2, TfSysMon, HW, wnbios64, ElbyCDIO, amsdk, PdFwKrnl, DBUtilDrv2)"
        mitre       = "T1068,T1562.001,T1014"
        reference   = "loldrivers.io ; ESET 2026 EDR-killer survey (54 killers / 35 drivers)"
        fp_notes    = "RTCore64 ships with MSI Afterburner, WinRing0 with hardware monitors, PROCEXP152 is dropped by Process Explorer, mhyprot2 by Genshin Impact. Any of these on a corporate laptop still deserves a look; outside Program Files it is an attack."

    condition:
        uint16(0) == 0x5A4D
        and filesize < 3MB
        and pe.is_pe
        and pe.subsystem == pe.SUBSYSTEM_NATIVE
        and (
            pe.version_info["OriginalFilename"] iequals "RTCore64.sys"
            or pe.version_info["OriginalFilename"] iequals "DBUtil_2_3.sys"
            or pe.version_info["OriginalFilename"] iequals "DBUtilDrv2.sys"
            or pe.version_info["OriginalFilename"] iequals "zam64.sys"
            or pe.version_info["OriginalFilename"] iequals "zamguard64.sys"
            or pe.version_info["OriginalFilename"] iequals "truesight.sys"
            or pe.version_info["OriginalFilename"] iequals "gdrv.sys"
            or pe.version_info["OriginalFilename"] iequals "iqvw64e.sys"
            or pe.version_info["OriginalFilename"] iequals "aswArPot.sys"
            or pe.version_info["OriginalFilename"] iequals "kprocesshacker.sys"
            or pe.version_info["OriginalFilename"] iequals "PROCEXP152.sys"
            or pe.version_info["OriginalFilename"] iequals "AsIO3.sys"
            or pe.version_info["OriginalFilename"] iequals "AsIO2.sys"
            or pe.version_info["OriginalFilename"] iequals "MsIo64.sys"
            or pe.version_info["OriginalFilename"] iequals "viragt64.sys"
            or pe.version_info["OriginalFilename"] iequals "WinRing0x64.sys"
            or pe.version_info["OriginalFilename"] iequals "mhyprot2.sys"
            or pe.version_info["OriginalFilename"] iequals "TfSysMon.sys"
            or pe.version_info["OriginalFilename"] iequals "HW.sys"
            or pe.version_info["OriginalFilename"] iequals "wnbios64.sys"
            or pe.version_info["OriginalFilename"] iequals "ElbyCDIO.sys"
            or pe.version_info["OriginalFilename"] iequals "amsdk.sys"
            or pe.version_info["OriginalFilename"] iequals "PdFwKrnl.sys"
            or pe.version_info["OriginalFilename"] iequals "ene.sys"
            or pe.version_info["OriginalFilename"] iequals "EneTechIo64.sys"
            or pe.version_info["OriginalFilename"] iequals "smuol.sys"
        )
}
