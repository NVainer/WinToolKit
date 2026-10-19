/* =============================================================================
   07_unwanted_tools.yar
   -----------------------------------------------------------------------------
   Author : Nati
   Date   : 2026-10-14 (v3)
   Scope  : Things a regular user should never have: Defender-killing
            utilities, activation cracks (the #1 infostealer lure), NirSoft
            password recovery tools, and the admin/recon/lateral tooling that
            an intruder drops on the first machine (PsExec, ProcDump, IP
            scanners, kernel-level process killers).
   ============================================================================= */

import "pe"

/* -----------------------------------------------------------------------------
   PUA_HIGH_Defender_Killer_Utility
   ----------------------------------------------------------------------------- */
rule PUA_HIGH_Defender_Killer_Utility
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "defense_evasion"
        severity    = "high"
        description = "Sordum Defender Control (dControl), defendnot / no-defender (fake WSC AV registration), Windows-Defender-Remover, ToggleDefender/DefenderSwitch scripts"
        mitre       = "T1562.001"

    strings:
        // Binaries: vendor domain/author AND product string. Single product names
        // also appear inside Windows' own ci.dll blocklist and in audio-driver
        // identifiers (SoundControl), so they never count alone.
        $sordum    = "sordum.org"       ascii wide nocase
        $dc1       = "Defender Control" ascii wide nocase
        $dc2       = "DefenderControl"  ascii wide nocase
        $dc3       = "dControl.exe"     ascii wide nocase
        $dn_a      = /(defendnot|no-defender)/ ascii wide
        $dn_b      = /(es3n1n|defendnot-loader|defendnot\.dll)/ ascii wide
        $rem_a     = /(Windows-Defender-Remover|DefenderRemover|Defender Remover)/ ascii wide
        $rem_b     = "ionuttbara" ascii wide
        // Text: the tool actually being invoked (filter lists and articles only name it)
        $cmd_dc    = /\bdControl(\.exe)?\s+\/[DE]\b/i ascii wide
        $cmd_other = /\b(defendnot(-loader)?(\.exe)?\s|defendnot\.dll|no-defender(\.exe)?\s|DefenderRemover\.exe|Defender\s*Remover\.exe|ToggleDefender\.(ps1|bat|cmd)|DefenderSwitch\.(ps1|bat|cmd)|DisableDefender\.(bat|cmd|ps1)|Disable-WindowsDefender\.ps1)/i ascii wide

    condition:
        filesize < 20MB
        and not uint32(0) == 0x464C457F
        and (
            ( uint16(0) == 0x5A4D and ( ( $sordum and 1 of ($dc*) ) or ( $dn_a and $dn_b ) or ( $rem_a and $rem_b ) ) )
            or ( not uint16(0) == 0x5A4D and ( $cmd_dc or $cmd_other ) )
        )
}

/* -----------------------------------------------------------------------------
   PUA_MED_KMS_Activator_Crack
   ----------------------------------------------------------------------------- */
rule PUA_MED_KMS_Activator_Crack
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "unwanted_software"
        severity    = "medium"
        description = "KMS/HWID activators and loaders (KMSAuto, KMSpico, AutoKMS, KMS_VL_ALL, MAS/massgrave, AAct/Ratiborus, Re-Loader, Windows Loader). Cracked-software bundles are the main infostealer delivery path for consumer-style users."
        mitre       = "T1204.002"

    strings:
        $kms      = /\b(KMSAuto|KMSpico|KMSPico|AutoKMS|KMS_VL_ALL|KMSELDI|KMSTools|KMS Pico|HEU KMS)\b/ ascii wide
        $act_ctx  = /(slmgr(\.vbs)?\s|\/skms\b|\/ato\b|\/ipk\b|KMSServer|KMS Server|ActivationID|ospp\.vbs|SppExtComObj|KMSEmulator|vlmcsd|KMS_VL_ALL|AutoRenewal)/i ascii wide
        $mas_site = "massgrave.dev" ascii wide nocase
        $mas_ctx  = /(Microsoft Activation Scripts|MAS_AIO|HWID Activation|Ohook Activation|KMS38|Online KMS Activation)/ ascii wide
        $mas_aio  = "MAS_AIO" ascii wide
        $other    = /(Ratiborus|AAct\.exe|AAct_x64\.exe|Re-Loader Activator|Windows Loader by Daz|W10 Digital Activation|Digital License Activation)/ ascii wide

    condition:
        filesize < 60MB
        and not uint32(0) == 0x464C457F
        and ( ( $kms and $act_ctx ) or $other or $mas_aio or ( $mas_site and $mas_ctx ) )
}

/* -----------------------------------------------------------------------------
   PUA_MED_NirSoft_Password_Tool
   ----------------------------------------------------------------------------- */
rule PUA_MED_NirSoft_Password_Tool
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "credential_access"
        severity    = "medium"
        description = "NirSoft credential/password recovery utility binary (nirsoft.net + a password-tool product name)"
        mitre       = "T1555,T1552"
        fp_notes    = "Legitimate for a helpdesk engineer on their own machine; not for a regular user."

    strings:
        $nir1 = "nirsoft.net" ascii wide nocase
        $nir2 = "NirSoft"     ascii wide
        $tool = /(PassView|ChromePass|Password Recovery|WirelessKeyView|Dialupass|BulletsPassView|PstPassword|RouterPassView|ProduKey|WebBrowserPassView|Mail PassView|Network Password Recovery|OperaPassView|SniffPass|PasswordFox|IE PassView|VNCPassView|RemoteDesktopPassView|LSASecretsView|CredentialsFileView|DataProtectionDecryptor|BrowserPasswordDecryptor|WebCookiesSniffer)/ ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and ( $nir1 or $nir2 )
        and $tool
}

/* -----------------------------------------------------------------------------
   PUA_MED_Admin_Recon_Lateral_Tool
   ----------------------------------------------------------------------------- */
rule PUA_MED_Admin_Recon_Lateral_Tool
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "discovery,lateral_movement"
        severity    = "medium"
        description = "PsExec/PAExec/RemCom, ProcDump, Advanced IP Scanner / Angry IP / SoftPerfect / Nmap, PCHunter / GMER / Process Hacker binaries; PsExec command lines to a remote host; 2+ remote PowerShell session commands in one script"
        mitre       = "T1569.002,T1046,T1021.006,T1562.001"
        fp_notes    = "Normal on IT staff machines. The target population here is regular users, where any of these is an intruder's toolkit."

    strings:
        // Sysinternals tools reference each other in their EULA/usage text (sysmon.exe
        // contains "PsExec"), so PsExec/PAExec/ProcDump are identified through their
        // own version resource (pe module) or the embedded PSEXESVC service name.
        $psexec2   = "PSEXESVC"     ascii wide nocase
        $remcom    = /(RemComSvc|RemCom_communicaton)/ ascii wide
        $ipscan    = /(Advanced IP Scanner|Famatech|Advanced Port Scanner)/ ascii wide
        $angry     = /(Angry IP Scanner|angryip\.org)/ ascii wide
        $softperf  = /(SoftPerfect Network Scanner|softperfect\.com)/ ascii wide
        $nmap      = /(nmap\.org|Nmap Security Scanner|Zenmap)/ ascii wide
        $pchunter  = /(PCHunter|Epoolsoft)/ ascii wide
        $gmer      = /(gmer\.net|GMER \d\.\d)/ ascii wide
        $prochack  = /(ProcessHacker|KProcessHacker|System Informer)/ ascii wide
        $psexec_cmd= /\bPsExec(64)?(\.exe)?\s+(-\w+\s+){0,4}\\\\[\w\.\-]{2,80}/i ascii wide

    condition:
        filesize < 60MB
        and not uint32(0) == 0x464C457F
        and (
            ( uint16(0) == 0x5A4D and (
                $psexec2 or $remcom
                or ( pe.is_pe and (
                    pe.version_info["InternalName"]     icontains "PsExec"
                    or pe.version_info["ProductName"]   icontains "PsExec"
                    or pe.version_info["OriginalFilename"] icontains "psexec"
                    or pe.version_info["InternalName"]  icontains "PAExec"
                    or pe.version_info["ProductName"]   icontains "PAExec"
                    or pe.version_info["InternalName"]  icontains "ProcDump"
                    or pe.version_info["ProductName"]   icontains "ProcDump"
                    or pe.version_info["OriginalFilename"] icontains "procdump"
                ) )
                or $ipscan or $angry or $softperf or $nmap or $pchunter or $gmer or $prochack
            ) )
            or ( not uint16(0) == 0x5A4D and $psexec_cmd )
        )
}
