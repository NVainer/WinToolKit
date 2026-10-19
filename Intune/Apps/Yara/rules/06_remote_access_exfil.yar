/* =============================================================================
   06_remote_access_exfil.yar
   -----------------------------------------------------------------------------
   Author : Nati
   Date   : 2026-10-14 (v3)
   Scope  : The "hands on keyboard" layer on a regular user's laptop: the RAT
            delivered by ClickFix/fake-update (NetSupport, commodity .NET RATs),
            remote-access tools installed by "IT support" scammers or by an
            intruder, tunnelling binaries that bypass the proxy, and the
            exfiltration plumbing (rclone, webhooks, bot tokens).

   TUNE: the RMM rule lists many vendors. Remove the branch for whatever your
   organisation actually uses, or filter by tool name in KQL.
   ============================================================================= */

/* -----------------------------------------------------------------------------
   RAT_HIGH_NetSupport_Manager_RAT
   NetSupport Manager repurposed as a RAT (fake browser updates, ClickFix).
   The client32.ini carries the attacker's gateway and licence.
   ----------------------------------------------------------------------------- */
rule RAT_HIGH_NetSupport_Manager_RAT
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "remote_access_tool"
        severity    = "high"
        description = "NetSupport client32.ini ([Client] + GatewayAddress/SecurityKey/Licensee/silent flags) or NetSupport client binaries (NetSupport Manager/Ltd + client32/PCICL32/TCCTL32/HTCTL32/remcmdstub)"
        mitre       = "T1219"
        reference   = "LevelBlue Threat Trends 2025: NetSupport RAT gaining traction"
        fp_notes    = "If NetSupport Manager is a licensed tool in your environment, scope this rule to paths outside Program Files in KQL."

    strings:
        $ini_client = /\[Client\]/ ascii wide
        $ini_gw     = /[\r\n]\s*GatewayAddress\s*=/ ascii wide
        $ini_key    = /[\r\n]\s*SecurityKey2?\s*=/ ascii wide
        $ini_lic    = /[\r\n]\s*Licensee\s*=/ ascii wide
        $ini_flag   = /[\r\n]\s*(silent|_present|SKMode|DisableChat|HideWhenIdle|quiet|DisableAudio|DisableMessage|DisableRequestHelp|DisableDisconnect)\s*=\s*1/i ascii wide
        $pe_nsm     = "NetSupport Manager" ascii wide nocase
        $pe_nsl     = "NetSupport Ltd"     ascii wide nocase
        $pe_cl32    = "client32"           ascii wide nocase
        $pe_mod     = /(remcmdstub|PCICL32|TCCTL32|HTCTL32|PCICHEK|NSM\.LIC)/i ascii wide

    condition:
        filesize < 20MB
        and (
            ( not uint16(0) == 0x5A4D and filesize < 200KB and $ini_client and 2 of ($ini_gw, $ini_key, $ini_lic, $ini_flag) )
            or ( uint16(0) == 0x5A4D and ( $pe_nsm or $pe_nsl ) and ( $pe_cl32 or $pe_mod ) )
        )
}

/* -----------------------------------------------------------------------------
   RAT_MEDHIGH_Commodity_RAT_Strings
   Unobfuscated builds of the RATs that follow ClickFix / cracked-software
   lures. 2-of-N per family. Packed/obfuscated builds are Defender's job.
   ----------------------------------------------------------------------------- */
rule RAT_MEDHIGH_Commodity_RAT_Strings
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "remote_access_tool"
        severity    = "medium-high"
        description = "PE with 2+ family-specific strings of Remcos, AsyncRAT, XWorm, DcRat, Quasar, NanoCore, VenomRAT or njRAT"
        mitre       = "T1219,T1071.001"
        reference   = "Sekoia / ditekSHen public rules for the .NET RAT family strings"

    strings:
        $rem1 = "Remcos"                 ascii wide
        $rem2 = "Breaking-Security.Net"  ascii wide
        $rem3 = "Remcos_Mutex_Inj"       ascii wide
        $rem4 = "licence_code.txt"       ascii wide

        $as1  = "AsyncRAT"               ascii wide
        $as2  = "get_SslClient"          ascii wide
        $as3  = "get_SendSync"           ascii wide
        $as4  = "Stub.exe"               ascii wide
        $as5  = "timeout 3 > NUL"        ascii wide

        $xw1  = "XWorm"                  ascii wide
        $xw2  = "StopDDos"               ascii wide
        $xw3  = "StopReport"             ascii wide
        $xw4  = "sendPlugin"             ascii wide
        $xw5  = "$VB$Local_Port"         ascii wide
        $xw6  = "Xwormmm"                ascii wide

        $dc1  = "DcRat"                  ascii wide
        $dc2  = "Pac_ket"                ascii wide
        $dc3  = "Po_ng"                  ascii wide
        $dc4  = "Install_ed"             ascii wide
        $dc5  = "qwqdanchun"             ascii wide

        $qs1  = "Quasar Client Startup"  ascii wide
        $qs2  = "QuasarRAT"              ascii wide
        $qs3  = "Quasar.Client"          ascii wide
        $qs4  = "Quasar.Common"          ascii wide
        $qs5  = "xClient.Core"           ascii wide
        $qs6  = "xClient.Config"         ascii wide

        $nc1  = "NanoCore"               ascii wide
        $nc2  = "ClientPluginHost"       ascii wide
        $nc3  = "NanoCore.ClientPlugin"  ascii wide
        $nc4  = "IClientNetworkHost"     ascii wide

        $vn1  = "VenomRAT"               ascii wide
        $vn2  = "Venom RAT"              ascii wide
        $vn3  = "VenomClient"            ascii wide

        $nj1  = "|'|'|"                  ascii wide
        $nj2  = "netsh firewall add allowedprogram" ascii wide
        $nj3  = "njRAT"                  ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 20MB
        and (
            2 of ($rem*) or 2 of ($as*) or 2 of ($xw*) or 2 of ($dc*)
            or 2 of ($qs*) or 2 of ($nc*) or 2 of ($vn*) or 2 of ($nj*)
        )
}

/* -----------------------------------------------------------------------------
   RMM_MED_Unsanctioned_Remote_Access_Tool
   Config artifacts (the tool was USED) and binaries (the tool is PRESENT) of
   remote-access products abused by tech-support scammers and intruders.
   ----------------------------------------------------------------------------- */
rule RMM_MED_Unsanctioned_Remote_Access_Tool
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "remote_access_tool"
        severity    = "medium"
        description = "AnyDesk conf lines (ad.anynet.*), RustDesk config (rendezvous/relay server + key), MeshAgent .msh (MeshServer=wss://), ScreenConnect client/relay parameters, or binaries of Atera, Splashtop, SimpleHelp, NinjaOne, Action1, Level, Syncro, Pulseway, Zoho Assist, LogMeIn Rescue/GoToAssist, Supremo, Ammyy, UltraVNC/TightVNC, RustDesk, AnyDesk"
        mitre       = "T1219,T1133"
        fp_notes    = "Delete the branch of your sanctioned RMM. Everything else on a regular user's device is either a scam session or an intruder's foothold."

    strings:
        $ad_cfg   = /[\r\n]ad\.(anynet|roster|security|features|session|ui)\.[a-z_\.]{2,40}\s*=/ ascii
        $ad_id    = /[\r\n]ad\.anynet\.(id|alias|pwd_hash|pwd_salt)\s*=/ ascii
        $rd_rz    = /[\r\n]\s*(rendezvous_server|custom-rendezvous-server|relay-server|api-server)\s*=\s*['"]/ ascii
        $rd_key   = /[\r\n]\s*(key|nat_type|serial|enc_id|password)\s*=/ ascii
        $mesh_srv = /MeshServer\s*=\s*wss?:\/\//i ascii
        $mesh_id  = /(MeshID|ServerID|MeshName|MeshType)\s*=/ ascii
        $sc_relay = /(\?e=Access&y=Guest|&h=[^&\s]{3,100}&p=\d{2,5}&k=|ClientLaunchParameters|relay\.screenconnect\.com|screenconnect\.com\/Bin)/i ascii wide

        // Binaries: product name AND a second vendor artifact (domain, service, company).
        // Single product names also live inside Windows' own DLLs (Defender's
        // ThreatAssessment, CapabilityAccessManager) and must not count alone.
        $ad_a     = "AnyDesk Software GmbH" ascii wide
        $ad_b     = /(anynet\.id|ad_svc\.trace|net\.anydesk\.com|AnyDesk\.exe)/ ascii wide
        $rd_a     = "RustDesk" ascii wide
        $rd_b     = /(rustdesk\.com|rendezvous_server|rs-ny\.rustdesk|RustDesk\.exe)/ ascii wide
        $mesh_a   = /(MeshAgent|MeshCentral)/ ascii wide
        $mesh_b   = /(meshagent\.msh|agent\.ashx|MeshServer=|meshcentral\.com)/ ascii wide
        $sc_a     = /ScreenConnect\.(Client|WindowsClient|ClientService|Windows\.Client|Service)/ ascii wide
        $sc_b     = /(screenconnect\.com|ConnectWise|ScreenConnect Software|\?e=Access&y=Guest)/ ascii wide
        $atera_a  = /(AteraAgent|AlphaControlAgent|AgentPackageSTRemote)/ ascii wide
        $atera_b  = /(atera\.com|Atera Networks)/ ascii wide
        $splash_a = /(SplashtopStreamer|Splashtop Remote|SRService\.exe)/ ascii wide
        $splash_b = /(splashtop\.com|Splashtop Inc)/ ascii wide
        $simple_a = /(JWrapper-Remote Access|SimpleHelp Technician|SimpleHelp Remote Access)/ ascii wide
        $simple_b = /(simple-help\.com|SimpleHelp Ltd)/ ascii wide
        $ninja_a  = "NinjaRMMAgent" ascii wide
        $ninja_b  = /(ninjarmm\.com|ninjaone\.com|NinjaOne)/ ascii wide
        $act1_a   = /(action1_agent|Action1 Agent)/ ascii wide
        $act1_b   = /(action1\.com|Action1 Corporation)/ ascii wide
        $level_a  = /(level-windows-amd64|LevelAgent\.exe)/ ascii wide
        $level_b  = "level.io" ascii wide
        $syncro_a = /(Syncro\.Service|SyncroLive)/ ascii wide
        $syncro_b = /(syncromsp\.com|Syncro Software)/ ascii wide
        $pulse_a  = "Pulseway" ascii wide
        $pulse_b  = /(PCMonitorSrv|pulseway\.com|MMSOFT Design)/ ascii wide
        $zoho_a   = /(ZohoMeeting|Zoho Assist|ZA_Access)/ ascii wide
        $zoho_b   = /(zohoassist\.com|assist\.zoho\.com|Zoho Corporation)/ ascii wide
        $lmi_a    = /(LogMeIn Rescue|LMIGuardianSvc|LMIRescue|GoToAssist Remote Support|GoTo Resolve)/ ascii wide
        $lmi_b    = /(logmein\.com|logmeinrescue\.com|LogMeIn, Inc|GoTo Technologies)/ ascii wide
        $supr_a   = /(Supremo Remote|SupremoService|SupremoHelper)/ ascii wide
        $supr_b   = /(nanosystems\.it|Nanosystems S\.r\.l)/ ascii wide
        $ammyy_a  = "Ammyy Admin" ascii wide
        $ammyy_b  = /(ammyy\.com|Ammyy LLC)/ ascii wide
        $vnc_a    = /(UltraVNC|TightVNC)/ ascii wide
        $vnc_b    = /(uvnc\.com|winvnc\.exe|tightvnc\.com|GlavSoft)/ ascii wide

    condition:
        filesize < 80MB
        and (
            ( not uint16(0) == 0x5A4D and ( #ad_cfg >= 2 or $ad_id or ( $rd_rz and $rd_key ) or ( $mesh_srv and $mesh_id ) or $sc_relay ) )
            or ( uint16(0) == 0x5A4D and (
                ( $ad_a and $ad_b ) or ( $rd_a and $rd_b ) or ( $mesh_a and $mesh_b ) or ( $sc_a and $sc_b )
                or ( $atera_a and $atera_b ) or ( $splash_a and $splash_b ) or ( $simple_a and $simple_b )
                or ( $ninja_a and $ninja_b ) or ( $act1_a and $act1_b ) or ( $level_a and $level_b )
                or ( $syncro_a and $syncro_b ) or ( $pulse_a and $pulse_b ) or ( $zoho_a and $zoho_b )
                or ( $lmi_a and $lmi_b ) or ( $supr_a and $supr_b ) or ( $ammyy_a and $ammyy_b )
                or ( $vnc_a and $vnc_b )
            ) )
        )
}

/* -----------------------------------------------------------------------------
   TUNNEL_MEDHIGH_Tunneling_Proxy_Tool
   Reverse tunnels and SOCKS proxies used to reach a victim laptop from the
   internet or to pivot through it.
   ----------------------------------------------------------------------------- */
rule TUNNEL_MEDHIGH_Tunneling_Proxy_Tool
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "command_and_control"
        severity    = "medium-high"
        description = "ngrok, cloudflared/trycloudflare, chisel, frp, ligolo-ng, bore, gost, rathole, revsocks, PowerShell SOCKS proxies, plink reverse tunnels, dnscat2, hosted tunnel services (localtonet, pinggy, serveo, localhost.run, loclx, playit, zrok)"
        mitre       = "T1572,T1090,T1090.001"
        fp_notes    = "cloudflared/ngrok are developer tools; a regular user has no reason to have them."

    strings:
        // Binaries: product/import-path markers (hostnames alone appear in every
        // public-suffix list and adblock list, so they are not used)
        $pe_ngrok   = /(connect\.ngrok-agent\.com|tunnel\.ngrok\.com|ngrok-agent|NGROK_AUTHTOKEN|ngrok\/ngrok)/ ascii wide
        $pe_cf      = /github\.com\/cloudflare\/cloudflared/ ascii wide
        $pe_chisel  = "jpillora/chisel" ascii wide
        $pe_frp     = "fatedier/frp" ascii wide
        $pe_ligolo  = /(ligolo-ng|nicocha30\/ligolo)/ ascii wide
        $pe_bore    = "ekzhang/bore" ascii wide
        $pe_gost    = /(ginuerzh\/gost|go-gost\/)/ ascii wide
        $pe_rathole = "rapiz1/rathole" ascii wide
        $pe_revsock = "kost/revsocks" ascii wide
        $pe_plink   = "PuTTY Link" ascii wide
        $pe_dnscat  = /(dnscat2|dns2tcp)/ ascii wide

        // Text: command lines and configs that actually start a tunnel
        // Real invocations carry a token or a local target; documentation carries placeholders.
        $cmd_ngrok  = /\bngrok(\.exe)?\s+((tcp|http|tls)\s+(\d{2,5}|localhost:\d{2,5}|127\.0\.0\.1:\d{2,5}|https?:\/\/localhost)|(authtoken|config\s+add-authtoken)\s+[A-Za-z0-9_]{20,})/i ascii wide
        $cmd_cf     = /\bcloudflared(\.exe)?\s+(tunnel\s+[^\r\n]{0,60}(run\s+--token\s+[A-Za-z0-9_\-\.=]{40,}|--url\s+(https?:\/\/)?(localhost|127\.0\.0\.1)|--hostname\s+[a-z0-9\.\-]{4,})|service\s+install\s+[A-Za-z0-9_\-\.=]{40,})/i ascii wide
        $cmd_chisel = /\bchisel(\.exe)?\s+(client|server)\s+[^\r\n]{0,80}(R:|socks|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})/i ascii wide
        $cfg_frp    = /\[common\][\s\S]{0,200}server_addr\s*=/ ascii wide
        $cmd_revsock= /\brevsocks(\.exe)?\s+-connect\s/i ascii wide
        $ps_socks   = /(Invoke-SocksProxy|Invoke-ReverseSocksProxy|Start-SocksProxy)/ ascii wide
        $cmd_plink  = /\bplink(\.exe)?\s+[^\r\n]{0,200}(-R\s+\d{2,5}:|-pw\s+\S+\s+[^\r\n]{0,80}-R\s)/i ascii wide
        $cmd_ssh_r  = /\bssh(\.exe)?\s+[^\r\n]{0,120}-R\s+\d{2,5}:(localhost|127\.0\.0\.1):\d{2,5}\s+[^\r\n]{0,80}(serveo\.net|localhost\.run|pinggy\.io|ngrok)/i ascii wide

    condition:
        filesize < 80MB
        and not uint32(0) == 0x464C457F
        and (
            ( uint16(0) == 0x5A4D and 1 of ($pe_*) )
            or ( not uint16(0) == 0x5A4D and ( 1 of ($cmd_*) or $cfg_frp or $ps_socks ) )
        )
}

/* -----------------------------------------------------------------------------
   EXFIL_HIGH_Rclone
   rclone is in nearly every ransomware playbook. Binary, config with a remote
   and credentials, or a copy/sync command to a remote.
   ----------------------------------------------------------------------------- */
rule EXFIL_HIGH_Rclone
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "exfiltration"
        severity    = "high"
        description = "rclone binary (rclone + rclone.org/github path/RCLONE_CONFIG), rclone.conf remote section with cloud backend type and credential line, or rclone copy/sync/move command to a remote"
        mitre       = "T1567.002,T1048"

    strings:
        $bin1    = "rclone" ascii wide nocase
        $bin2    = /(rclone\/rclone|rclone\.org|RCLONE_CONFIG|github\.com\/rclone|rclone\.conf)/i ascii wide
        $cfg_sec = /\[[^\]\r\n]{1,64}\][\s\r\n]{1,8}type\s*=\s*(mega|s3|b2|sftp|ftp|webdav|dropbox|drive|onedrive|azureblob|pcloud|box|swift|koofr|yandex|mailru|seafile|jottacloud|hidrive|internetarchive|storj|protondrive|filefabric|putio|opendrive|smb|union|crypt)\b/i ascii
        $cfg_crd = /[\r\n](pass|token|access_key_id|secret_access_key|key_file|client_secret|user|account)\s*=\s*\S/i ascii
        $cmd     = /\brclone(\.exe)?\s+(--[a-z\-]+\s+){0,4}(copy|sync|move|copyto|moveto)\s+["']?[A-Za-z]:\\[^\r\n]{0,200}\s["']?[A-Za-z0-9_\-]{1,40}:/i ascii wide

    condition:
        filesize < 100MB
        and (
            ( uint16(0) == 0x5A4D and $bin1 and $bin2 )
            or ( not uint16(0) == 0x5A4D and $cfg_sec and $cfg_crd )
            or ( not uint16(0) == 0x5A4D and $cmd )
        )
}

/* -----------------------------------------------------------------------------
   EXFIL_HIGH_Hardcoded_Webhook_Or_Bot_Token
   Infostealers and scripts ship their exfil channel as a literal.
   ----------------------------------------------------------------------------- */
rule EXFIL_HIGH_Hardcoded_Webhook_Or_Bot_Token
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        category    = "exfiltration,command_and_control"
        severity    = "high"
        description = "Complete Discord webhook URL (id + token) or Telegram bot token / bot sendDocument|sendMessage endpoint inside any file"
        mitre       = "T1567,T1102.002"
        fp_notes    = "A legitimate automation script with its own webhook is possible on an admin machine; on a regular user's device it is an exfil channel."

    strings:
        $discord  = /discord(app)?\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_\-]{60,}/ ascii wide
        $telegram = /api\.telegram\.org\/bot\d{8,12}:[A-Za-z0-9_\-]{30,}/ ascii wide
        $tg_send  = /api\.telegram\.org\/bot[^\r\n"'\s]{0,80}\/send(Document|Message|Photo)/ ascii wide

    condition:
        filesize < 60MB
        and not uint32(0) == 0x464C457F
        and any of them
}
