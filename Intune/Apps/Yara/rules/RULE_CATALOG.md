# YARA Rule Catalog — what each rule catches and what a hit means

Ruleset v3 (2026-10-14). 49 detection rules in 7 files plus 2 global filters.
Target: Intune-managed, Entra-joined Windows 11 endpoints with regular (non-admin, non-developer) users.

## How to read severity

| Group | Meaning of a hit | First action |
|---|---|---|
| Credentials and known tooling (files 03, 04) | Assume the device and the user's credentials are compromised | Reset the user's credentials and revoke sessions, then investigate |
| Initial access and execution (files 01, 02) | A malicious file reached the disk | Answer "did it run?" from MDE process events |
| Persistence, remote access, unwanted software (files 05, 06, 07) | Cleanup plus a conversation with the user | Escalate only if it co-occurs with the first two groups |

## Global filters (file 00)

| Rule | What it does |
|---|---|
| SKIP_OWN_SCAN_ARTIFACTS | Ignores the scanner's own compiled rules and JSON output, including cached or emailed copies |
| SKIP_SYSTEM_DATASTORES | Ignores ESE and SQLite databases, event logs, Outlook PST/OST, prefetch and registry hives — except readable copies of SAM/SYSTEM/SECURITY, which are let through on purpose |

## Initial access (file 01)

| Rule | Catches | Impact when it fires |
|---|---|---|
| IA_HIGH_LNK_ScriptHost_Payload | Shortcut files that launch PowerShell/mshta/wscript with a URL, encoded command or hidden window | Phishing attachment reached the disk; the user may have clicked it |
| IA_HIGH_HTA_Dropper | HTML applications that spawn a shell | Same as above, HTA variant |
| IA_HIGH_Script_Dropper_XMLHTTP_ADODB | VBS/JS that download, write and run a file | First-stage dropper on disk; look for the second stage |
| IA_HIGH_ClickFix_Lure | Fake CAPTCHA pages that copy a command to the clipboard, and the pasted command itself | The #2 attack vector of 2025; if the command exists, the user probably ran it |
| IA_HIGH_Embedded_Base64_Executable | An EXE/DLL base64-wrapped inside a text, script or HTML file | Smuggled binary; treat as malware delivery |
| IA_MEDHIGH_HTML_Smuggling_Download | HTML that rebuilds a zip/script client-side and forces a download | Phishing page delivered a payload past mail filters |
| IA_MED_SVG_Script_Smuggling | Standalone SVG with script and redirect/decode logic | Phishing attachment, usually credential theft |
| IA_MED_Office_Macro_AutoExec_Payload | Legacy Office files with an auto-running macro and shell/download code | Macro document; blocked by default, still worth knowing who received it |
| IA_MEDHIGH_RTF_Equation_Editor_Exploit | RTF carrying an Equation Editor object | Exploit document; patched since 2018 but still used |
| IA_MEDHIGH_OneNote_Embedded_Script | OneNote file with an embedded executable, shortcut or script | Phishing lure |

## PowerShell and LOLBAS (file 02)

| Rule | Catches | Impact when it fires |
|---|---|---|
| PS_HIGH_Download_Cradle_IEX | PowerShell that downloads code and runs it in memory | Hands-on attacker or ClickFix payload; high confidence |
| PS_HIGH_EncodedCommand_Malicious_Payload | Encoded PowerShell whose decoded content contains download/exec/evasion markers | Attacker command line stored in a task, shortcut or script |
| RS_HIGH_PS_TCPClient_Stream_IEX_Loop | PowerShell reverse shell | Interactive access by an attacker |
| PS_HIGH_AMSI_Bypass | Script disabling Defender's script-scanning interface | Attacker preparing to run malware undetected |
| PS_HIGH_Defender_Tamper | Commands turning Defender off, adding exclusions, killing its services | Active defense evasion; isolate and check Defender state |
| PS_MED_Logging_ETW_Tamper | Disabling PowerShell logging, ETW, clearing event logs | Anti-forensics; evidence may already be gone |
| PS_MEDHIGH_Reflective_Load_InMemory | Loading .NET assemblies or shellcode in memory | Fileless stage-2; MDE memory telemetry is the next pivot |
| PS_MED_Obfuscated_PowerShell | Scrambled PowerShell bound to an execution sink | Someone hiding what a script does |
| PS_HIGH_Stealth_Flags_Remote_Payload | Hidden-window launchers with a remote or encoded payload | The launcher of a malicious chain |
| LOL_HIGH_LOLBAS_Download_Execute | certutil, bitsadmin, mshta, regsvr32, rundll32, msiexec, curl used to fetch or run code | Living-off-the-land execution; check the URL host |

## Credential access (file 03)

| Rule | Catches | Impact when it fires |
|---|---|---|
| CRED_HIGH_LSASS_Minidump_On_Disk | A memory dump of the LSASS process | Every credential on that machine is compromised; reset and revoke |
| CRED_HIGH_Registry_Hive_Copy_SAM_SYSTEM_SECURITY | Readable copies of the credential hives | Local account hashes and secrets taken; same response |
| CRED_HIGH_Kerberos_Ticket_File | Exported Kerberos tickets | Ticket theft for lateral movement |
| CRED_HIGH_Dumped_Credentials_Text | Output files of credential dumpers and stealers | Credentials already harvested on this device |
| CRED_HIGH_Mimikatz | The tool, its wrapper or its commands | Credential-theft tooling present |
| CRED_HIGH_LSASS_Dump_Command | Commands and tools that create LSASS dumps | Attempted or completed credential theft |
| CRED_HIGH_Browser_Credential_Theft_Tool | Tools and scripts that decrypt browser password stores | Infostealer core; browser-saved passwords exposed |
| CRED_HIGH_Hive_Theft_Command | Commands that copy credential hives | Attempted credential theft |

## Known offensive tools (file 04)

| Rule | Catches | Impact when it fires |
|---|---|---|
| TOOL_HIGH_CobaltStrike_Beacon | Cobalt Strike implant | Professional intrusion in progress |
| TOOL_HIGH_Sliver_Implant | Sliver implant | Same |
| TOOL_HIGH_Metasploit_Meterpreter | Meterpreter payloads or stagers | Same, or a pentest you did not authorize |
| TOOL_HIGH_Offensive_PowerShell_Framework | PowerSploit, Empire, Nishang, PowerView function sets | Attacker toolkit staged on the device |
| TOOL_HIGH_AD_Attack_Toolkit | Rubeus, SharpHound, Impacket, NetExec and friends | Lateral-movement toolkit, usually dropped right after initial access |
| TOOL_HIGH_Entra_Attack_Toolkit | AADInternals, ROADtools, TokenTactics, GraphRunner, token-cache theft | Your Entra tenant is the target; check sign-in logs for that user |
| TOOL_HIGH_Potato_LPE_Family | Local privilege-escalation exploits | Attacker trying to become SYSTEM |
| TOOL_MEDHIGH_Vulnerable_Driver_BYOVD | Signed drivers abused to kill EDR | Ransomware precursor; verify the vendor install |

## Persistence (file 05)

| Rule | Catches | Impact when it fires |
|---|---|---|
| PERSIST_HIGH_ScheduledTask_Suspicious | Tasks launching script hosts with remote/encoded/hidden payloads | Attacker survives reboot; remove after understanding the entry point |
| PERSIST_HIGH_WMI_Event_Subscription | WMI subscriptions with command or script consumers | Stealthy persistence, rarely used legitimately |
| PERSIST_MEDHIGH_Script_Autorun_Write | Scripts writing Run keys, services or Startup items with payloads | Persistence being installed |

## Remote access and exfiltration (file 06)

| Rule | Catches | Impact when it fires |
|---|---|---|
| RAT_HIGH_NetSupport_Manager_RAT | NetSupport configured as a remote access trojan | Full remote control by a third party |
| RAT_MEDHIGH_Commodity_RAT_Strings | Remcos, AsyncRAT, XWorm, DcRat, Quasar, NanoCore, VenomRAT, njRAT | Same, commodity malware |
| RMM_MED_Unsanctioned_Remote_Access_Tool | AnyDesk, RustDesk, MeshAgent, ScreenConnect and other RMM artifacts | Tech-support scam session or intruder foothold; ask the user who installed it |
| TUNNEL_MEDHIGH_Tunneling_Proxy_Tool | ngrok, cloudflared, chisel, frp, ligolo, SOCKS proxies | Device is reachable from the internet behind your proxy |
| EXFIL_HIGH_Rclone | rclone binary, config or sync command | Data exfiltration staging; standard ransomware step |
| EXFIL_HIGH_Hardcoded_Webhook_Or_Bot_Token | Discord webhooks and Telegram bot tokens in files | Infostealer exfil channel; the data already left or is about to |

## Unwanted tools (file 07)

| Rule | Catches | Impact when it fires |
|---|---|---|
| PUA_HIGH_Defender_Killer_Utility | Defender Control, defendnot and similar | User or malware disabling protection |
| PUA_MED_KMS_Activator_Crack | Activators and cracks | Policy violation and the usual infostealer carrier |
| PUA_MED_NirSoft_Password_Tool | Password recovery utilities | Credential harvesting, insider or attacker |
| PUA_MED_Admin_Recon_Lateral_Tool | PsExec, ProcDump, IP scanners, kernel process killers on user devices | Reconnaissance or lateral movement from that device |

## Known benign matches

See `README.md` section 5 for the tuning table (developer installers, Windows.old hive copies, container base layers, sanctioned RMM, security-staff devices).
