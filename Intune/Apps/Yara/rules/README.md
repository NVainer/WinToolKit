# Windows 11 Endpoint YARA Ruleset

**Author:** Nati
**Version:** v3 — 2026-10-14 (rebuilt for a regular-user fleet)
**Target:** Intune-managed, Entra-joined Windows 11 endpoints. Regular users: not developers, not local admins. Defender / MDE is the primary EDR, Microsoft Sentinel the SIEM.
**Total:** 49 detection rules in 7 category files + 2 global private filters.
**License / scope:** internal use.

---

## 1. What changed in v3

v2 had 134 rules and still produced noise from binary datastores. v3 starts from the question "what can a file scanner find on a regular user's laptop that MDE does not already own?" and keeps only that.

Removed, and why:

| Removed | Reason |
|---|---|
| Refresh-token / ESTSAUTH "staged on disk" rule | Every MSAL.js web app (Teams, Outlook on the web, the Azure portal) stores `"accessToken":"eyJ..."` in Edge/Chrome LevelDB files in plain text. The rule fired on normal browser state. |
| AiTM landing-page rule | Matched the real `login.microsoftonline.com` page cached by the browser (branding strings + a `wss://` host). |
| Device-code lure-page rule | `[A-Z0-9]{4}-[A-Z0-9]{4}` matches dates; the real `microsoft.com/devicelogin` page matched too. |
| ISO / VHD container heuristic | `CD001` + a `.lnk` string anywhere in a 200 MB file matched every Windows ISO in Downloads. |
| MSI CustomAction rule | Every vendor MSI has a VBScript custom action. |
| Havoc and Brute Ratel string rules | Both implants hash API names and ship no stable plaintext; the strings were guesses. |
| NTDS / DCSync / ntdsutil / GPP cpassword / PrintNightmare / SpoolFool / PetitPotam / RBCD / ADCS | Domain-controller era tooling with nothing to attack from a cloud-joined workstation. |
| wmic rules, Follina, xwizard, ie4uinit, pcalua, cdb, tracker, msdt, WSL, hh.exe, CHM, XLL, PDF JavaScript | Gone from Windows 11 24H2 (wmic), patched for years, or too rare to earn a rule. |
| Sysmon unload, COR_PROFILER, CLM escape, BITS jobs, GPO scripts, AppDomainManager, profile tampering | Not in use here / registry-only / noise. |

Added:

- Global skips for SQLite, EVTX, PST/OST and compressed prefetch on top of the ESE and registry-hive skips.
- Registry hives are skipped **except** readable copies of SAM / SYSTEM / SECURITY, which are now detected (`CRED_HIGH_Registry_Hive_Copy_SAM_SYSTEM_SECURITY`).
- `-EncodedCommand` payload inspection without decoding, via YARA's `wide base64` modifier.
- Base64-encoded executables inside text/HTML/scripts (HTML smuggling, droppers with embedded binaries).
- ClickFix lure pages and the pasted command, LSASS minidumps on disk, Kerberos ticket files.
- NetSupport RAT, commodity .NET RATs, unsanctioned remote-access tools, tunnelling binaries, rclone, Discord/Telegram exfil channels.
- Vulnerable drivers used by EDR killers, Defender-killer utilities, KMS activators, NirSoft password tools, admin/recon tooling on user endpoints.

End state on the reference machine (a developer laptop, so noisier than a regular user's): every decoy in `tests\` fires exactly the intended rule, every benign control stays clean, our own `install.ps1`, `scan-*.ps1` and task XMLs do not fire.

---

## 2. Design

### 2.1 Three anchors per rule

Every rule needs a **format anchor** (magic bytes, or a structural marker such as `<Task version=`), an **execution primitive** (a verb, API or tool name) and a **payload shape** (URL, encoded blob, user-writable path, hidden-window flag, credential store path). One of the three alone never fires.

```yara
condition:
    $lnk_magic at 0            // format
    and 1 of ($h_*)            // script host
    and 1 of ($p_*)            // payload shape
```

### 2.2 Text rules skip binaries

Every rule that looks for commands or script text starts with:

```yara
not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F   // not PE, not ELF
and filesize < 10MB
```

.NET DLLs export every `WebClient` / `AmsiScanBuffer` / `Bypass` symbol as a method name. Rules that *target* binaries (C2 implants, drivers, RATs) require `uint16(0) == 0x5A4D` instead.

### 2.3 Global private filters (`00_global_filters.yar`)

A `global private rule` is an AND-precondition for every other rule. Two of them drop file classes that only ever contain indexed text and cached web content:

| Filter | Drops |
|---|---|
| `SKIP_OWN_SCAN_ARTIFACTS` | the compiled `.yarc` (magic `YARA`), our own scan JSON (three keys co-occur), anything carrying `__YARA_INTUNE_SELF_OUTPUT_v1__` |
| `SKIP_SYSTEM_DATASTORES` | ESE (`Windows.db`, `WebCacheV01.dat`, `qmgr.db`), SQLite (browser History/Cookies/Login Data, Teams, ActivitiesCache), `.evtx`, `.pst/.ost`, compressed `.pf`, and `regf` hives **unless** the hive is a SAM/SYSTEM/SECURITY copy |

All checks are magic-byte based. Nothing is path based, so an attacker cannot hide a payload by choosing a folder.

### 2.4 Encoded commands without decoding

`powershell -enc <b64>` encodes the UTF-16LE script. YARA's `wide base64` modifier produces exactly that encoding, in all three alignments:

```yara
$b_dls = "DownloadString" wide base64 base64wide
```

`base64wide` additionally covers blobs stored as UTF-16 themselves (scheduled-task XML, LNK arguments). `PS_HIGH_EncodedCommand_Malicious_Payload` combines the `-e/-ec/-enc` flag with these markers; TCPClient, AMSI and Invoke-Mimikatz markers fire even without the flag.

### 2.5 Tool names need a second element

A tool name in a blog post must not fire. Tool rules bind the name to a tool-specific argument (`Rubeus … /user:`), a second family string (`AsyncRAT` + `get_SslClient`), a Go import path (`github.com/bishopfox/sliver`), or require a PE header.

---

## 3. Severity model

| Severity | Meaning | Response |
|---|---|---|
| `high` | Attack artifact or tool with no benign explanation on a regular user's device | Triage now; isolate via MDE if the user is non-admin and the file sits in a user-writable path |
| `medium-high` | Attack shape with one looser element, or a tool that IT staff might legitimately own | Triage within the day; check path and publisher |
| `medium` | Unwanted-but-not-malicious, or a format heuristic | Review in the weekly sweep; tune by path/tool name in KQL |

---

## 4. Rule inventory

| File | Rules | Coverage |
|---|---:|---|
| `00_global_filters.yar` | 2 globals | own artifacts; ESE/SQLite/EVTX/PST/prefetch/registry-hive skip with SAM/SYSTEM/SECURITY exception |
| `01_initial_access.yar` | 10 | LNK with script-host payload, HTA dropper, XMLHTTP+ADODB script dropper, ClickFix lure, base64-embedded executable, HTML smuggling download, SVG script smuggling, OLE macro auto-exec, RTF Equation Editor, OneNote embedded file |
| `02_powershell_and_lolbas.yar` | 10 | download cradle to IEX, encoded-command payload, TCPClient reverse shell (+PowerCat/Nishang), AMSI bypass, Defender tamper, logging/ETW tamper, reflective load / shellcode scaffold / msfvenom prologue, obfuscation stacks, stealth flags + remote payload, LOLBAS download-execute one-liners |
| `03_credential_access.yar` | 8 | LSASS minidump on disk, SAM/SYSTEM/SECURITY hive copy, Kerberos ticket file, dumped-credentials text (mimikatz/pwdump/stealer logs/kerberoast hashes), mimikatz binary/script/commands, LSASS dump commands, browser credential theft tools and scripts, hive theft commands |
| `04_known_offensive_tools.yar` | 8 | Cobalt Strike beacon, Sliver, Meterpreter, offensive PowerShell frameworks, AD toolkit (Rubeus/SharpHound/Seatbelt/Certify/Impacket/NetExec/PtH), Entra toolkit (AADInternals/ROADtools/TokenTactics/GraphRunner/TeamFiltration/PRT & token-cache theft/device-code flow), Potato LPE family, BYOVD vulnerable drivers |
| `05_persistence.yar` | 3 | suspicious scheduled-task XML / schtasks / Register-ScheduledTask, WMI event subscription (script + OBJECTS.DATA instance records), script writing autorun keys / services / Startup folder |
| `06_remote_access_exfil.yar` | 6 | NetSupport RAT config and binaries, commodity RAT strings (Remcos/AsyncRAT/XWorm/DcRat/Quasar/NanoCore/VenomRAT/njRAT), unsanctioned RMM artifacts (AnyDesk/RustDesk/MeshAgent/ScreenConnect/Atera/Splashtop/…), tunnelling tools (ngrok/cloudflared/chisel/frp/ligolo/…), rclone, hard-coded Discord/Telegram exfil |
| `07_unwanted_tools.yar` | 4 | Defender-killer utilities, KMS/HWID activators, NirSoft password tools, PsExec/ProcDump/IP scanners/kernel process killers on user endpoints |

---

## 5. Known benign matches and tuning

| Rule | Benign case | What to do |
|---|---|---|
| `PS_HIGH_Download_Cradle_IEX` | Chocolatey / Scoop / `irm aka.ms/install-powershell.ps1 \| iex` one-liners | Developer actions; on a regular user's device still worth a question |
| `CRED_HIGH_Registry_Hive_Copy_*` | `C:\Windows.old\…\config\*` for ~10 days after a feature update; RegBack if periodic backup is enabled; Windows Sandbox / container base layers under `C:\ProgramData\Microsoft\Windows\Containers\Layers\*\Specialization\` (readable `SYSTEM` and `SYSTEM.LOG1`) | Filter those paths in KQL; a hive copy anywhere else is theft |
| `TOOL_MEDHIGH_Vulnerable_Driver_BYOVD` | RTCore64 (MSI Afterburner), WinRing0 (hardware monitors), PROCEXP152 (Process Explorer), mhyprot2 (Genshin Impact) under Program Files | Verify the installing product once, then filter by path |
| `RMM_MED_Unsanctioned_Remote_Access_Tool` | Your own RMM | Delete that branch from the rule |
| `RAT_HIGH_NetSupport_Manager_RAT` | A licensed NetSupport Manager deployment | Scope to paths outside Program Files |
| `CRED_HIGH_Mimikatz`, `PS_HIGH_AMSI_Bypass`, `IA_HIGH_ClickFix_Lure` | A security article cached by the browser (`…\Edge\User Data\Default\Cache\Cache_Data\f_*`) | The path tells you; a cached article is not an artifact in Downloads |
| `PUA_MED_Admin_Recon_Lateral_Tool`, `TOOL_HIGH_AD_Attack_Toolkit` | IT staff / security team machines | Exclude those device groups in the Sentinel analytics rule |
| `PERSIST_HIGH_ScheduledTask_Suspicious` | A vendor task that runs a `.vbs/.bat` from ProgramData | Verify the publisher once, filter by task name |
| `PS_HIGH_Download_Cradle_IEX` | Developer-tool installers (`irm <vendor>/install.ps1 \| iex`) | The exact URLs of Claude Code, Chocolatey, Scoop, PowerShell, uv, bun, pnpm, nvm, rustup and poetry are allow-listed in the rule; the WebClient form of the Chocolatey line still fires and is the documented `expectedfp_` case |
| `TUNNEL_MEDHIGH_Tunneling_Proxy_Tool` | npm packages and docs that quote `cloudflared`/`ngrok` commands | Command branches require a real token or localhost target; placeholders in docs no longer match |
| Security staff devices | OneNote notebooks, PowerShell history and notes full of tool names and commands | True positives on legitimately owned content; exclude the security team's device group in the analytics rule |
| Everything | The maintainer's clone of this repo (`rules\*.yar` quote the indicator strings) | Exclude the repo path on the maintainer's machine |

Classes that were false positives during v3 validation and are now fixed in the rules themselves:

- browser ad-block / public-suffix lists (hostnames and tool names appear in them);
- Windows feature-pack resources naming activators, and Windows' own `ci.dll`, `ThreatAssessment.dll`, `CapabilityAccessManager.dll`, which list tamper tools and remote-access products by name (every tool-name rule now needs a second vendor artifact);
- Intel Wi-Fi drivers (contain "Quasar"), Realtek audio DLLs ("SoundControl" contains "dControl"), AMD Vitis AI ("GraphRunner" class), `EhStorTcgDrv.sys` (name contains "gdrv.sys") — the BYOVD rule now reads `OriginalFilename` through the `pe` module with exact matching;
- PowerShell's own help files and the DSC module (`Invoke-Command -ComputerName` examples, `[Array]::Reverse`, ascending `{0}{1}{2}` format strings);
- Microsoft's code-integrity block policies (`C:\Windows\schemas\CodeIntegrity\ExamplePolicies\*.xml` list blocked tool file names: the LSASS-dump rule now skips `<SiPolicy` documents and needs an invocation argument after a tool name), System Guard assertions and Sysmon configs that name the mimikatz driver (PE-only now), and `sysmon.exe` itself, whose EULA text names PsExec (PsExec/PAExec/ProcDump are now identified by their own version resource);
- `SOFTWARE`/`NTUSER` hives whose value data contains `ControlSet001` (hive fingerprints are now anchored on `nk` key cells);
- Office add-in bundles and web apps with copy-to-clipboard buttons next to command samples;
- OEM Start Menu shortcuts that open support pages through `rundll32` / `cmd /c start`;
- installer one-liners of common developer tools (allow-listed by exact URL);
- a Dutch news site whose name matched an LSASS-dump tool.

The DCR transform currently drops clean scans (`SelfMarker` is always present, so only `TotalMatches > 0` passes). Keep that in mind when you look for "which devices scanned".

---

## 6. Build and validate

```powershell
cd C:\Git_Project\WinToolKit\Intune\Apps\Yara
.\tests\Test-Rules.ps1          # combine -> compile -> decoys -> scan -> assert
```

The runner extracts `yara64.exe` / `yarac64.exe` from the release zip when they are missing, writes `rules\_master.yar` and `compiled_rules.yarc`, generates `tests\decoys\` with `tests\make_decoys.py` (Python 3; a PowerShell generator carrying the same strings is blocked by AMSI), scans it and reports:

- `ok fired` — a decoy fired the expected category rule
- `ok clean` — a `benign_*` control (our own scripts and task XML, a benign LNK, an NTUSER-shaped hive full of attack text, a vendor task, an HTML page with inline SVG) fired nothing
- `info expected FP` — the documented Chocolatey one-liner
- `FAIL` — anything else; fix before deploying

Defender flags the decoy generation (the fake `.kirbi` triggers a behaviour detection on `python.exe`). Run the tests from a folder excluded from Defender real-time protection. Decoys and build artifacts are git-ignored.

Manual equivalent:

```powershell
.\combine_rules.ps1                                     # rules\_master.yar
.\yarac64.exe .\rules\_master.yar .\compiled_rules.yarc # expect 0 errors; "may slow down scanning" warnings are fine
.\yara64.exe -w -r -C .\compiled_rules.yarc <folder>    # ad-hoc scan
```

Before shipping, also scan a real profile: `yara64.exe -w -r -p 8 -z 300000000 -C compiled_rules.yarc C:\Users\<you>` and read every hit. `-z` skips files above 300 MB; consider adding it to the scan scripts.

---

## 7. Triage playbook

1. **Path first.** Downloads, Desktop, Temp, AppData\Roaming, Public, ProgramData, Windows\Temp, Startup → treat as delivered. Browser cache (`Cache_Data\f_*`), `Windows.old`, Program Files → read the matched strings before escalating.
2. **Read `MatchStrings`.** The record shows the literal bytes at each match; it tells you which branch fired and usually what the payload is (URL, encoded command, remote).
3. **Hash and pivot.** `Get-FileHash`, then MDE `DeviceFileEvents` for the creation event and its `InitiatingProcess*` chain, `DeviceProcessEvents` for the command line, `DeviceNetworkEvents` for the URL host.
4. **Category-specific:**
   - `IA_*` / `PS_*` / `LOL_*`: find the user action (mail attachment, browser download, ClickFix paste → `DeviceProcessEvents` where `InitiatingProcessFileName == "explorer.exe"` and `ProcessCommandLine` contains the string).
   - `CRED_HIGH_LSASS_Minidump_On_Disk`, `CRED_HIGH_Registry_Hive_Copy_*`, `CRED_HIGH_Kerberos_Ticket_File`: assume credential theft happened; reset the user's credentials and revoke sessions, then investigate.
   - `TOOL_*`, `RAT_*`, `TUNNEL_*`, `EXFIL_*`: hands-on-keyboard. Isolate via MDE, then collect.
   - `RMM_MED_*`: ask the user who installed it. "IT support called me" means a scam session; treat as compromise.
   - `PERSIST_*`: enumerate the task / subscription / key on the host and remove it after the initial access is understood.
   - `PUA_*`: policy violation unless it co-occurs with anything above.
5. **Decoy check.** If the hit is on the maintainer's machine inside this repo or `tests\decoys`, it is the test corpus.

---

## 8. Style guide for new rules

```yara
/* -----------------------------------------------------------------------------
   CATEGORY_SEVERITY_ShortName
   One paragraph: what artifact, why it only exists in an attack.
   ----------------------------------------------------------------------------- */
rule CATEGORY_SEVERITY_ShortName
{
    meta:
        author      = "Nati"
        date        = "YYYY-MM-DD"
        category    = "<category>"
        severity    = "high|medium-high|medium"
        description = "Plain-language description of every branch"
        mitre       = "T1059.001"
        fp_notes    = "Known benign matches and how to tune them"

    strings:
        $format  = { ... }                      // or a structural marker
        $verb    = /.../i ascii wide
        $payload = /.../i ascii wide

    condition:
        <format anchor> and filesize < 10MB
        and $verb and $payload
}
```

Hard rules:

- **Three anchors** (format, primitive, payload). No rule fires on a single keyword.
- **Text rules skip PE/ELF**; binary rules require MZ.
- **`ascii wide`** on everything PowerShell/script related (UTF-16 in LNK, task XML, memory).
- **`filesize` gate** on every rule.
- **Keep rule names stable.** Sentinel KQL pivots on them; add a new rule instead of renaming.
- **No YARA externals** (`filename`, `filepath`, `extension`, `owner` as operators); `combine_rules.ps1` drops such files.
- **Add a decoy** to `tests\make_decoys.py` for every new rule, and a `benign_*` control for every FP you fix.
- **Prefer wide base64 over decoding** for anything that can arrive `-EncodedCommand`.

YARA syntax reminders:

| Gotcha | Wrong | Right |
|---|---|---|
| Forward slash inside a regex char class | `[A-Za-z0-9+/=]` | `[A-Za-z0-9+\/=]` |
| Non-capturing group / lookaround / inline flags | `(?:x)`, `(?!x)`, `(?i)` | `(x)`, rewrite positively, `/i` |
| Unreferenced string | declared `$x` not in condition | reference every `$x` (compile error otherwise) |
| Backslash in a text string | `"System32\Config"` | `"System32\\Config"` |
| `^` / `$` in regex | expecting per-line anchors | they anchor to the file; use `[\r\n]\s*` instead |
| Repeat counts | `{0,200000}` | keep intervals under ~10000 or split the pattern |
| Non-ASCII in regex | `I['’]?m` | `I'?m` |
| `nocase` with base64 | `"x" nocase base64` | not allowed; declare each case variant |

---

## 9. Backlog

- [ ] Sentinel analytics rule per category file (`IA_*`, `CRED_*`, `TOOL_*` …) with the severity mapping from §3.
- [ ] Add `-z 300000000` (skip files > 300 MB) to `scan-quick.ps1` / `scan-full.ps1`.
- [ ] Decide whether the DCR transform should keep zero-match records (device heartbeat) or stay cost-optimised.
- [ ] Quarterly: refresh BYOVD driver list from loldrivers.io, RAT string sets from Sekoia/ditekSHen, RMM vendor list from the sanctioned-software inventory.
- [ ] Real-sample validation: run the compiled set against MalwareBazaar samples for Remcos/AsyncRAT/XWorm/NetSupport in an isolated VM.
