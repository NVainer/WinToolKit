# Windows 11 Endpoint YARA Ruleset

**Author:** Nati
**Version:** 2026-05-24 (bound-pattern hardening pass)
**Target:** Intune-managed Windows 11 endpoints (cloud-joined, Defender + MDE primary EDR)
**Total:** 134 detection rules across 9 category files + 2 global private filters
**License / scope:** internal use; rules tuned to this environment's trusted baseline (Intune Management Extension, MDE live response, Windows Update, certutil/bitsadmin used legitimately by IME).

---

## 1. What changed in 2026-05-24

The previous design used `any of ($foo, $bar)` and bare standalone-keyword conditions. On a real Windows 11 fleet that produced **2552 hits per scan**, of which **0 were real attacks**. The 24.05 rewrite enforces one rule:

> **Every detection rule must require a bound ATTACK SHAPE — verb + argument + value combined inside a single proximity-bounded regex (or AND of two such regexes). No standalone keyword conditions. No `or $tool_name_alone` branches.**

The first pass (2552 → 231 hits) fixed the worst single rule (`OBF_HIGH_PS_Backtick_Broken_IEX`, which used `` `? `` making backticks optional). The second pass (231 → 18) added a global content-based suppressor for the scanner's own artifacts. The third pass (18 → 7) addressed Defender ATP scripts, vcredist installer logs, ExplorerStartupLog.etl, and SettingsCache.txt. The fourth pass (this one) tightened the remaining ESE-database / store DB FPs by adding a second global filter, then rebuilt all 134 rules with bound patterns.

End state on the reference Windows 11 endpoint:
- `reverse.txt` decoy (canonical PS TCPClient reverse shell) → fires `RS_HIGH_PS_TCPClient_Stream_IEX_Loop`, exactly one rule
- HP TechPulse JSON, Microsoft Search index, Edge WebCache, Windows Store DB, NTUSER.DAT, Office Excel JS bundles, Defender ATP DataCollection .ps1, vcredist installer logs, ExplorerStartupLog.etl, Microsoft Settings cache → **zero matches**

---

## 2. The bound-pattern design

### 2.1 What "bound" means

A bound pattern is one regex that requires **two or more attack-shape elements to appear together in proximity**. The elements are typically (verb, argument, value) — for example:

| Element type | Examples |
|---|---|
| Verb | `New-Object`, `Invoke-WmiMethod`, `Add-MpPreference`, `reg save`, `certutil -urlcache`, `rundll32 ... MiniDump` |
| Argument shape | `(literal IP, literal port)`, `-ma <pid>`, `-CollectionMethod All`, `-DisableRealtimeMonitoring $true` |
| Value / target | `lsass(.exe)?`, `\\<host>\<share>\*.dll`, `HKLM\SAM`, `C:\Users\...\AppData\...`, `https://raw.githubusercontent.com/...` |

A bound regex puts those together within a 200–500 char window:

```
$bound = /<verb>[^\r\n]{0,200}<argument>[^\r\n]{0,200}<value>/i ascii wide
```

### 2.2 Why this kills FPs

Loose conditions like `($verb and $value)` fire on any file that mentions the two elements *anywhere*. Windows Search index (`Windows.db`) contains every PowerShell cmdlet name as indexed text. .NET runtime DLLs export every `WebClient` / `Bypass` / `Base64` symbol as a method name. Office Excel JS bundles contain `cUrl` (a JS class) on one line and `https://raw.githubusercontent.com/...` (a webpack source-map URL) on another. None of those are attacks, but every one of them is two-keyword positive under the old design.

Bound patterns require the elements to be **structurally adjacent in the way a real attacker writes them**. `New-Object Net.Sockets.TCPClient('1.2.3.4',4444)` is a bound shape. `Net.Sockets.TCPClient` somewhere in a 200 MB MUI file is not.

### 2.3 Three universal hardening clauses

Every script/text-content rule applies these three gates in its `condition`:

```yara
condition:
    not uint16(0) == 0x5A4D and       // skip PE  (MZ header)
    not uint32(0) == 0x464C457F and   // skip ELF (0x7F ELF header)
    filesize < 5MB and                // typical PS payload cap
    <bound regex(es)>
```

PE skip excludes .NET DLLs, .exe, .mui, .tbres, .etl-with-PE-headers — these files contain symbol names like `WebClient`/`Bypass`/`AmsiScanBuffer` as exports, not as attacker invocations. Filesize cap keeps scans cheap and reflects that real obfuscated PS payloads are tiny.

Rules that **target binary content** intentionally omit the PE skip (XLL add-ins, CobaltStrike beacons, Mimikatz banner strings inside the .exe). These are flagged in each rule's comment.

### 2.4 Global private filters (`00_global_filters.yar`)

YARA `global private rule` acts as an AND-precondition for every other rule in the namespace. Two of them suppress entire file classes that produce only noise:

| Filter | Suppresses |
|---|---|
| `SKIP_OWN_SCAN_ARTIFACTS` | `.yarc` magic at offset 0; scanner JSON schema (3-marker co-occurrence); explicit `__YARA_INTUNE_SELF_OUTPUT_v1__` marker. Kills self-detection when the scan JSON is emailed back to a scanned box and Outlook caches the attachment. |
| `SKIP_BINARY_SYSTEM_DATASTORES` | ESE database / log (`uint32(4) == 0xEFCDAB89` — Windows.db, V01.log, store.db, WebCacheV01.dat); REGF registry hive (`uint32(0) == 0x66676572` — NTUSER.DAT, SOFTWARE, SYSTEM, SAM). These are kernel-managed binary stores; attackers modify them via APIs, not by writing raw bytes, so static byte scanning produces only indexed-text noise. |

Neither filter is path-based. An attacker dropping a malicious payload in `C:\ProgramData\HP\evil.ps1` is still scanned and matched — the global skips only file *types* whose binary structure inherently can't carry attacker-crafted detectable content.

The scanner emits its own marker into every scan record:

```powershell
# scan-quick.ps1 / scan-full.ps1
$SelfMarker = '__YARA_INTUNE_SELF_OUTPUT_v1__'
$rec = [pscustomobject]@{
    TimeGenerated = $nowIso
    ...
    SelfMarker    = $SelfMarker
}
```

---

## 3. Severity model

| Severity | When it fires | Response |
|---|---|---|
| `high` | High-confidence bound attack shape (TCPClient + literal IP+port + IEX loop, mimikatz + `sekurlsa::logonpasswords`, PrintNightmare RPC + UNC, etc.) | Immediate triage; isolate endpoint if user is non-admin or off-baseline |
| `medium-high` | Bound shape with one looser element (e.g. PowerView 3-of-N functions + arg, but specific function set is dispersed) | Triage within 1 hour; correlate with MDE timeline |

There is no `low` band. If you wouldn't look at a hit, the rule shouldn't be in the set.

---

## 4. Rule inventory

| # | File | Rules | Coverage |
|---|------|------:|----------|
| 00 | `00_global_filters.yar` | 2 globals | `SKIP_OWN_SCAN_ARTIFACTS`, `SKIP_BINARY_SYSTEM_DATASTORES` |
| 01 | `01_reverse_shells_c2.yar` | 17 | PS TCPClient/NetworkStream reverse shells, PowerCat, download cradles, reflective Assembly.Load, P/Invoke shellcode, named-pipe C2, certutil/curl IEX cradle, WMI/DCOM lateral, .NET C# reverse-shell source, HTTP beacon loop, CobaltStrike / Sliver / Havoc / BruteRatel / Meterpreter / PoshC2-Empire stagers |
| 02 | `02_lolbas_abuse.yar` | 18 | certutil/bitsadmin/mshta/regsvr32/rundll32/msbuild/installutil/wmic/cmstp/forfiles/hh/msdt/ie4uinit/xwizard/pcalua/mavinject/cdb/tracker/wsl/cscript-wscript — every one bound to abuse syntax + payload |
| 03 | `03_amsi_etw_defender_bypass.yar` | 13 | AMSI patch (reflection, byte-patch, HWBP, CtxField), ETW patch, COR_PROFILER hijack, Script-block / module logging disable, Defender realtime disable, exclusion-of-user-writable-path, service-kill, Sysmon unload, LanguageMode escape, TamperProtection bypass |
| 04 | `04_credential_access.yar` | 15 | procdump/comsvcs/MiniDumpWriteDump/sqldumper/WerFault/KProcessHacker LSASS dump, reg save SAM/SYSTEM/SECURITY, VSS shadow NTDS extract, Mimikatz module strings + PS wrapper, Rubeus kerberoast, SharpHound/BloodHound, LaZagne, browser cred DB + DPAPI, SharpDPAPI/DonPAPI, PS direct NT API LSASS read |
| 05 | `05_persistence.yar` | 16 | Run/RunOnce, IFEO accessibility, IFEO SilentProcessExit, WMI event subscription, sc create suspicious binPath, Winlogon Userinit/Shell, AppInit_DLLs, LSA SSP, COM HKCU InprocServer32, Print Monitor, Scheduled Task with -enc/user-writable, Startup folder script drop, .NET AppDomainManager hijack, PS profile tampering, BITS job, GPO ScheduledTask/Scripts.ini |
| 06 | `06_obfuscated_powershell.yar` | 14 | Stealth-flag stack + downloader, Invoke-Obfuscation format-op stack, [char] array reconstruction, backtick-broken IEX, env-var IEX, ScriptBlock.Create+Invoke, GZip/Deflate in-memory unpack, reflective Assembly.Load + b64, trusted-site download cradle, string-reverse + GetType, shellcode loader scaffold, AMSI token char-reassembly, XOR inline decode loop, FromBase64 inline IEX one-liner |
| 07 | `07_initial_access.yar` | 13 | HTA WScript.Shell + payload, VBA AutoExec + payload, LNK + embedded cmdline, OneNote + FileDataStoreObject + script-suffix, SCT/WSC + regsvr32 scrobj.dll, XLL + xlAutoOpen + suspicious imports, ISO/IMG/VHD container + LNK + sibling, CHM + script + WScript.Shell.Run, MSI CustomAction + script body, SVG smuggling + base64 + JS click, PDF + /OpenAction + JS, JS/VBS XMLHTTP + ADODB.Stream + Run, ClickFix pastejack |
| 08 | `08_post_exploitation.yar` | 18 | Impacket scripts + tool-specific args, PtH cmdline shape, Potato family by name+args, generic Potato (SeImpersonate+COM+Impersonate), PrintNightmare, SpoolFool, RBCD abuse, NTLM relay tooling, PowerView 3-of-N functions, GPP cpassword, SeBackup/NTDS extract, DCSync, PSExec family + UNC, NetExec/CME, WMI lateral, DCOM lateral, PetitPotam/Coercer, ADCS Certify/Certipy |
| 09 | `09_cloud_identity_attacks.yar` | 10 | OAuth DeviceCode phish tool, TokenTactics module, TokenSmith/ROADtools artifact, WAM TokenBroker cache theft, OneAuth identity cache theft, C4Bomb Chrome AppBound decrypt, PRT extraction cmd, AiTM phish landing (Tycoon/Mamba/Sneaky/Whisper), refresh-token staged on disk, device-code phish lure HTML |

---

## 5. Style guide (for new rules)

Match this template:

```yara
/* -----------------------------------------------------------------------------
   <CATEGORY>_<SEVERITY>_<ShortName>
   One-line description of the bound attack shape.
   ----------------------------------------------------------------------------- */
rule CATEGORY_SEVERITY_ShortName
{
    meta:
        author      = "Nati"
        date        = "YYYY-MM-DD"
        category    = "<category>"
        severity    = "high"
        description = "Bound: <verb> + <argument> + <value/target> in one <N>-char window"
        mitre       = "T1059.001,T1140"
        reference   = "<URL or CVE>"

    strings:
        // Forward bound: verb -> arg -> value
        $bound_vav = /<verb>[^\r\n]{0,200}<argument>[^\r\n]{0,200}<value>/is ascii wide
        // Reverse bound: value -> arg -> verb (catches piped variants)
        $bound_vva = /<value>[^\r\n]{0,200}<argument>[^\r\n]{0,200}<verb>/is ascii wide

    condition:
        not uint16(0) == 0x5A4D and
        not uint32(0) == 0x464C457F and
        filesize < 5MB and
        ( $bound_vav or $bound_vva )
}
```

Hard rules:

- **No `or $single_keyword` branches.** A standalone tool name, function name, or class name is forbidden as a final OR-arm. Always pair with attacker-context.
- **Always `ascii wide`** on PS/script content (PowerShell stores strings as UTF-16LE in memory).
- **Always a `filesize` gate.** Real obfuscated PS is small.
- **Always the PE/ELF header skip** unless the rule targets binary content (XLL, CobaltStrike, Mimikatz banner-in-exe).
- **Preserve rule names** when modifying — Sentinel/MDE KQL queries pivot on the rule name.
- **Don't reference YARA externals** (`filename`, `filepath`, `extension`, `owner` *as YARA operators*) — `combine_rules.ps1` strips files that use them. Word-substrings like `FileName` in PowerShell cmdlet contexts are fine; the combiner now uses an operator-following-token regex to distinguish.
- Forward slashes inside regex char classes (`[A-Za-z0-9+\/=]`) must be escaped as `\/`.
- YARA does **not** support `(?:...)`, `(?!...)`, `(?=...)`, `(?<=...)`, `(?<!...)`, or `(?i)` inline modifiers. Use `(...)` non-capturing groups and `/i` flag.
- All declared `$strings` **must** be referenced in the condition — YARA treats unreferenced strings as syntax errors, not warnings.
- Non-ASCII characters in regex patterns will fail to compile. Use ASCII alternatives (`I'?m` not `I'’?m`).
- YARA's regex engine caps repetition counts. Repeat intervals larger than ~10000 will fail with "repeat interval too large" — split into separate strings and AND in the condition.

---

## 6. Deployment

### 6.1 Layout

```
C:\Program Files\YARA\
├── yara64.exe                  (binary, signed)
├── yarac64.exe                 (compiler)
├── compiled_rules.yarc         (master compiled blob - deployed via Intune)
├── scan-quick.ps1              (Users / ProgramData / Temp / Windows\Temp)
├── scan-full.ps1               (entire C:\ + other fixed drives)
└── logs\
    └── yara_scan_{quick|full}_<HOST>_<DD.MM.YYYY_HH.mm>.json
```

### 6.2 Build the compiled blob

```powershell
cd C:\Git_Project\yara_intune
.\combine_rules.ps1                          # writes rules\_master.yar (10 includes)
& "<yarac64.exe>" rules\_master.yar compiled_rules.yarc
Copy-Item compiled_rules.yarc "C:\Program Files\YARA\" -Force
Copy-Item scan-quick.ps1      "C:\Program Files\YARA\" -Force
Copy-Item scan-full.ps1       "C:\Program Files\YARA\" -Force
```

The compiler is in the YARA release zip; the combiner script skips its own master file (`_master.yar`) and any rule file that references YARA externals (`filename matches /.../`, `extension == "..."`, etc.) by content.

### 6.3 Scanning

`scan-quick.ps1` / `scan-full.ps1` invoke:

```
yara64.exe -r -p 2 -s -C compiled_rules.yarc <target>
```

| Flag | Purpose |
|---|---|
| `-C` | load compiled rules (~30% faster than parsing source on every scan) |
| `-r` | recursive |
| `-p 2` | 2 worker threads (raise to 4 on i7+/16 GB endpoints) |
| `-s` | print matching strings (essential for triage) |

Output is one JSON record per match, with `SelfMarker` embedded so the global filter recognises any cached/forwarded copy of the output as scanner-own.

### 6.4 Intune deployment

Package as a Win32 app:
- **Install:** `powershell.exe -ExecutionPolicy Bypass -File install.ps1`
- **Uninstall:** `powershell.exe -ExecutionPolicy Bypass -File uninstall.ps1`
- **Detection rule:** file exists `C:\Program Files\YARA\compiled_rules.yarc` AND `HKLM\SOFTWARE\YARA\Version` matches.

For rule updates, ship just the new `compiled_rules.yarc` as a separate Win32 app keyed to a version registry value — no need to rebuild the whole package.

### 6.5 Log shipping

Pipe `C:\Program Files\YARA\logs\` to Sentinel via:
- **Option A (preferred):** MDE recommended file collection — captures match lines into custom table.
- **Option B:** AMA with a custom DCR collecting the log directory.

A match record looks like:

```json
{"TimeGenerated":"2026-05-24T...","Computer":"DESKTOP-...","Rule":"RS_HIGH_PS_TCPClient_Stream_IEX_Loop","MatchedFile":"C:\\...\\evil.ps1","MatchStrings":"0x0:$bound_full: ...","MatchCount":1,"SelfMarker":"__YARA_INTUNE_SELF_OUTPUT_v1__"}
```

Drop any record where `MatchedFile` contains the scanner-own paths *or* where any indexed cache contains the SelfMarker — those are echoes of prior scans.

---

## 7. Triage playbook

1. Parse the match record. The `MatchStrings` field shows the literal bytes at each match offset — confirms which bound branch fired.
2. Hash the file (`Get-FileHash`). Pivot in MDE / Defender / VT.
3. Pull parent process chain for the file's creation event (`DeviceFileEvents` → `InitiatingProcess*`).
4. Pivot in MDE on the rule name. The bound shape gives you the exact KQL pivot:
   - `RS_HIGH_PS_TCPClient_Stream_IEX_Loop` → `DeviceProcessEvents | where ProcessCommandLine matches regex @"Net\.Sockets\.TCPClient\s*\(\s*['""](\d{1,3}\.){3}\d{1,3}['""]?\s*,\s*\d{1,5}"`
   - `CRED_HIGH_Comsvcs_MiniDump_LSASS` → `DeviceProcessEvents | where ProcessCommandLine has_all ("comsvcs.dll","MiniDump") and ProcessCommandLine matches regex @"\d{2,6}\s+['""].*\.dmp"`
   - `OBF_HIGH_TrustedSite_Download_Cradle` → `DeviceNetworkEvents | where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe") and RemoteUrl matches regex @"raw\.githubusercontent\.com|gist\.githubusercontent\.com|cdn\.discordapp\.com\/attachments|..."`
5. If user is non-admin and the matched file is in `AppData\Local\Temp`, `Downloads`, or `ProgramData` → isolate via MDE live response (`Isolate-Machine`) pending review.
6. If user is admin (sysadmin running pentest tooling on purpose), confirm out-of-band before isolation.

---

## 8. Validation

Before deploying:

```powershell
cd C:\Git_Project\yara_intune
.\combine_rules.ps1
& "<yarac64.exe>" rules\_master.yar compiled_rules.yarc.test 2>&1
# Expect: 0 errors, possibly a few "may slow down scanning" warnings (acceptable).
# If error: read the file/line, fix, re-run.
Remove-Item compiled_rules.yarc.test
```

Then functional test against the canonical decoys:

```powershell
# 1) Reverse-shell decoy must fire RS_HIGH_PS_TCPClient_Stream_IEX_Loop exactly
& "<yara64.exe>" -w -C compiled_rules.yarc <path-to-reverse-decoy>.txt

# 2) Clean text file with the literal substring "iex" but no attack shape must fire NOTHING
"this script demonstrates iex usage" | Set-Content .\noisetest.txt
& "<yara64.exe>" -w -C compiled_rules.yarc .\noisetest.txt   # expect no output
Remove-Item .\noisetest.txt
```

If (1) fires more than one rule, or (2) fires anything → a bound pattern regressed; investigate before deploying.

---

## 9. Known YARA syntax gotchas

| Gotcha | Wrong | Right |
|---|---|---|
| Forward slash inside char class | `[A-Za-z0-9+/=]` | `[A-Za-z0-9+\/=]` |
| Non-capturing group | `(?:foo\|bar)` | `(foo\|bar)` |
| Negative lookahead | `(?!Program Files)` | rewrite as positive user-writable match |
| Inline case-insensitive | `(?i)foo` | `/foo/i` flag or `"foo" nocase` |
| Unreferenced string | `$x = "..."` declared but not in condition | reference every declared `$x` |
| Windows path backslash | `\Run` | `\\Run` (in regex) or `"\\Run"` (in plain string) |
| Wide PowerShell strings | `"AmsiUtils" ascii` | `"AmsiUtils" ascii wide` (PS uses UTF-16LE in memory) |
| Non-ASCII chars in regex | `I['’]?m` | `I'?m` (or hex bytes) |
| Huge repeat intervals | `[\s\S]{0,200000}<x>` | split into separate strings + AND |
| `or $tool_name_alone` | `or $rubeus` | `( $rubeus and $rubeus_verb )` |

---

## 10. Backlog

- [ ] Build a Sentinel **Analytics Rule per category file** that fires on YARA log ingestion + does the KQL pivot in one step.
- [ ] DLL side-loading pair detection (proxy DLL next to signed EXE) — needs sibling-file logic; pair with a PS pre-filter script.
- [ ] Quarterly red-team decoy refresh: add new canonical PoCs as `tests/decoys/*.txt` and run the validator section §8 as CI.
- [ ] Investigate moving SelfMarker into a hidden Alternate Data Stream so the scan JSON looks marker-free to a human reader but the global filter still recognises it.
