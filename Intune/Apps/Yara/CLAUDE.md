# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An Intune Win32 app that puts a YARA scanner on Entra-joined Windows 11 endpoints (Clicknet fleet: regular, non-admin, non-developer users; Defender/MDE is the EDR). Nothing here runs on the dev box except the build and the tests; the endpoint side is `install.ps1` + two scheduled tasks + two scan scripts, and the result of every scan is one JSON line that Azure Monitor Agent (AMA) tails into a Log Analytics custom table for Sentinel.

Three things live in this folder and move at different speeds:

| Part | Files | Changes |
|---|---|---|
| Engine | `yara-4.5.5-2368-win64.zip` (contains `yara64.exe` + `yarac64.exe`) | rarely |
| Endpoint scripts | `install.ps1`, `uninstall.ps1`, `scan-quick.ps1`, `scan-full.ps1`, `YARA-Quick.xml`, `YARA-Full.xml` | rarely |
| Detection rules | `rules/0?_*.yar`, `combine_rules.ps1`, `tests/` | often |

`rules/README.md` is the authoritative design doc for the ruleset (what v3 removed and why, the three-anchor design, global filters, the `wide base64` trick for encoded commands, severity model, inventory, known benign matches, triage playbook, rule template, YARA gotchas). Read it before touching a `.yar` file; do not duplicate it here.

## Build, test, package

```powershell
cd C:\Git_Project\WinToolKit\Intune\Apps\Yara
.\tests\Test-Rules.ps1 [-KeepDecoys]   # extract yara -> combine -> compile -> decoys -> scan -> assert
```

That is the whole validation loop. It writes `rules\_master.yar` and `compiled_rules.yarc` (both git-ignored), generates `tests\decoys\` with `tests\make_decoys.py` and checks that every `<category>_*` decoy fires, every `benign_*` control stays clean (our own scripts and task XML are among the controls) and reports the documented `expectedfp_*` case. Exit code = number of failures.

Things to know:

- The decoy generator is **Python on purpose**. A PowerShell generator carrying the same strings is blocked by AMSI before it runs (it was, on 2026-10-14).
- Defender real-time protection raises a behaviour detection when the fake `.kirbi` decoy is written. Run tests from a folder excluded from Defender.
- `combine_rules.ps1` excludes any file whose name starts with `_` and any file whose *content* uses a YARA external variable as an operator (`filename matches`, `extension ==`, …). It throws if nothing is left. If a new rule file silently disappears from the compile, that filter is why.
- `yarac` warnings of the form "string … may slow down scanning" are expected on a handful of short-atom regexes; errors are not.
- Before shipping, scan a real profile with `yara64.exe -w -r -p 8 -z 300000000 -C compiled_rules.yarc C:\Users\<you>` and read every hit. On the maintainer's own machine expect self-matches on this repo, on `.claude` session transcripts and on browser caches of security articles; those are not fleet false positives.

Packaging (manual, no script yet):

```powershell
# Stage only the files install.ps1 copies, in an ASCII path:
#   C:\YARA_Package\ = install.ps1 uninstall.ps1 yara64.exe scan-quick.ps1 scan-full.ps1 YARA-Quick.xml YARA-Full.xml compiled_rules.yarc
IntuneWinAppUtil.exe -c C:\YARA_Package -s install.ps1 -o C:\YARA_Out -q
```

### Intune app settings (portal, Apps → Windows → Win32)

| Setting | Value |
|---|---|
| Install | `powershell.exe -ExecutionPolicy Bypass -File install.ps1 -TargetVersion 1.0.0 -Force` |
| Uninstall | `powershell.exe -ExecutionPolicy Bypass -Command "Copy-Item 'C:\Program Files\YARA\uninstall.ps1' 'C:\Windows\Temp\uninstall.ps1' -Force; & 'C:\Windows\Temp\uninstall.ps1'"` — copied out first because the script deletes its own folder |
| Detection | Registry `HKLM\SOFTWARE\YARA`, value `Version`, version comparison `>= 1.0.0` |
| Install behavior | System |

`-TargetVersion` is the only version source: `install.ps1` writes it to the registry (both 64/32-bit views) and the detection rule compares against it. **Bump both together** on every release or Intune will consider the old install still current and never re-run.

## Rules layout (v3, 2026-10-14)

| File | Rules | Scope |
|---|---:|---|
| `00_global_filters.yar` | 2 global private | own artifacts; ESE/SQLite/EVTX/PST/prefetch/registry-hive skip, with SAM/SYSTEM/SECURITY hive copies deliberately let through |
| `01_initial_access.yar` | 10 | LNK, HTA, script droppers, ClickFix, base64-embedded PE, HTML/SVG smuggling, OLE macro, RTF Equation, OneNote |
| `02_powershell_and_lolbas.yar` | 10 | cradles, `-enc` payloads (`wide base64`), reverse shell, AMSI/Defender/logging tamper, reflective load, obfuscation, stealth launchers, LOLBAS |
| `03_credential_access.yar` | 8 | LSASS dump on disk and the commands that make one, hive copies and theft commands, kirbi, dumped-credential text, mimikatz, browser credential theft |
| `04_known_offensive_tools.yar` | 8 | Cobalt Strike, Sliver, Meterpreter, offensive PowerShell, AD toolkit, Entra toolkit, Potato LPE, BYOVD drivers |
| `05_persistence.yar` | 3 | scheduled-task XML/commands, WMI subscriptions (incl. OBJECTS.DATA), autorun-writing scripts |
| `06_remote_access_exfil.yar` | 6 | NetSupport RAT, commodity RATs, unsanctioned RMM, tunnels, rclone, webhook/bot-token exfil |
| `07_unwanted_tools.yar` | 4 | Defender killers, KMS activators, NirSoft, admin/recon tooling on user endpoints |

Conventions that matter when editing: rule names are KQL pivot keys (add, never rename); every text rule skips PE/ELF and caps `filesize`; every binary rule requires MZ; tool names always bind to a second element; no YARA externals; add a decoy to `tests/make_decoys.py` for every new rule and a `benign_*` control for every false positive you fix. `RS_HIGH_PS_TCPClient_Stream_IEX_Loop` kept its v2 name on purpose.

`04_known_offensive_tools.yar` and `07_unwanted_tools.yar` import the `pe` module: the BYOVD rule reads `pe.version_info["OriginalFilename"]` with exact (`iequals`) matching because plain driver-name strings also occur inside unrelated drivers (`EhStorTcgDrv.sys` contains `gdrv.sys`), and PsExec/PAExec/ProcDump are identified by their own version resource because Sysinternals binaries name each other in EULA text. Its decoy is a copy of Windows' `null.sys` with the version resource renamed, since the fake-PE helper in `tests/make_decoys.py` does not parse as a PE.

The global `regf` skip and `CRED_HIGH_Registry_Hive_Copy_SAM_SYSTEM_SECURITY` share the same fingerprint strings (header path at 0x30..0x70, `ControlSet001`, `PolSecretEncryptionKey`, `Domains`+`Builtin`+`Aliases`). Change them in both places or hive copies become invisible again.

## Endpoint runtime

Everything is hardcoded to `C:\Program Files\YARA\`; the scan scripts, task XMLs and uninstaller all assume that path.

- `install.ps1` copies the package there, registers `YARA-Quick` and `YARA-Full` from the XMLs (SYSTEM, highest privileges, hidden, 2 h execution limit, not on battery), and adds a Defender process exclusion for `yara64.exe`.
- `YARA-Quick` runs daily 14:00 → `scan-quick.ps1` (`C:\Users`, `C:\ProgramData`, `C:\Temp`, `C:\Windows\Temp` + every other fixed drive). `YARA-Full` runs on the 26th of each month → `scan-full.ps1` (all of `C:\` + other fixed drives).
- Both scripts call `yara64.exe -r -p 2 -s -C compiled_rules.yarc <target>` and parse stdout: a line `RULE  PATH` opens a hit, following `0x…` lines are its matched strings.
- The two scan scripts are identical except for `$BaseTargets` and the `ScanType` string. **Any change to one must be mirrored in the other.**
- The XMLs declare `encoding="UTF-16"`; `install.ps1` feeds them to `Register-ScheduledTask -Xml` via `Get-Content | Out-String`, so keep them readable by `Get-Content` with default encoding.
- `System32\Tasks\*` and `wbem\Repository\OBJECTS.DATA` (targets of the persistence rules) are only reached by the full scan, which runs as SYSTEM.

## Output contract (do not change casually)

Each scan writes **one JSON line** (UTF-8, no BOM — AMA requires this) to
`C:\Program Files\YARA\logs\yara_scan_{quick|full}_{COMPUTERNAME}_{dd.MM.yyyy_HH.mm}.json`:

```json
{"TimeGenerated":"<UTC ISO>","Computer":"HOST","ScanType":"quick|full","ScanId":"<guid>",
 "SelfMarker":"__YARA_INTUNE_SELF_OUTPUT_v1__","TotalMatches":0,
 "Matches":[{"Rule":"…","MatchedFile":"…","MatchStrings":"0x..:$s: …; …","MatchCount":1}]}
```

Three consumers depend on these exact names:

1. The Log Analytics custom table / DCR stream `Custom-YARA_CL` (columns TimeGenerated, Computer, ScanType, ScanId, SelfMarker, TotalMatches int, Matches dynamic) and the DCR `logFiles` source that globs `C:\Program Files\YARA\logs\yara_scan_quick_*.json` and `…_full_*.json` with `format: json`. Renaming a field means changing table, stream declaration and transform.
2. `rules/00_global_filters.yar` — the global private rule `SKIP_OWN_SCAN_ARTIFACTS` recognises scanner output by the literal `__YARA_INTUNE_SELF_OUTPUT_v1__` marker and by the co-occurrence of the `"TimeGenerated":"`, `"MatchedFile":"`, `"MatchStrings":"` keys. Changing the marker or those key names re-opens the self-detection loop (scan JSON gets emailed, cached by Outlook, indexed by Windows Search, then matched by the next scan).
3. Sentinel KQL pivots on **rule names**. Renaming a rule breaks analytics; add a new rule instead.

## Ingestion side (lives in Azure, not in this repo)

Windows *client* devices cannot use the VM extension path: AMA is installed with the client installer and authenticates with the device's Entra identity through a tenant-scoped **Monitored Object**. The DCR is associated to that object, not to individual devices. Chain: scheduled task → JSON file → AMA (custom JSON text-log source, via the Data Collection Endpoint) → DCR `transformKql` → `YARA_CL` → Sentinel analytics. The table schema, stream declaration and DCR JSON are not in this repo (they live in Azure); keep them in sync with the output contract above. The current transform keeps only records with `TotalMatches > 0`.
