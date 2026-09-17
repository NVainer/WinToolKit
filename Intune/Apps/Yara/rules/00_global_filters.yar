/* =============================================================================
   00_global_filters.yar
   -----------------------------------------------------------------------------
   Author: Nati
   Date:   2026-05-21

   Global private rules. YARA evaluates a `global` rule as an AND-precondition
   for every other rule in the namespace - if the global rule's condition is
   false on a given file, NO other rule will match that file.

   We use this to suppress the scanner's own output artifacts without resorting
   to path-based allowlisting (which an attacker could exploit). Discrimination
   is purely content-based:

     1) YARA compiled rules files (.yarc)  - magic bytes "YARA" at offset 0
     2) The scanner's JSON log output      - schema fingerprint (3 markers co-occur)
     3) Explicit self-marker emitted by scan-quick.ps1 / scan-full.ps1 (v1+)

   Triggers covered (from prior triage):
     - C:\Program Files\YARA\compiled_rules.yarc when copied/emailed elsewhere
     - C:\Program Files\YARA\logs\yara_scan_*.json when copied/emailed elsewhere
     - C:\Users\*\AppData\Local\Microsoft\Olk\Attachments\... (Outlook download
       of the above two when user emails results to themselves)
     - C:\Users\*\AppData\Local\Microsoft\Olk\EBWebView\...   (Outlook web-view
       cache of the email body containing the JSON)
     - C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.db
       (Windows Search index that indexed any of the above as text)
   ============================================================================= */

global private rule SKIP_OWN_SCAN_ARTIFACTS
{
    meta:
        author      = "Nati"
        date        = "2026-05-21"
        description = "Suppress matches on this scanner's own artifacts (compiled .yarc, scan JSON, Outlook-cached copy, Windows Search index of either)"

    strings:
        // (1) YARA compiled-rules schema marker at offset 0
        //     (covered by uint32(0) check below; string form kept for visibility)

        // (2) Scanner JSON output schema - all three markers appear in every record
        $json_tg = "\"TimeGenerated\":\"" ascii
        $json_mf = "\"MatchedFile\":\""   ascii
        $json_ms = "\"MatchStrings\":\""  ascii

        // (3) Explicit self-marker emitted by scan-quick.ps1 / scan-full.ps1 (v1+)
        //     Unique enough that no malware family includes it accidentally,
        //     specific enough that an attacker has no incentive to embed it.
        $self_marker = "__YARA_INTUNE_SELF_OUTPUT_v1__" ascii wide

    condition:
        not (
            // .yarc file (magic "YARA" = 0x41524159 little-endian)
            uint32(0) == 0x41524159
            // Scanner JSON output (all three markers must co-occur)
            or ( $json_tg and $json_mf and $json_ms )
            // Explicit self-marker
            or $self_marker
        )
}

/* -----------------------------------------------------------------------------
   SKIP_BINARY_SYSTEM_DATASTORES
   -----------------------------------------------------------------------------
   ESE databases (Windows Search index, Edge/IE WebCache, Windows Store DB,
   ESE transaction logs) and Windows registry hives (NTUSER.DAT, SOFTWARE,
   SYSTEM, SAM) are kernel-managed binary stores. Attackers DO modify them,
   but only via APIs (RegSetValue, ESE-aware libs) - they cannot embed raw
   payload bytes into the file structure. Static string scanning of these
   files produces indexed-text noise (paths, cookies, app names, GUIDs) with
   no actionable signal; real attacker activity in registry / browser data
   is detected by registry-aware EDR telemetry, not raw byte scanning.

   Suppresses (from 24.05 scan triage):
     - Windows.db                        (ESE - search index)
     - WebCache V01.log / WebCacheV01.dat (ESE - Edge/IE auth cookies)
     - store.db                          (ESE - Windows Store app catalog)
     - NTUSER.DAT, UsrClass.dat, SOFTWARE, SYSTEM, SAM, SECURITY  (REGF hives)
   ----------------------------------------------------------------------------- */

global private rule SKIP_BINARY_SYSTEM_DATASTORES
{
    meta:
        author      = "Nati"
        date        = "2026-05-24"
        description = "Suppress matches on ESE databases and Windows registry hives (kernel-managed binary stores)"

    condition:
        not (
            // ESE database / transaction log:
            //   bytes 0..3 = checksum (varies), bytes 4..7 = magic 0x89ABCDEF
            //   reading as little-endian uint32 at offset 4 -> 0xEFCDAB89
            uint32(4) == 0xEFCDAB89

            // REGF - Windows registry hive: "regf" ASCII at offset 0
            //   bytes 'r' 'e' 'g' 'f' = 0x72 0x65 0x67 0x66
            //   little-endian uint32 -> 0x66676572
            or uint32(0) == 0x66676572
        )
}
