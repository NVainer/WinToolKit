/* =============================================================================
   00_global_filters.yar
   -----------------------------------------------------------------------------
   Author : Nati
   Date   : 2026-10-14 (v3 - rebuilt for Windows 11 / Intune / regular users)

   Global private rules are AND-preconditions for every other rule in the set.
   If a global rule's condition is false for a file, nothing else can match it.
   We use them to drop whole classes of files that produce only noise:

     1. This scanner's own output (compiled rules, scan JSON, cached copies).
     2. Kernel-managed / application binary datastores whose contents are
        indexed text and cached web pages, not attacker-written payloads:
          - ESE databases            Windows.db, WebCacheV01.dat, store.db, qmgr.db
          - SQLite databases         browser History/Cookies/Login Data, Teams,
                                     ActivitiesCache.db, StateRepository, wpndatabase
          - Windows event logs       *.evtx (contain scriptblock text of things
                                     that already ran - MDE/Sentinel own that)
          - Outlook data files       *.ost / *.pst (email bodies quoting attacks)
          - Prefetch (compressed)    *.pf
          - Registry hives           NTUSER.DAT, UsrClass.dat, settings.dat ...
            EXCEPT copies of SAM / SYSTEM / SECURITY, which are credential-theft
            artifacts and are matched by CRED_HIGH_Registry_Hive_Copy.

   Everything is magic-byte based. Nothing here is path based, so an attacker
   cannot hide a payload by dropping it into an "allowlisted" folder.
   ============================================================================= */

global private rule SKIP_OWN_SCAN_ARTIFACTS
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        description = "Suppress matches on this scanner's own artifacts (compiled .yarc, scan JSON, Outlook/Search cached copies of either)"

    strings:
        // Scanner JSON envelope - the three keys always co-occur in our records
        $json_tg = "\"TimeGenerated\":\"" ascii
        $json_mf = "\"MatchedFile\":\""   ascii
        $json_ms = "\"MatchStrings\":\""  ascii

        // Explicit self-marker written by scan-quick.ps1 / scan-full.ps1
        $self_marker = "__YARA_INTUNE_SELF_OUTPUT_v1__" ascii wide

    condition:
        not (
            uint32(0) == 0x41524159                      // "YARA" compiled rules magic
            or ( $json_tg and $json_mf and $json_ms )
            or $self_marker
        )
}

global private rule SKIP_SYSTEM_DATASTORES
{
    meta:
        author      = "Nati"
        date        = "2026-10-14"
        description = "Suppress ESE, SQLite, EVTX, PST/OST, compressed prefetch and registry hives (except SAM/SYSTEM/SECURITY copies)"

    strings:
        // Registry hive header "file name" field lives at 0x30..0x70 (UTF-16LE,
        // last 32 chars of the hive path). Copies of the credential hives keep it.
        $hive_sam      = "System32\\Config\\SAM"      wide nocase
        $hive_system   = "System32\\Config\\SYSTEM"   wide nocase
        $hive_security = "System32\\Config\\SECURITY" wide nocase

        // Key-name fingerprints, in case the header name was rewritten. Anchored on
        // the nk cell layout ("nk" + 74 header bytes + key name) so the same words
        // inside value DATA of a SOFTWARE/NTUSER hive do not count.
        $sys_ccs       = /nk[\s\S]{74}ControlSet001/          ascii
        $sec_polkey    = /nk[\s\S]{74}PolSecretEncryptionKey/ ascii
        $sam_rxact     = /nk[\s\S]{74}RXACT/                  ascii
        $sam_domains   = /nk[\s\S]{74}Domains/                ascii

    condition:
        not (
            uint32(4) == 0xEFCDAB89          // ESE database / transaction log (magic at offset 4)
            or uint32(0) == 0x694C5153       // "SQLi" - SQLite 3
            or uint32(0) == 0x46666C45       // "ElfF" - Windows event log (.evtx)
            or uint32(0) == 0x4E444221       // "!BDN" - Outlook PST/OST
            or uint32(0) == 0x044D414D       // "MAM\x04" - compressed prefetch
            or (
                uint32(0) == 0x66676572      // "regf" - registry hive ...
                and not (                    // ... unless it is a SAM/SYSTEM/SECURITY copy
                    $hive_sam in (0x30..0x70)
                    or $hive_system in (0x30..0x70)
                    or $hive_security in (0x30..0x70)
                    or $sys_ccs
                    or $sec_polkey
                    or ( $sam_rxact and $sam_domains )
                )
            )
        )
}
