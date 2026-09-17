/*
   09_cloud_identity_attacks.yar
   --------------------------------------------------------------------------
   Author : Nati
   Date   : 2026-05-24
   Target : Intune-managed Windows 11 endpoints (cloud-only Entra ID users,
            MDE primary EDR).

   Detection focus: on-disk artifacts of Entra ID / M365 identity attacks.
   Bound-pattern design: every rule requires an attack shape (token field
   name + token value structure bound in single regex, OR landing-page
   branding + AiTM-kit-specific obfuscation + non-MS WS back-channel bound).
   Standalone keyword matches are forbidden.

   Categories covered:
     - OAuth device-code phishing tooling (TokenTactics, TokenSmith, EvilTokens, ROADtools)
     - WAM Token Broker cache theft (NetExec, TBRESDecryptor, SpecterBroker)
     - OneAuth cache theft (OAuthBandit and successors)
     - IdentityCache / PRT extraction (cloudap, dsregcmd manipulation)
     - C4 Bomb / AppBound Chrome cookie decryption (CyberArk Feb 2026)
     - AiTM phish landing pages cached in browser (Tycoon, Mamba, Whisper)
     - Staged refresh-token / ESTSAUTH files on disk

   ESE-DB and REGF-hive global suppression lives in 00_global_filters.yar.
   -------------------------------------------------------------------------- */

import "pe"


/* -----------------------------------------------------------------------------
   CLOUD_HIGH_OAuth_DeviceCode_Phish_Tool
   PS scripts performing raw OAuth 2.0 device-code flow against
   login.microsoftonline.com. Bound: HTTP verb + MS login host + devicecode
   endpoint in a single regex, OR grant_type + endpoint bound, OR login host
   + endpoint + FOCI client-id bound.
   ----------------------------------------------------------------------------- */
rule CLOUD_HIGH_OAuth_DeviceCode_Phish_Tool
{
    meta:
        author      = "Nati"
        date        = "2026-05-24"
        category    = "cloud_identity,credential_access"
        severity    = "high"
        description = "Bound: PS web-call to login.microsoftonline.com /oauth2/devicecode endpoint with grant_type or FOCI client-id"
        mitre       = "T1528,T1078.004,T1606"
        reference   = "https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html"

    strings:
        // Full canonical bind: PS web call + MS login host + devicecode endpoint
        $bound_full = /Invoke-(WebRequest|RestMethod|Method)\s+[^\r\n]{0,200}https?:\/\/login\.microsoftonline\.com\/(common|organizations|consumers|[0-9a-f-]{36})\/oauth2(\/v2\.0)?\/devicecode/is ascii wide

        // grant_type bound to MS login host within 200 chars (either order)
        $bound_grant1 = /urn:ietf:params:oauth:grant-type:device_code[^\r\n]{0,200}login\.microsoftonline\.com/is ascii wide
        $bound_grant2 = /login\.microsoftonline\.com[^\r\n]{0,200}urn:ietf:params:oauth:grant-type:device_code/is ascii wide

        // MS login host + devicecode/token endpoint + FOCI client-id bound (any order, two regex variants)
        $bound_foci1 = /login\.microsoftonline\.com[^\r\n]{0,200}\/oauth2(\/v2\.0)?\/(devicecode|token)[^\r\n]{0,200}(d3590ed6-52b3-4102-aeff-aad2292ab01c|1950a258-227b-4e31-a9cf-717495945fc2|1b730954-1685-4b74-9bfd-dac224a7b894|04b07795-8ddb-461a-bbee-02f9e1bf7b46|29d9ed98-a469-4536-ade2-f981bc1d605e|1fec8e78-bce4-4aaf-ab1b-5451cc387264)/is ascii wide
        $bound_foci2 = /(d3590ed6-52b3-4102-aeff-aad2292ab01c|1950a258-227b-4e31-a9cf-717495945fc2|1b730954-1685-4b74-9bfd-dac224a7b894|04b07795-8ddb-461a-bbee-02f9e1bf7b46|29d9ed98-a469-4536-ade2-f981bc1d605e|1fec8e78-bce4-4aaf-ab1b-5451cc387264)[^\r\n]{0,200}login\.microsoftonline\.com[^\r\n]{0,200}\/oauth2(\/v2\.0)?\/(devicecode|token)/is ascii wide

    condition:
        filesize < 2MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and ( $bound_full or $bound_grant1 or $bound_grant2 or $bound_foci1 or $bound_foci2 )
}


/* -----------------------------------------------------------------------------
   CLOUD_HIGH_TokenTactics_Module
   TokenTactics / TokenTacticsV2 PS module. Bound: tool-distinct function
   name AND a second TokenTactics-distinct function or module path within
   proximity. No standalone single-fn match.
   ----------------------------------------------------------------------------- */
rule CLOUD_HIGH_TokenTactics_Module
{
    meta:
        author      = "Nati"
        date        = "2026-05-24"
        category    = "cloud_identity,credential_access"
        severity    = "high"
        description = "Bound: TokenTactics/V2 distinct refresh-token function names co-occurring or with module path"
        mitre       = "T1528,T1550.001"
        reference   = "https://github.com/f-bader/TokenTacticsV2"

    strings:
        $fn1  = /Invoke-RefreshToMSGraphToken\b/i ascii wide
        $fn2  = /Invoke-RefreshToAzureManagementToken\b/i ascii wide
        $fn3  = /Invoke-RefreshToTeamsToken\b/i ascii wide
        $fn4  = /Invoke-RefreshToOfficeManagementToken\b/i ascii wide
        $fn5  = /Invoke-RefreshToOfficeAppsToken\b/i ascii wide
        $fn6  = /Invoke-RefreshToOutlookToken\b/i ascii wide
        $fn7  = /Invoke-RefreshToOneDriveToken\b/i ascii wide
        $fn8  = /Invoke-RefreshToSharePointToken\b/i ascii wide
        $fn9  = /Invoke-RefreshToYammerToken\b/i ascii wide
        $fn10 = /Invoke-RefreshToIntuneToken\b/i ascii wide
        $fn11 = /Invoke-RefreshToFamilyToken\b/i ascii wide
        $fn12 = /Invoke-DeviceCodeAttack\b/i ascii wide

        // Module-path bind to a TokenTactics fn within 4KB
        $bound_modfn = /\\WindowsPowerShell\\Modules\\TokenTactics(V2)?\\[^\r\n]{0,4000}Invoke-(RefreshTo[A-Za-z]+Token|DeviceCodeAttack)\b/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and ( 2 of ( $fn* ) or $bound_modfn )
}


/* -----------------------------------------------------------------------------
   CLOUD_HIGH_TokenSmith_ROADtools_Artifact
   Bound: ROADtools/TokenSmith tool name AND tool-specific argument or
   artifact-file token within proximity. Tool name alone (esp. common words
   like roadtx in news copy) is insufficient.
   ----------------------------------------------------------------------------- */
rule CLOUD_HIGH_TokenSmith_ROADtools_Artifact
{
    meta:
        author      = "Nati"
        date        = "2026-05-24"
        category    = "cloud_identity,credential_access,discovery"
        severity    = "high"
        description = "Bound: ROADtools/TokenSmith/EvilTokens tool name with tool-specific argument or artifact-file token"
        mitre       = "T1528,T1087.004,T1606"
        reference   = "https://github.com/JumpsecLabs/TokenSmith ; https://github.com/dirkjanm/ROADtools"

    strings:
        // TokenSmith: name bound to invocation/file marker
        $b_ts1 = /\bTokenSmith\b[^\r\n]{0,200}(Get-TokenSmithToken|TokenSmith\.ps1|--access-token|--device-code|tokens\.json)/is ascii wide
        $b_ts2 = /(Get-TokenSmithToken|TokenSmith\.ps1)[^\r\n]{0,200}\bTokenSmith\b/is ascii wide

        // ROADtools: roadrecon/roadtx/roadlib bound to tool-specific switch or auth file
        $b_rt1 = /\b(roadrecon|roadtx|roadlib)\b[^\r\n]{0,200}(--access-token|--refresh-token|--device-code|--tokens-stdin|\.roadtools_auth|tokens\.json|roadrecon\.db)/is ascii wide
        $b_rt2 = /(--access-token|--refresh-token|--device-code|--tokens-stdin|\.roadtools_auth|roadrecon\.db)[^\r\n]{0,200}\b(roadrecon|roadtx|roadlib)\b/is ascii wide

        // ROADtools auth-scope literal bound to roadtools/roadlib/roadtx in proximity
        $b_rt3 = /\brequestaadrefreshtoken\b[^\r\n]{0,200}\b(road(tools|lib|tx|recon))\b/is ascii wide
        $b_rt4 = /\b(road(tools|lib|tx|recon))\b[^\r\n]{0,200}\brequestaadrefreshtoken\b/is ascii wide

        // EvilTokens (Feb 2026 PhaaS): name bound to a tool-specific marker
        $b_et1 = /\bEvilTokens\b[^\r\n]{0,200}(eviltokens\.py|--tenant-id|--device-code|tokens\.json)/is ascii wide
        $b_et2 = /(eviltokens\.py|--tenant-id|--device-code)[^\r\n]{0,200}\bEvilTokens\b/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and 1 of ( $b_ts1, $b_ts2, $b_rt1, $b_rt2, $b_rt3, $b_rt4, $b_et1, $b_et2 )
}


/* -----------------------------------------------------------------------------
   CLOUD_HIGH_WAM_TokenBroker_Cache_Theft
   Bound: WAM TokenBroker cache path AND a read/exfil verb in proximity,
   OR a tool-distinct name bound to the cache path. No standalone path or
   single-keyword match.
   ----------------------------------------------------------------------------- */
rule CLOUD_HIGH_WAM_TokenBroker_Cache_Theft
{
    meta:
        author      = "Nati"
        date        = "2026-05-24"
        category    = "cloud_identity,credential_access"
        severity    = "high"
        description = "Bound: WAM TokenBroker cache path with read/exfil verb (Copy-Item, ReadAllBytes, sqlite3_open, TokenBroker /dump)"
        mitre       = "T1555,T1528,T1539"
        reference   = "https://www.netexec.wiki/smb-protocol/obtaining-credentials/dump-token-broker-cache"

    strings:
        // Bind: TokenBroker cache path or .tbres + read/exfil verb (either order)
        $b_path_read1 = /\\Microsoft\\TokenBroker\\Cache\\[^\r\n]{0,200}(Copy-Item|\[IO\.File\]::ReadAllBytes|sqlite3_open|TokenBroker(\.exe)?\s+\/dump|CryptUnprotectData|ProtectedData(\.|\]::)\s*Unprotect|BCryptDecrypt|dpapi-ng)/is ascii wide
        $b_path_read2 = /(Copy-Item|\[IO\.File\]::ReadAllBytes|sqlite3_open|TokenBroker(\.exe)?\s+\/dump|CryptUnprotectData|ProtectedData(\.|\]::)\s*Unprotect|BCryptDecrypt|dpapi-ng)[^\r\n]{0,200}\\Microsoft\\TokenBroker\\Cache\\/is ascii wide
        $b_tbres_read1 = /\.tbres\b[^\r\n]{0,200}(Copy-Item|\[IO\.File\]::ReadAllBytes|sqlite3_open|CryptUnprotectData|ProtectedData(\.|\]::)\s*Unprotect|BCryptDecrypt|dpapi-ng)/is ascii wide
        $b_tbres_read2 = /(Copy-Item|\[IO\.File\]::ReadAllBytes|sqlite3_open|CryptUnprotectData|ProtectedData(\.|\]::)\s*Unprotect|BCryptDecrypt|dpapi-ng)[^\r\n]{0,200}\.tbres\b/is ascii wide

        // Tool-name bind to cache path
        $b_tool_path1 = /\b(TBRESDecryptor|SpecterBroker|Decrypt-?TBRES|dump[-_]tokenbroker)\b[^\r\n]{0,400}(\\Microsoft\\TokenBroker\\Cache\\|\.tbres)/is ascii wide
        $b_tool_path2 = /(\\Microsoft\\TokenBroker\\Cache\\|\.tbres)[^\r\n]{0,400}\b(TBRESDecryptor|SpecterBroker|Decrypt-?TBRES|dump[-_]tokenbroker)\b/is ascii wide

    condition:
        filesize < 50MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and 1 of ( $b_path_read1, $b_path_read2, $b_tbres_read1, $b_tbres_read2, $b_tool_path1, $b_tool_path2 )
}


/* -----------------------------------------------------------------------------
   CLOUD_HIGH_OneAuth_IdentityCache_Theft
   Bound: OneAuth or IdentityCache path AND a read/exfil verb in proximity,
   OR a tool-distinct name bound to the cache path/file.
   ----------------------------------------------------------------------------- */
rule CLOUD_HIGH_OneAuth_IdentityCache_Theft
{
    meta:
        author      = "Nati"
        date        = "2026-05-24"
        category    = "cloud_identity,credential_access"
        severity    = "high"
        description = "Bound: OneAuth/IdentityCache path with read/exfil verb (Copy-Item, ReadAllBytes, sqlite3_open, sekurlsa::cloudap)"
        mitre       = "T1555,T1528,T1552.004"
        reference   = "https://github.com/anak0ndah/OAuthBandit"

    strings:
        // OneAuth / IdentityCache path bound to read/exfil verb
        $b_path_read1 = /\\Microsoft\\(OneAuth|IdentityCache)\\[^\r\n]{0,200}(Copy-Item|\[IO\.File\]::ReadAllBytes|sqlite3_open|CryptUnprotectData|ProtectedData(\.|\]::)\s*Unprotect|Get-ChildItem|robocopy|xcopy)/is ascii wide
        $b_path_read2 = /(Copy-Item|\[IO\.File\]::ReadAllBytes|sqlite3_open|CryptUnprotectData|ProtectedData(\.|\]::)\s*Unprotect|Get-ChildItem|robocopy|xcopy)[^\r\n]{0,200}\\Microsoft\\(OneAuth|IdentityCache)\\/is ascii wide

        // OneAuth-specific cache filenames bound to read verb
        $b_file_read1 = /(accounts\.json|msal_token_cache\.bin|OneAuth(MsaUser|AadUser|Account))[^\r\n]{0,200}(Copy-Item|\[IO\.File\]::ReadAllBytes|sqlite3_open|CryptUnprotectData|ProtectedData(\.|\]::)\s*Unprotect)/is ascii wide
        $b_file_read2 = /(Copy-Item|\[IO\.File\]::ReadAllBytes|sqlite3_open|CryptUnprotectData|ProtectedData(\.|\]::)\s*Unprotect)[^\r\n]{0,200}(accounts\.json|msal_token_cache\.bin|OneAuth(MsaUser|AadUser|Account))/is ascii wide

        // Tool-name bind: OAuthBandit / Mimikatz cloudap with OneAuth/IdentityCache path
        $b_tool1 = /\b(OAuthBandit|sekurlsa::cloudap|dpapi::cloudapkd)\b[^\r\n]{0,400}(\\Microsoft\\(OneAuth|IdentityCache)\\|accounts\.json|msal_token_cache\.bin)/is ascii wide
        $b_tool2 = /(\\Microsoft\\(OneAuth|IdentityCache)\\|accounts\.json|msal_token_cache\.bin)[^\r\n]{0,400}\b(OAuthBandit|sekurlsa::cloudap|dpapi::cloudapkd)\b/is ascii wide

    condition:
        filesize < 50MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and 1 of ( $b_path_read1, $b_path_read2, $b_file_read1, $b_file_read2, $b_tool1, $b_tool2 )
}


/* -----------------------------------------------------------------------------
   CLOUD_HIGH_C4Bomb_Chrome_AppBound_Decrypt
   Bound: C4Bomb-distinct COM CLSID OR ABE symbol AND Chrome Local State
   path AND AppBound decrypt API call (CryptUnprotectData / padding-oracle)
   bound in proximity. No standalone keyword match.
   ----------------------------------------------------------------------------- */
rule CLOUD_HIGH_C4Bomb_Chrome_AppBound_Decrypt
{
    meta:
        author      = "Nati"
        date        = "2026-05-24"
        category    = "cloud_identity,credential_access"
        severity    = "high"
        description = "Bound: C4Bomb/ABE symbol + Chrome Local State path + AppBound decrypt API call all within proximity"
        mitre       = "T1539,T1555.003"
        reference   = "https://www.cyberark.com/resources/threat-research-blog/c4-bomb-blowing-up-chromes-appbound-cookie-encryption"

    strings:
        // Full bind: ABE/C4Bomb symbol + Local State path + decrypt API (within 800 chars)
        $b_full1 = /(\bC4Bomb\b|app_bound_encrypted_key|WebKitMasterKey|AppBoundKey|elevation_service\.exe|browser_install_id)[^\r\n]{0,800}\\(Google\\Chrome|Microsoft\\Edge)\\User Data\\Local State[^\r\n]{0,800}(CryptUnprotectData|padding_oracle|PaddingOracle|IElevator|GoogleChromeElevator)/is ascii wide
        $b_full2 = /\\(Google\\Chrome|Microsoft\\Edge)\\User Data\\Local State[^\r\n]{0,800}(\bC4Bomb\b|app_bound_encrypted_key|WebKitMasterKey|AppBoundKey|elevation_service\.exe|browser_install_id)[^\r\n]{0,800}(CryptUnprotectData|padding_oracle|PaddingOracle|IElevator|GoogleChromeElevator)/is ascii wide
        $b_full3 = /(CryptUnprotectData|padding_oracle|PaddingOracle|IElevator|GoogleChromeElevator)[^\r\n]{0,800}\\(Google\\Chrome|Microsoft\\Edge)\\User Data\\Local State[^\r\n]{0,800}(\bC4Bomb\b|app_bound_encrypted_key|WebKitMasterKey|AppBoundKey)/is ascii wide

        // C4Bomb-specific Chrome elevation-service COM CLSID bound to AppBound key
        $b_clsid1 = /(708860E0-F641-4611-8895-7D867DD3675B|463ABECF-410D-407F-8AF5-0DF35A005CC8|A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C)[^\r\n]{0,400}(app_bound_encrypted_key|AppBoundKey|WebKitMasterKey)/is ascii wide
        $b_clsid2 = /(app_bound_encrypted_key|AppBoundKey|WebKitMasterKey)[^\r\n]{0,400}(708860E0-F641-4611-8895-7D867DD3675B|463ABECF-410D-407F-8AF5-0DF35A005CC8|A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C)/is ascii wide

    condition:
        filesize < 10MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and 1 of ( $b_full1, $b_full2, $b_full3, $b_clsid1, $b_clsid2 )
}


/* -----------------------------------------------------------------------------
   CLOUD_HIGH_PRT_Extraction_Cmd
   Bound: dsregcmd offensive flag combo bound, OR cloudap Mimikatz verb
   bound to IdentityStore/CloudDomainJoin reg path, OR PRT cookie field
   bound to IdentityStore reg path. No standalone single-keyword match.
   ----------------------------------------------------------------------------- */
rule CLOUD_HIGH_PRT_Extraction_Cmd
{
    meta:
        author      = "Nati"
        date        = "2026-05-24"
        category    = "cloud_identity,credential_access"
        severity    = "high"
        description = "Bound: dsregcmd offensive flag combo OR cloudap verb with IdentityStore path OR PRT cookie with reg path"
        mitre       = "T1528,T1552.004,T1606"
        reference   = "https://github.com/Cloud-Architekt/AzureAD-Attack-Defense/blob/main/ReplayOfPrimaryRefreshToken.md"

    strings:
        // dsregcmd offensive flag combinations (single regex, internally bound)
        $b_dr1 = /dsregcmd\s+\/debug\s+\/leaveJoin\b/i ascii wide
        $b_dr2 = /dsregcmd\s+\/refreshprt\b/i ascii wide
        $b_dr3 = /dsregcmd\s+\/(forcerecovery|debug|leave|join)\b[^\r\n]{0,200}HK(LM|EY_LOCAL_MACHINE)\\(SOFTWARE|System)\\Microsoft\\(IdentityStore\\LoadParameters|Cryptography\\OfflineDomainJoin)/is ascii wide
        $b_dr4 = /HK(LM|EY_LOCAL_MACHINE)\\(SOFTWARE|System)\\Microsoft\\(IdentityStore\\LoadParameters|Cryptography\\OfflineDomainJoin)[^\r\n]{0,200}dsregcmd\s+\/(forcerecovery|debug|leave|join)\b/is ascii wide

        // Mimikatz cloudap verb bound to IdentityStore / CloudDomainJoin reg path
        $b_mm1 = /(sekurlsa::cloudap|dpapi::cloudapkd)\b[^\r\n]{0,400}HK(LM|EY_LOCAL_MACHINE)\\(SOFTWARE|System|SYSTEM)\\(Microsoft\\IdentityStore\\LoadParameters|Microsoft\\Cryptography\\OfflineDomainJoin|CurrentControlSet\\Control\\CloudDomainJoin\\TenantInfo)/is ascii wide
        $b_mm2 = /HK(LM|EY_LOCAL_MACHINE)\\(SOFTWARE|System|SYSTEM)\\(Microsoft\\IdentityStore\\LoadParameters|Microsoft\\Cryptography\\OfflineDomainJoin|CurrentControlSet\\Control\\CloudDomainJoin\\TenantInfo)[^\r\n]{0,400}(sekurlsa::cloudap|dpapi::cloudapkd)\b/is ascii wide

        // PRT cookie field bound (cookie-syntax) to IdentityStore reg path or 2+ PRT fields
        $b_prt1 = /(\bSet-Cookie:\s*|^|;\s*)x-ms-RefreshTokenCredential\s*=\s*[A-Za-z0-9_\-\.+\/=]{40,}/i ascii wide
        $b_prt2 = /(\bSet-Cookie:\s*|^|;\s*)ESTSAUTHPERSISTENT\s*=\s*[A-Za-z0-9_\-\.+\/=]{40,}/i ascii wide
        $b_prt3 = /"PrimaryRefreshToken"\s*:\s*"[A-Za-z0-9_\-\.+\/=]{40,}"/ ascii wide

        $b_prt_path1 = /(x-ms-RefreshTokenCredential|PrimaryRefreshToken)[^\r\n]{0,200}HK(LM|EY_LOCAL_MACHINE)\\(SOFTWARE|System|SYSTEM)\\(Microsoft\\IdentityStore\\LoadParameters|CurrentControlSet\\Control\\CloudDomainJoin\\TenantInfo)/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and (
            $b_dr1
            or $b_dr2
            or $b_dr3
            or $b_dr4
            or $b_mm1
            or $b_mm2
            or $b_prt_path1
            or ( $b_prt1 and $b_prt2 )
            or ( $b_prt3 and ( $b_prt1 or $b_prt2 ) )
        )
}


/* -----------------------------------------------------------------------------
   CLOUD_HIGH_AiTM_Phish_Landing_Cached
   Bound: 2+ MS branding strings AND (AiTM-kit-specific obfuscation OR
   non-MS WS back-channel + credential handling). Standalone "Tycoon"
   keyword is rejected; it now requires 2+ branding strings AND a non-MS
   WS host OR credential-handling script in proximity.
   ----------------------------------------------------------------------------- */
rule CLOUD_HIGH_AiTM_Phish_Landing_Cached
{
    meta:
        author      = "Nati"
        date        = "2026-05-24"
        category    = "cloud_identity,initial_access"
        severity    = "high"
        description = "Bound: MS branding + AiTM-kit obfuscation OR non-MS WS back-channel + credential-handling JS"
        mitre       = "T1539,T1557.003,T1606"
        reference   = "https://blog.sekoia.io/tycoon-2fa-an-in-depth-analysis-of-the-latest-version-of-the-aitm-phishing-kit/"

    strings:
        // MS branding (legitimate-looking copy used by phish landing pages)
        $ms1 = /login\.microsoftonline\.com/i ascii wide
        $ms2 = /Sign in to your account/i ascii wide
        $ms3 = "office_logo" ascii wide nocase
        $ms4 = /Microsoft\s+365/i ascii wide
        $ms5 = /Pick an account\b/i ascii wide
        $ms6 = /Keep me signed in\b/i ascii wide

        // AiTM-kit-distinct obfuscation / anti-debug motifs
        $tk_obf1 = /var\s+_0x[a-f0-9]{4,6}\s*=\s*\[/i ascii wide                                                  // Tycoon obfuscator array
        $tk_obf2 = /window\.outerHeight\s*-\s*window\.innerHeight\s*>\s*200/i ascii wide                          // devtools detection
        $tk_obf3 = /setInterval\s*\(\s*function\s*\(\s*\)\s*\{\s*debugger\s*;/i ascii wide                        // anti-debug
        $tk_obf4 = /HeadlessChrome/i ascii wide                                                                   // Sneaky 2FA UA check
        $tk_obf5 = /crypto\.subtle\.decrypt\s*\(\s*\{\s*name\s*:\s*['"](AES-CBC|AES-GCM)['"]/i ascii wide         // Whisper 2FA in-browser decrypt

        // Tycoon kit name bound to a kit-distinct obfuscator or AiTM marker
        $tk_bound1 = /\bTycoon\b[^\r\n]{0,400}(var\s+_0x[a-f0-9]{4,6}\s*=\s*\[|wss?:\/\/|socket\.io|ESTSAUTH)/is ascii wide
        $tk_bound2 = /(var\s+_0x[a-f0-9]{4,6}\s*=\s*\[|wss?:\/\/|socket\.io|ESTSAUTH)[^\r\n]{0,400}\bTycoon\b/is ascii wide

        // Non-MS WS back-channel
        $ws_any = /wss?:\/\/[a-z0-9.\-]{4,80}\.(com|net|org|io|cc|xyz|top|me|app|info|biz|ru|cn|club|live|cloud|shop|click|site|online)\b/i ascii wide
        $ws_ms  = /wss?:\/\/[a-z0-9.\-]+\.(microsoft|microsoftonline|office|sharepoint|live|outlook|azure|skype|teams|onedrive|onmicrosoft)\.com\b/i ascii wide
        $sio    = "socket.io.min.js" ascii wide nocase

        // Credential-handling JS bound to ESTSAUTH cookie syntax or POST of password/token
        $cred1 = /document\.cookie\s*=\s*['"]ESTSAUTH(PERSISTENT)?\s*=/i ascii wide
        $cred2 = /fetch\s*\(\s*['"]https?:\/\/[^'"\r\n]+['"][^\r\n]{0,200}body\s*:\s*JSON\.stringify\s*\(\s*\{[^\r\n]{0,200}(password|username|token)/is ascii wide
        $cred3 = /XMLHttpRequest[^\r\n]{0,200}open\s*\(\s*['"]POST['"][^\r\n]{0,200}(password|username|token)/is ascii wide

    condition:
        filesize < 20MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and (
            // Strong branding + AiTM-kit-distinct obfuscation
            ( 2 of ( $ms* ) and 2 of ( $tk_obf1, $tk_obf2, $tk_obf3, $tk_obf4, $tk_obf5 ) )
            // Branding + non-MS WS back-channel + credential handling
            or ( 2 of ( $ms* ) and $ws_any and not $ws_ms and ( $cred1 or $cred2 or $cred3 ) )
            // Branding + socket.io + credential handling
            or ( 2 of ( $ms* ) and $sio and ( $cred1 or $cred2 or $cred3 ) )
            // Tycoon kit name bound to kit-distinct marker AND 2+ branding strings AND
            // (non-MS WS OR credential-handling script)
            or ( ( $tk_bound1 or $tk_bound2 ) and 2 of ( $ms* ) and ( ( $ws_any and not $ws_ms ) or $cred1 or $cred2 or $cred3 ) )
        )
}


/* -----------------------------------------------------------------------------
   CLOUD_HIGH_Refresh_Token_Staged_On_Disk
   Bound: every token context string lives inside a properly-structured
   JSON field or cookie syntax. Bare ESTSAUTH substring is forbidden;
   match requires cookie-syntax with value structure. Bare JWT headers
   must co-occur with a structured token field.
   ----------------------------------------------------------------------------- */
rule CLOUD_HIGH_Refresh_Token_Staged_On_Disk
{
    meta:
        author      = "Nati"
        date        = "2026-05-24"
        category    = "cloud_identity,credential_access,collection"
        severity    = "high"
        description = "Bound: Entra refresh/access/id token in JSON field shape OR ESTSAUTH in cookie-syntax with value structure"
        mitre       = "T1528,T1539,T1074.001"
        reference   = "https://learn.microsoft.com/en-us/entra/identity/devices/protecting-tokens-microsoft-entra-id"

    strings:
        // JWT v1/v2 header literals are NOT declared as standalone strings - the
        // bound regexes ($b_hdr_tok1 / $b_hdr_tok2) encode them inline next to a
        // structured token-field shape, so a bare "eyJ..." in indexed text cannot
        // fire this rule on its own.

        // Structured JSON field shapes: field-name + quoted value with token charset/length
        $tok1 = /"refresh_token"\s*:\s*"[A-Za-z0-9_\-\.+\/=]{200,}"/ ascii wide
        $tok2 = /"access_token"\s*:\s*"eyJ[A-Za-z0-9_\-\.]{40,}\.[A-Za-z0-9_\-\.]{20,}"/ ascii wide
        $tok3 = /"id_token"\s*:\s*"eyJ[A-Za-z0-9_\-\.]{40,}\.[A-Za-z0-9_\-\.]{20,}"/ ascii wide
        $tok4 = /"refreshToken"\s*:\s*"[A-Za-z0-9_\-\.+\/=]{200,}"/ ascii wide
        $tok5 = /"accessToken"\s*:\s*"eyJ[A-Za-z0-9_\-\.]{40,}\.[A-Za-z0-9_\-\.]{20,}"/ ascii wide

        // ESTSAUTH / ESTSAUTHPERSISTENT in cookie syntax with value charset and length
        $bound_est = /(\bSet-Cookie:\s*|^|;\s*)ESTSAUTH(PERSISTENT)?\s*=\s*[A-Za-z0-9_\-\.+\/=]{40,}/i ascii wide
        // x-ms-RefreshTokenCredential in cookie or JSON shape with value structure
        $bound_xmsrt = /(\bSet-Cookie:\s*|^|;\s*|")x-ms-RefreshTokenCredential("\s*:\s*"|\s*=\s*)[A-Za-z0-9_\-\.+\/=]{40,}/i ascii wide

        // Entra audience / authority host (binds tokens to MS context)
        $aud1 = "https://graph.microsoft.com" ascii wide nocase
        $aud2 = "https://management.azure.com" ascii wide nocase
        $aud3 = "https://manage.office.com"    ascii wide nocase
        $aud4 = /login\.microsoftonline\.com/i ascii wide

        // Bind JWT header to a structured token field within 400 chars (single regex)
        $b_hdr_tok1 = /eyJ(0eXAiOiJKV1Q|hbGciOi|raWQiOi)[A-Za-z0-9_\-\.+\/=]{0,400}"(refresh_token|access_token|id_token|refreshToken|accessToken)"\s*:/is ascii wide
        $b_hdr_tok2 = /"(refresh_token|access_token|id_token|refreshToken|accessToken)"\s*:\s*"[^"\r\n]{0,200}eyJ(0eXAiOiJKV1Q|hbGciOi|raWQiOi)/is ascii wide

    condition:
        filesize < 5MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and (
            // Structured token field + Entra audience
            ( 1 of ( $tok1, $tok2, $tok3, $tok4, $tok5 ) and 1 of ( $aud* ) )
            // JWT header bound inside (or right next to) a structured token field
            or $b_hdr_tok1
            or $b_hdr_tok2
            // Cookie-syntax ESTSAUTH/x-ms-RefreshTokenCredential + Entra audience
            or ( ( $bound_est or $bound_xmsrt ) and 1 of ( $aud* ) )
            // Two cookie-bound markers together
            or ( $bound_est and $bound_xmsrt )
            // Two camelCase MSAL/ROADtools token fields together
            or ( $tok4 and $tok5 )
        )
}


/* -----------------------------------------------------------------------------
   CLOUD_HIGH_DeviceCode_Phish_LurePage_HTML
   Bound: landing-page HTML AND user_code field in canonical format
   (AAAA-AAAA / AAA-AAAAA) AND lure copy ("Enter the code",
   microsoft.com/devicelogin) AND MS branding bound.
   ----------------------------------------------------------------------------- */
rule CLOUD_HIGH_DeviceCode_Phish_LurePage_HTML
{
    meta:
        author      = "Nati"
        date        = "2026-05-24"
        category    = "cloud_identity,initial_access,phishing"
        severity    = "high"
        description = "Bound: HTML lure with devicelogin URL + canonical user_code format + lure copy + MS branding"
        mitre       = "T1566.002,T1528"
        reference   = "https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html"

    strings:
        // HTML container shape (gates the rule to actual landing-page HTML)
        $html1 = /<html\b/i ascii wide
        $html2 = /<body\b/i ascii wide
        $html3 = /<!DOCTYPE\s+html/i ascii wide

        // Lure URL to MS devicelogin endpoint
        $url1 = /https?:\/\/microsoft\.com\/devicelogin\b/i ascii wide
        $url2 = /https?:\/\/aka\.ms\/devicelogin\b/i ascii wide
        $url3 = /https?:\/\/login\.microsoftonline\.com\/common\/oauth2\/deviceauth\b/i ascii wide

        // Lure copy in proximity to a devicelogin URL or canonical user_code
        $b_copy1 = /Enter the code\b[^\r\n]{0,400}(microsoft\.com\/devicelogin|aka\.ms\/devicelogin|\b[A-Z0-9]{4}-[A-Z0-9]{4}\b|\b[A-Z0-9]{3}-[A-Z0-9]{5}\b)/is ascii wide
        $b_copy2 = /(microsoft\.com\/devicelogin|aka\.ms\/devicelogin|\b[A-Z0-9]{4}-[A-Z0-9]{4}\b|\b[A-Z0-9]{3}-[A-Z0-9]{5}\b)[^\r\n]{0,400}Enter the code\b/is ascii wide
        $b_copy3 = /Code expires in \d+ minutes?\b/i ascii wide
        $b_copy4 = /sign\s+in\s+to\s+your\s+(work|school|Microsoft)\s+account/i ascii wide

        // Canonical user_code shapes: AAAA-AAAA, AAA-AAAAA, or JSON user_code field
        $uc1 = /\b[A-Z0-9]{4}-[A-Z0-9]{4}\b/  ascii wide
        $uc2 = /\b[A-Z0-9]{3}-[A-Z0-9]{5}\b/  ascii wide
        $uc3 = /["']user_code["']\s*:\s*["'][A-Z0-9]{3,4}-?[A-Z0-9]{4,5}["']/i ascii wide

        // MS branding
        $ms1 = /login\.microsoftonline\.com/i ascii wide
        $ms2 = /Sign in to your account/i ascii wide
        $ms3 = "office_logo" ascii wide nocase
        $ms4 = /Microsoft\s+365/i ascii wide
        $ms5 = /Pick an account\b/i ascii wide

    condition:
        filesize < 20MB
        and not uint16(0) == 0x5A4D and not uint32(0) == 0x464C457F
        and 1 of ( $html1, $html2, $html3 )
        and 1 of ( $url1, $url2, $url3 )
        and 1 of ( $uc1, $uc2, $uc3 )
        and 1 of ( $b_copy1, $b_copy2, $b_copy3, $b_copy4 )
        and 1 of ( $ms1, $ms2, $ms3, $ms4, $ms5 )
}
