# scan-full.ps1
chcp 65001 | Out-Null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$Yara = "C:\Program Files\YARA\yara64.exe"
$Rules = "C:\Program Files\YARA\compiled_rules.yarc"
$Out = "C:\Program Files\YARA\logs"; New-Item $Out -ItemType Directory -Force | Out-Null

# Base targets + all other fixed drives (D:\, E:\, …)
$BaseTargets = @("C:\")
$OtherDrives = Get-PSDrive -PSProvider FileSystem |
    Where-Object { $_.Root -ne 'C:\' -and $_.DisplayRoot -eq $null -and $_.Free -ne $null } |
    ForEach-Object { $_.Root.TrimEnd('\') }
$Targets = $BaseTargets + ($OtherDrives | ForEach-Object { "$_\\" })

$hits = @()

foreach ($t in $Targets) {
    if (Test-Path $t) {
        # -r recursive, -p threads, -s show strings, -C compiled rules (.yarc)
        $r = & $Yara -r -p 2 -s -C $Rules $t 2>$null

        $currentHit = $null

        foreach ($line in $r) {
            if ($line -match "^(?<Rule>\S+)\s+(?<File>.+)$" -and $line -notmatch "^0x") {
                if ($currentHit) { $hits += $currentHit }
                $currentHit = [pscustomobject]@{
                    Rule        = $Matches.Rule
                    File        = $Matches.File
                    Match_Found = @()
                }
            } elseif ($line -match "^0x" -and $currentHit) {
                $currentHit.Match_Found += $line.Trim()
            }
        }
        if ($currentHit) { $hits += $currentHit }
    }
}

$hostName  = $env:COMPUTERNAME
$timestamp = Get-Date -Format "dd.MM.yyyy_HH.mm"
$fn        = Join-Path $Out ("yara_scan_full_{0}_{1}.json" -f $hostName, $timestamp)
$nowIso    = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
$scanId    = [Guid]::NewGuid().ToString()

# Self-marker: lets the SKIP_OWN_SCAN_ARTIFACTS global rule recognise this
# file (or any copy of it - Outlook attachment, Windows Search index, etc.)
# as scanner-generated output and suppress all matches on it.
$SelfMarker = '__YARA_INTUNE_SELF_OUTPUT_v1__'

# ---- Envelope-per-scan output schema (v2) -----------------------------------
# One JSON line per SCAN (not per match). All matches nested under .Matches[].
# Sentinel KQL can unpack with: | mv-expand Match = Matches
# Empty-scan record still carries SelfMarker + ScanId so DCR sees every run.
# ---------------------------------------------------------------------------
$matches = @()
foreach ($h in $hits) {
    $matches += [pscustomobject]@{
        Rule         = $h.Rule
        MatchedFile  = $h.File
        MatchStrings = ($h.Match_Found -join '; ')
        MatchCount   = $h.Match_Found.Count
    }
}

$envelope = [pscustomobject]@{
    TimeGenerated = $nowIso
    Computer      = $hostName
    ScanType      = 'full'
    ScanId        = $scanId
    SelfMarker    = $SelfMarker
    TotalMatches  = $matches.Count
    Matches       = @($matches)   # force array even when count == 0 or 1
}

$json = $envelope | ConvertTo-Json -Compress -Depth 6
[System.IO.File]::WriteAllLines($fn, @($json), [System.Text.UTF8Encoding]::new($false))
Write-Host "Saved results to $fn  (ScanId=$scanId, $($matches.Count) matches)"
