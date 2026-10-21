# scan-quick.ps1
chcp 65001 | Out-Null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$Yara = "C:\Program Files\YARA\yara64.exe"
$Rules = "C:\Program Files\YARA\compiled_rules.yarc"
$Out = "C:\Program Files\YARA\logs"; New-Item $Out -ItemType Directory -Force | Out-Null

$BaseTargets = @("C:\Users","C:\ProgramData","C:\Temp","C:\Windows\Temp")
$OtherDrives = Get-PSDrive -PSProvider FileSystem |
    Where-Object { $_.Root -ne 'C:\' -and $_.DisplayRoot -eq $null -and $_.Free -ne $null } |
    ForEach-Object { $_.Root.TrimEnd('\') }
$Targets = $BaseTargets + ($OtherDrives | ForEach-Object { "$_\\" })

$hits = @()

foreach ($t in $Targets) {
    if (Test-Path $t) {
        # -r recursive, -p threads, -s show strings, -C compiled rules (.yarc)
        # -N do not follow junctions/symlinks: C:\Users\All Users -> C:\ProgramData and the
        #    legacy "Application Data" junctions inside each profile are traversable by SYSTEM,
        #    so without -N everything under ProgramData/AppData is scanned and reported twice.
        $r = & $Yara -r -N -p 10 -s -C $Rules $t 2>$null

        $currentHit = $null

        foreach ($line in $r) {
            if ($line -match "^(?<Rule>\S+)\s+(?<File>.+)$" -and $line -notmatch "^0x") {
                # Save previous hit before starting a new one
                if ($currentHit) { $hits += $currentHit }
                $currentHit = [pscustomobject]@{
                    Rule        = $Matches.Rule
                    File        = $Matches.File
                    Match_Found = @()
                }
            } elseif ($line -match "^0x" -and $currentHit) {
                # Nest the match string under the current hit
                $currentHit.Match_Found += $line.Trim()
            }
        }
        # Add the last hit
        if ($currentHit) { $hits += $currentHit }
    }
}

$hashCache = @{}
function Get-HitHash {
    param([string]$Path)
    if ($hashCache.ContainsKey($Path)) { return $hashCache[$Path] }
    $r = [pscustomobject]@{ SHA256=$null; SHA1=$null; CreatedUtc=$null }
    try {
        $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $r.CreatedUtc = $fi.CreationTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
        foreach ($alg in 'SHA256','SHA1') {
            $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                                  [IO.FileShare]'ReadWrite, Delete')
            try     { $r.$alg = (Get-FileHash -InputStream $fs -Algorithm $alg).Hash }
            finally { $fs.Dispose() }
        }
    } catch { }
    $hashCache[$Path] = $r
    $r
}

$hostName  = $env:COMPUTERNAME
$timestamp = Get-Date -Format "dd.MM.yyyy_HH.mm"
$fn        = Join-Path $Out ("yara_scan_quick_{0}_{1}.json" -f $hostName, $timestamp)
$nowIso    = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
$scanId    = [Guid]::NewGuid().ToString()

$SelfMarker = '__YARA_INTUNE_SELF_OUTPUT_v1__'


$matchList = foreach ($h in $hits) {
    $fh = Get-HitHash $h.File
    [pscustomobject]@{
        Rule         = $h.Rule
        MatchedFile  = $h.File
        SHA256       = $fh.SHA256
        SHA1         = $fh.SHA1
        CreatedUtc   = $fh.CreatedUtc
        MatchStrings = ($h.Match_Found -join '; ')
        MatchCount   = $h.Match_Found.Count
    }
}
$envelope = [pscustomobject]@{
    TimeGenerated = $nowIso
    Computer      = $hostName
    ScanType      = 'quick'
    ScanId        = $scanId
    SelfMarker    = $SelfMarker
    TotalMatches  = @($matchList).Count
    Matches       = @($matchList)   # force array even when count == 0 or 1
}

$json = $envelope | ConvertTo-Json -Compress -Depth 6
[System.IO.File]::WriteAllLines($fn, @($json), [System.Text.UTF8Encoding]::new($false))
Write-Host "Saved results to $fn  (ScanId=$scanId, $(@($matchList).Count) matches)"