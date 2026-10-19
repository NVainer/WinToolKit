<#
.SYNOPSIS
  Build + validate the rule set: combine -> compile -> generate decoys -> scan -> assert.

.DESCRIPTION
  1. Extracts yara64/yarac64 from the release zip if they are not next to the package.
  2. Runs combine_rules.ps1 (writes rules\_master.yar) and compiles compiled_rules.yarc.
  3. Generates the synthetic decoy corpus with tests\make_decoys.py (needs Python 3;
     the generator is Python on purpose - a PowerShell version carrying the same
     strings is blocked by AMSI before it can run).
  4. Scans the corpus. Every <category>_* file must fire, every benign_* file must
     stay clean, expectedfp_* files are reported for information.

  Defender real-time protection flags some decoys as they are written (the fake
  .kirbi triggers a behaviour detection). Run this from a folder excluded from
  Defender, or expect a quarantined decoy to show up as "missed".

.PARAMETER KeepDecoys
  Leave tests\decoys in place after the run (default: deleted).

.EXAMPLE
  .\tests\Test-Rules.ps1
  .\tests\Test-Rules.ps1 -KeepDecoys
#>
param(
    [switch]$KeepDecoys
)

$ErrorActionPreference = 'Stop'
$root   = Split-Path $PSScriptRoot -Parent
$yarac  = Join-Path $root 'yarac64.exe'
$yara   = Join-Path $root 'yara64.exe'
$master = Join-Path $root 'rules\_master.yar'
$yarc   = Join-Path $root 'compiled_rules.yarc'
$decoys = Join-Path $PSScriptRoot 'decoys'

if (-not (Test-Path $yarac) -or -not (Test-Path $yara)) {
    $zip = Get-ChildItem $root -Filter 'yara-*-win64.zip' | Select-Object -First 1
    if (-not $zip) { throw "yara binaries not found and no yara-*-win64.zip in $root" }
    Expand-Archive $zip.FullName -DestinationPath $root -Force
}

Push-Location $root
try {
    & (Join-Path $root 'combine_rules.ps1')
    & $yarac -w $master $yarc
    if ($LASTEXITCODE -ne 0) { throw "yarac failed with exit code $LASTEXITCODE" }
    Write-Host ("Compiled {0} ({1:N0} bytes)" -f $yarc, (Get-Item $yarc).Length)

    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
    if (-not $py) { throw 'Python 3 is required to generate the decoy corpus (tests\make_decoys.py)' }
    & $py.Source -I (Join-Path $PSScriptRoot 'make_decoys.py') $decoys $root
    if ($LASTEXITCODE -ne 0) { throw 'decoy generation failed' }
    Start-Sleep -Seconds 2   # let real-time protection settle before scanning

    $hits = @{}
    & $yara -w -r -C $yarc $decoys | ForEach-Object {
        $p = $_ -split ' ', 2
        $f = [IO.Path]::GetFileName($p[1])
        if (-not $hits.ContainsKey($f)) { $hits[$f] = @() }
        $hits[$f] += $p[0]
    }

    $fail = 0
    foreach ($f in (Get-ChildItem $decoys -File | Sort-Object Name)) {
        $r = $hits[$f.Name]
        if ($f.Name -like 'benign_*') {
            if ($r) { Write-Host ("FAIL  benign fired : {0}  <-  {1}" -f $f.Name, ($r -join ', ')) -ForegroundColor Red; $fail++ }
            else    { Write-Host ("ok    clean        : {0}" -f $f.Name) -ForegroundColor DarkGray }
        }
        elseif ($f.Name -like 'expectedfp_*') {
            Write-Host ("info  expected FP  : {0}  <-  {1}" -f $f.Name, ($r -join ', ')) -ForegroundColor Yellow
        }
        else {
            if ($r) { Write-Host ("ok    fired        : {0}  <-  {1}" -f $f.Name, ($r -join ', ')) -ForegroundColor Green }
            else    { Write-Host ("FAIL  missed       : {0}" -f $f.Name) -ForegroundColor Red; $fail++ }
        }
    }

    if (-not $KeepDecoys) { Remove-Item $decoys -Recurse -Force }
    Write-Host ("`nResult: {0} failure(s)" -f $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
    exit $fail
}
finally {
    Pop-Location
}
