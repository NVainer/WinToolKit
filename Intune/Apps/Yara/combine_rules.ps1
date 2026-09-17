$dir = ".\rules"
$master = Join-Path $dir "_master.yar"

# create _master.yar that:
#  - excludes itself (files starting with "_")
#  - excludes rule sets that require external vars or THOR metadata
# Detection of external-variable usage must distinguish:
#   - TRUE positives (rule references YARA externals):
#       filename matches /.../   filepath contains "..."   extension == ".."   owner == "..."
#   - FALSE positives (rule references PowerShell/.NET tokens of similar name):
#       FileName  (cmdlet pipeline property)  Get-MpPreference -ExclusionExtension
#       FileSystem.GetFile.FullName            ScriptExtensions
# Match only when the lowercase external-var name is followed by a YARA operator
# (matches, contains, ==, !=, startswith, endswith, icontains, iequals).
$badName    = '(_ext_vars|thor_inverse_matches|renamed|configured_vulns|yara-rules_vuln_drivers)'
$badContent = '(?m)\b(filename|filepath|extension|owner)\s+(matches|contains|icontains|startswith|endswith|iequals|istartswith|iendswith|==|!=)'

# build include lines only for safe .yar
$includeLines = Get-ChildItem $dir -Filter *.yar |
  Where-Object {
    $name = $_.Name
    $content = Get-Content $_.FullName -Raw
    $keep = ($name -cnotmatch '^_') -and ($name -cnotmatch $badName) -and (-not ($content -cmatch $badContent))
    if (-not $keep) { Write-Host ("SKIP {0}" -f $name) }
    $keep
  } |
  ForEach-Object { 'include "{0}"' -f $_.Name }

if(-not $includeLines){ throw "No safe .yar files left after filtering." }

$includeLines | Set-Content -Encoding ASCII $master
Write-Host ("WROTE {0} ({1} includes)" -f $master, $includeLines.Count)
