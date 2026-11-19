param(
    [string]$GroupId = '0f5b6ef5-8017-47a9-ae11-fd7418ea1d8d'   # Object ID
)
$DeviceIdList = @'
"id1"
"id2"
"id3"
'@

Import-Module Microsoft.Graph.Authentication, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.DeviceManagement -ErrorAction Stop
Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop     # user-assigned MI: add -ClientId '<client-id>'

if ($GroupId -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' -or $GroupId -eq '00000000-0000-0000-0000-000000000000') {
    throw "GroupId '$GroupId' is not a valid group Object ID."
}
try   { $group = Get-MgGroup -GroupId $GroupId -Property Id, DisplayName, GroupTypes, SecurityEnabled -ErrorAction Stop }
catch { throw "Group $GroupId not found or not readable: $($_.Exception.Message)" }

if ($group.GroupTypes -contains 'DynamicMembership') { throw "Group '$($group.DisplayName)' is dynamic - members can't be added." }
if (-not $group.SecurityEnabled)                     { throw "Group '$($group.DisplayName)' is not a security group." }
"Target group: $($group.DisplayName) ($($group.Id))"

function Get-EntraObjectId([string]$Id) {
    # 1. Intune device ID -> its Entra device ID
    $md = Get-MgDeviceManagementManagedDevice -ManagedDeviceId $Id -Property AzureADDeviceId -ErrorAction SilentlyContinue
    if ($md.AzureADDeviceId) {
        return (Get-MgDevice -Filter "deviceId eq '$($md.AzureADDeviceId)'" -Property Id | Select-Object -First 1).Id
    }

    # 2. Fallback: Entra device ID
    (Get-MgDevice -Filter "deviceId eq '$Id'" -Property Id | Select-Object -First 1).Id
}

$ids = $DeviceIdList -split "`r?`n" | ForEach-Object { $_ -replace '[\s"'',{}]', '' } | Where-Object { $_ } | Sort-Object -Unique
"IDs parsed: $($ids.Count)"

$added = 0
foreach ($id in $ids) {
    $objId = Get-EntraObjectId $id
    if (-not $objId) { Write-Warning "Not found: $id"; continue }

    try {
        New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $objId -ErrorAction Stop
        $added++
    }
    catch { Write-Warning "Skipped $id : $($_.Exception.Message)" }
}

"Done: $added / $($ids.Count) added to $($group.DisplayName) ($($group.Id))"