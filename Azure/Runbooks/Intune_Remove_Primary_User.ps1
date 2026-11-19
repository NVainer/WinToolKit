param(
    [Parameter(Mandatory = $false)]
    [string]$GroupId = "",

    [Parameter(Mandatory = $false)]
    [int]$LookbackHours = 24
)

$ErrorActionPreference = 'Stop'

Connect-MgGraph -Identity -NoWelcome

try {
    $MemberDeviceIds = New-Object System.Collections.Generic.HashSet[string]
    $Uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/microsoft.graph.device?`$select=deviceId,displayName"
    do {
        $Page = Invoke-MgGraphRequest -Method GET -Uri $Uri
        foreach ($m in $Page.value) { if ($m.deviceId) { [void]$MemberDeviceIds.Add($m.deviceId) } }
        $Uri = $Page.'@odata.nextLink'
    } while ($Uri)
    Write-Output "Group device members: $($MemberDeviceIds.Count)"

    $Since   = (Get-Date).ToUniversalTime().AddHours(-$LookbackHours).ToString("o")
    $Filter  = "operatingSystem eq 'Windows' and enrolledDateTime ge $Since"
    $Uri     = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=$Filter&`$select=id,deviceName,userPrincipalName,azureADDeviceId"
    $Devices = @()
    do {
        $Page    = Invoke-MgGraphRequest -Method GET -Uri $Uri
        $Devices += $Page.value
        $Uri     = $Page.'@odata.nextLink'
    } while ($Uri)

    $Targets = $Devices | Where-Object { $_.userPrincipalName -and $MemberDeviceIds.Contains($_.azureADDeviceId) }
    Write-Output "Devices in scope for primary-user removal: $($Targets.Count)"

    foreach ($d in $Targets) {
        $RemoveUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($d.id)/users/`$ref"
        try {
            Invoke-MgGraphRequest -Uri $RemoveUri -Method DELETE -ErrorAction Stop
            Write-Output "Removed: $($d.deviceName) ($($d.userPrincipalName))"
        } catch {
            Write-Warning "Failed: $($d.deviceName) - $($_.Exception.Message)"
        }
    }
}
finally {
    Disconnect-MgGraph | Out-Null
}
