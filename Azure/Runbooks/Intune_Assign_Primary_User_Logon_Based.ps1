<#
.SYNOPSIS
Safely updates Intune primary users from recent successful Windows sign-ins.

.DESCRIPTION
Designed for Azure Automation PowerShell 7.4 with a system-assigned managed
identity. Defaults to simulation mode. Validates Graph permissions, direct and
nested group exclusions, device activity, sign-in confidence, and target user
before changing an Intune primary user.

All active Windows devices are considered unless DeviceNameFilter is set.
Excluded devices, disabled/deleted users, disallowed guests, missing sign-ins,
ambiguous candidates and other expected no-action conditions are reported as
Informational, in both WhatIf and live modes. Technical Graph failures are
reported as Failed. A historical UPN change does not prevent assignment if
the immutable Entra user ID still resolves to an eligible user.

Each device result is emitted as compact JSON. The job fails only if a technical
failure occurs. An unreadable exclusion group fails the runbook before changes.

Adapted from the Intune primary-user script by Tbone Granheden (@MrTbone_se).
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 90)]
    [int]$SignInLookbackDays = 30,

    [ValidateRange(1, 90)]
    [int]$DeviceActivityLookbackDays = 30,

    [ValidateRange(1, 100)]
    [int]$MinimumSignInCount = 1,

    [ValidateRange(1, 100)]
    [int]$MinimumSignInLead = 1,

    [ValidatePattern('^$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ExcludedEntraGroupId1 = '',

    [ValidatePattern('^$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ExcludedEntraGroupId2 = '',

    [ValidatePattern('^$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ExcludedEntraGroupId3 = '',

    [ValidatePattern('^$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ExcludedEntraGroupId4 = '',

    [ValidatePattern('^$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ExcludedEntraGroupId5 = '',

    [string[]]$EnrollmentAccountUpns = @(),

    [bool]$AllowGuestUsers = $false,

    [bool]$WhatIf = $true,

    # Optional exact device-name filter for a controlled test.
    [string]$DeviceNameFilter = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$GraphBaseUri = 'https://graph.microsoft.com'
$script:GraphToken = $null
$script:GraphTokenRefreshAt = [datetime]::MinValue

function Get-ManagedIdentityGraphToken {
    if ([string]::IsNullOrWhiteSpace($env:IDENTITY_ENDPOINT) -or
        [string]::IsNullOrWhiteSpace($env:IDENTITY_HEADER)) {
        throw 'Azure Automation managed identity endpoint variables are unavailable. Enable the Automation account system-assigned identity.'
    }

    $tokenUri = '{0}?resource={1}&api-version=2019-08-01' -f
        $env:IDENTITY_ENDPOINT,
        [uri]::EscapeDataString("$GraphBaseUri/")

    $response = Invoke-RestMethod -Method GET -Uri $tokenUri -Headers @{
        'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER
        Metadata            = 'True'
    } -ErrorAction Stop

    if ([string]::IsNullOrWhiteSpace($response.access_token)) {
        throw 'Azure Automation managed identity returned an empty Microsoft Graph access token.'
    }

    return $response.access_token
}

function Get-JwtPayload {
    param(
        [Parameter(Mandatory)]
        [string]$Token
    )

    $parts = $Token.Split('.')
    if ($parts.Count -lt 2) {
        throw 'The managed identity access token is not a valid JWT.'
    }

    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
        1 { throw 'The managed identity JWT payload has invalid Base64URL encoding.' }
    }

    $json = [Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String($payload)
    )
    return $json | ConvertFrom-Json
}

function Assert-GraphPermissions {
    param(
        [Parameter(Mandatory)]
        [string]$Token,

        [Parameter(Mandatory)]
        [string[]]$RequiredRoles
    )

    $coveringRoles = @{
        'User.Read.All' = @(
            'User.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All'
        )
        'GroupMember.Read.All' = @(
            'Group.Read.All', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All',
            'Directory.Read.All', 'Directory.ReadWrite.All'
        )
        'Device.Read.All' = @(
            'Device.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All'
        )
    }

    $payload = Get-JwtPayload -Token $Token
    $assignedRoles = if ($payload.PSObject.Properties.Name -contains 'roles') {
        @($payload.roles)
    }
    else {
        @()
    }

    $missingRoles = [Collections.Generic.List[string]]::new()
    foreach ($requiredRole in $RequiredRoles) {
        $alternatives = @(
            $coveringRoles[$requiredRole] | Where-Object { $_ }
        )
        $acceptedRoles = @($requiredRole) + $alternatives
        $grantedRole = $acceptedRoles |
            Where-Object { $_ -in $assignedRoles } |
            Select-Object -First 1

        if ($grantedRole) {
            Write-Verbose "Required permission '$requiredRole' is satisfied by '$grantedRole'."
        }
        else {
            $missingRoles.Add($requiredRole)
        }
    }

    if ($missingRoles.Count -gt 0) {
        throw "The Automation managed identity is missing Microsoft Graph application permissions: $($missingRoles -join ', ')."
    }
}

function Invoke-GraphRequest {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [object]$Body,

        [ValidateRange(0, 10)]
        [int]$MaximumRetries = 5
    )

    for ($attempt = 0; $attempt -le $MaximumRetries; $attempt++) {
        try {
            if ((Get-Date).ToUniversalTime() -ge $script:GraphTokenRefreshAt) {
                $script:GraphToken = Get-ManagedIdentityGraphToken
                $script:GraphTokenRefreshAt = (Get-Date).ToUniversalTime().AddMinutes(45)
            }

            $parameters = @{
                Method      = $Method
                Uri         = $Uri
                Headers     = @{
                    Authorization = "Bearer $script:GraphToken"
                    Accept        = 'application/json'
                }
                ErrorAction = 'Stop'
            }

            if ($PSBoundParameters.ContainsKey('Body')) {
                $parameters.ContentType = 'application/json'
                $parameters.Body = ConvertTo-Json -InputObject $Body -Depth 10 -Compress
            }

            return Invoke-RestMethod @parameters
        }
        catch {
            $statusCode = $null
            $retryAfter = $null
            $response = $_.Exception.Response

            if ($null -ne $response) {
                $statusCode = [int]$response.StatusCode
                if ($null -ne $response.Headers -and
                    $response.Headers.Contains('Retry-After')) {
                    $retryAfterText = $response.Headers.GetValues('Retry-After') |
                        Select-Object -First 1
                    $parsedSeconds = 0
                    if ([int]::TryParse([string]$retryAfterText, [ref]$parsedSeconds)) {
                        $retryAfter = $parsedSeconds
                    }
                }
            }

            $retryable = $statusCode -eq 429 -or
                ($null -ne $statusCode -and $statusCode -ge 500)

            if (-not $retryable -or $attempt -eq $MaximumRetries) {
                $detail = if (-not [string]::IsNullOrWhiteSpace($_.ErrorDetails.Message)) {
                    $_.ErrorDetails.Message
                }
                else {
                    $_.Exception.Message
                }

                $errorMessage = "Graph $Method $Uri failed. HTTP=$statusCode; Response=$detail"
                $failure = [System.Exception]::new($errorMessage, $_.Exception)
                if ($null -ne $statusCode) {
                    $failure.Data['HttpStatus'] = $statusCode
                }
                throw $failure
            }

            $delaySeconds = if ($null -ne $retryAfter) {
                $retryAfter
            }
            else {
                [int][math]::Min([math]::Pow(2, $attempt + 1), 60)
            }

            Write-Warning "Microsoft Graph returned HTTP $statusCode for $Method $Uri. Retrying in $delaySeconds second(s)."
            Start-Sleep -Seconds $delaySeconds
        }
    }
}

function Get-AllGraphResults {
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $results = [Collections.Generic.List[object]]::new()
    $nextLink = $Uri

    while (-not [string]::IsNullOrWhiteSpace($nextLink)) {
        $response = Invoke-GraphRequest -Method GET -Uri $nextLink
        if ($null -ne $response -and
            $response.PSObject.Properties.Name -contains 'value') {
            foreach ($item in @($response.value)) {
                if ($null -ne $item) {
                    $results.Add($item)
                }
            }
        }

        $nextLink = if ($null -ne $response -and
            $response.PSObject.Properties.Name -contains '@odata.nextLink') {
            $response.'@odata.nextLink'
        }
        else {
            $null
        }
    }

    return $results.ToArray()
}

function Get-GroupDeviceIds {
    param(
        [string[]]$GroupIds,

        [Parameter(Mandatory)]
        [string]$ParameterName
    )

    # Key: Entra deviceId. Value: groups responsible for the exclusion.
    $excludedDevices = @{}

    foreach ($groupId in @($GroupIds | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    } | Select-Object -Unique)) {
        if ($groupId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
            throw "$ParameterName contains an invalid group ID: '$groupId'."
        }

        $encodedGroupId = [uri]::EscapeDataString($groupId)
        $groupUri = "$GraphBaseUri/v1.0/groups/${encodedGroupId}?`$select=id,displayName"
        $group = Invoke-GraphRequest -Method GET -Uri $groupUri

        $membersUri = "$GraphBaseUri/v1.0/groups/$encodedGroupId/transitiveMembers/microsoft.graph.device?`$select=id,deviceId&`$top=999"
        $members = @(Get-AllGraphResults -Uri $membersUri)

        foreach ($member in $members) {
            if ([string]::IsNullOrWhiteSpace($member.deviceId)) {
                throw "Group $groupId ($ParameterName) returned a device without deviceId. Check the Automation identity's Device.Read.All permission."
            }

            $deviceId = [string]$member.deviceId
            if (-not $excludedDevices.ContainsKey($deviceId)) {
                $excludedDevices[$deviceId] = [Collections.Generic.List[string]]::new()
            }
            $excludedDevices[$deviceId].Add("$($group.displayName) ($groupId)")
        }

        Write-Verbose "Group '$($group.displayName)' ($groupId) from $ParameterName contributed $($members.Count) device object(s)."
    }

    return ,$excludedDevices
}

function Get-ValidatedTargetUser {
    param(
        [Parameter(Mandatory)]
        [string]$UserId,

        [Parameter(Mandatory)]
        [string]$ExpectedUserPrincipalName
    )

    $encodedUserId = [uri]::EscapeDataString($UserId)
    $userUri = "$GraphBaseUri/v1.0/users/${encodedUserId}?`$select=id,userPrincipalName,accountEnabled,userType"

    try {
        $user = Invoke-GraphRequest -Method GET -Uri $userUri
    }
    catch {
        $status = $_.Exception.Data['HttpStatus']
        if ($status -eq 404) {
            return [pscustomobject]@{
                IsValid   = $false
                IsError   = $false
                User      = $null
                Note      = $null
                Reason    = "Historical sign-in user '$ExpectedUserPrincipalName' (userId '$UserId') no longer exists or cannot be found in Entra ID. No assignment attempted. Graph response: $($_.Exception.Message)"
            }
        }
        return [pscustomobject]@{
            IsValid = $false
            IsError = $true
            User    = $null
            Note    = $null
            Reason  = "Target user '$ExpectedUserPrincipalName' (userId '$UserId') could not be read due to a technical Graph failure: $($_.Exception.Message)"
        }
    }

    if ([string]::IsNullOrWhiteSpace($user.id) -or $user.id -ine $UserId) {
        return [pscustomobject]@{
            IsValid = $false
            IsError = $true
            User    = $null
            Note    = $null
            Reason  = "Graph returned user ID '$($user.id)' but sign-in userId was '$UserId'. No assignment attempted."
        }
    }

    if ($user.accountEnabled -ne $true) {
        return [pscustomobject]@{
            IsValid = $false
            IsError = $false
            User    = $user
            Note    = $null
            Reason  = "Target user '$($user.userPrincipalName)' is disabled in Entra ID. No assignment attempted."
        }
    }

    if (-not $AllowGuestUsers -and $user.userType -ne 'Member') {
        return [pscustomobject]@{
            IsValid = $false
            IsError = $false
            User    = $user
            Note    = $null
            Reason  = "Target user '$($user.userPrincipalName)' has userType '$($user.userType)'; AllowGuestUsers is false. No assignment attempted."
        }
    }

    $note = $null
    if ($user.userPrincipalName -ine $ExpectedUserPrincipalName) {
        $note = "Historical sign-in UPN '$ExpectedUserPrincipalName' differs from current Entra UPN '$($user.userPrincipalName)'. Identity was validated by immutable userId '$UserId'."
    }

    return [pscustomobject]@{
        IsValid = $true
        IsError = $false
        User    = $user
        Note    = $note
        Reason  = $null
    }
}

function Get-CurrentPrimaryUser {
    param(
        [Parameter(Mandatory)]
        [string]$ManagedDeviceId
    )

    $encodedManagedDeviceId = [uri]::EscapeDataString($ManagedDeviceId)
    $uri = "$GraphBaseUri/beta/deviceManagement/managedDevices/$encodedManagedDeviceId/users?`$select=id,userPrincipalName"
    $users = @(Get-AllGraphResults -Uri $uri)

    if ($users.Count -gt 1) {
        throw "Managed device '$ManagedDeviceId' returned multiple primary users; no assignment attempted."
    }
    if ($users.Count -eq 0) {
        return $null
    }
    return $users[0]
}

function Set-PrimaryUser {
    param(
        [Parameter(Mandatory)]
        [string]$ManagedDeviceId,

        [Parameter(Mandatory)]
        [string]$UserId
    )

    # Preflight the exact Intune managed-device and Entra user references.
    # A successful GET does not guarantee the relationship POST will succeed,
    # but it distinguishes a missing reference from a relationship failure.
    $encodedManagedDeviceId = [uri]::EscapeDataString($ManagedDeviceId)
    $encodedUserId = [uri]::EscapeDataString($UserId)
    $deviceUri = "$GraphBaseUri/beta/deviceManagement/managedDevices/$encodedManagedDeviceId`?`$select=id,deviceName,azureADDeviceId"
    $userUri = "$GraphBaseUri/v1.0/users/$encodedUserId`?`$select=id,userPrincipalName"

    try {
        $deviceReference = Invoke-GraphRequest -Method GET -Uri $deviceUri
        if ($null -eq $deviceReference -or $deviceReference.id -ine $ManagedDeviceId) {
            throw "Graph returned an unexpected managed-device ID '$($deviceReference.id)' for '$ManagedDeviceId'."
        }
    }
    catch {
        throw "Preflight managed-device GET failed for '$ManagedDeviceId': $($_.Exception.Message)"
    }

    try {
        $userReference = Invoke-GraphRequest -Method GET -Uri $userUri
        if ($null -eq $userReference -or $userReference.id -ine $UserId) {
            throw "Graph returned an unexpected user ID '$($userReference.id)' for '$UserId'."
        }
    }
    catch {
        throw "Preflight target-user GET failed for '$UserId': $($_.Exception.Message)"
    }

    # Diagnostic change: test the beta relationship endpoint for the POST.
    # Escape $ref so PowerShell sends the literal Graph path segment.
    $uri = "$GraphBaseUri/beta/deviceManagement/managedDevices('$ManagedDeviceId')/users/`$ref"
    $body = @{
        '@odata.id' = "$GraphBaseUri/v1.0/users/$encodedUserId"
    }

    Write-Verbose "Primary-user POST: ManagedDeviceId='$ManagedDeviceId'; UserId='$UserId'; URI='$uri'."
    $null = Invoke-GraphRequest -Method POST -Uri $uri -Body $body
}

$requiredRoles = @(
    'AuditLog.Read.All'
    'DeviceManagementManagedDevices.ReadWrite.All'
    'User.Read.All'
)

$excludedGroupIds = @(
    @(
        $ExcludedEntraGroupId1
        $ExcludedEntraGroupId2
        $ExcludedEntraGroupId3
        $ExcludedEntraGroupId4
        $ExcludedEntraGroupId5
    ) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique
)

$script:GraphToken = Get-ManagedIdentityGraphToken
$script:GraphTokenRefreshAt = (Get-Date).ToUniversalTime().AddMinutes(45)
if ($excludedGroupIds.Count -gt 0) {
    $requiredRoles += @('GroupMember.Read.All', 'Device.Read.All')
}
Assert-GraphPermissions -Token $script:GraphToken -RequiredRoles $requiredRoles

# An unreadable exclusion group stops the runbook before any assignment.
$excludedDeviceGroups = Get-GroupDeviceIds -GroupIds $excludedGroupIds -ParameterName 'ExcludedEntraGroupId1-5'
if ($excludedDeviceGroups.Count -gt 0) {
    Write-Output "Excluding $($excludedDeviceGroups.Count) device(s) that are members of excluded Entra group(s)."
}

$excludedUpns = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase
)
foreach ($upn in @($EnrollmentAccountUpns | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_)
})) {
    [void]$excludedUpns.Add($upn.Trim())
}

$deviceCutoff = (Get-Date).ToUniversalTime().AddDays(-$DeviceActivityLookbackDays)
$deviceFilter = "operatingSystem eq 'Windows' and lastSyncDateTime ge $($deviceCutoff.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
$devicesUri = "$GraphBaseUri/v1.0/deviceManagement/managedDevices?" +
    "`$filter=$([uri]::EscapeDataString($deviceFilter))&" +
    '$select=id,deviceName,azureADDeviceId,operatingSystem,lastSyncDateTime&$top=999'
$devices = @(Get-AllGraphResults -Uri $devicesUri)

if (-not [string]::IsNullOrWhiteSpace($DeviceNameFilter)) {
    $devices = @($devices | Where-Object { $_.deviceName -ieq $DeviceNameFilter })
}
if ($devices.Count -eq 0) {
    Write-Output "Informational: No active Windows Intune devices matched the activity/device-name filters. No changes required."
    return
}

$signInCutoff = (Get-Date).ToUniversalTime().AddDays(-$SignInLookbackDays)
$signInFilter = "createdDateTime ge $($signInCutoff.ToString('yyyy-MM-ddTHH:mm:ssZ')) and appDisplayName eq 'Windows Sign In' and status/errorCode eq 0 and isInteractive eq true"
$signInsUri = "$GraphBaseUri/v1.0/auditLogs/signIns?" +
    "`$filter=$([uri]::EscapeDataString($signInFilter))&" +
    '$select=createdDateTime,userId,userPrincipalName,deviceDetail&$top=1000'
$signIns = @(Get-AllGraphResults -Uri $signInsUri)

$signInsByDevice = @{}
$excludedSignInsByDevice = @{}
$unusableSignInsByDevice = @{}
foreach ($signIn in $signIns) {
    $deviceId = [string]$signIn.deviceDetail.deviceId
    if ([string]::IsNullOrWhiteSpace($deviceId)) {
        continue
    }

    if (-not [string]::IsNullOrWhiteSpace($signIn.userPrincipalName) -and
        $excludedUpns.Contains($signIn.userPrincipalName)) {
        if (-not $excludedSignInsByDevice.ContainsKey($deviceId)) {
            $excludedSignInsByDevice[$deviceId] = 0
        }
        $excludedSignInsByDevice[$deviceId]++
        continue
    }

    if ([string]::IsNullOrWhiteSpace($signIn.userId) -or
        $signIn.userId -eq '00000000-0000-0000-0000-000000000000' -or
        [string]::IsNullOrWhiteSpace($signIn.userPrincipalName)) {
        if (-not $unusableSignInsByDevice.ContainsKey($deviceId)) {
            $unusableSignInsByDevice[$deviceId] = 0
        }
        $unusableSignInsByDevice[$deviceId]++
        continue
    }

    if (-not $signInsByDevice.ContainsKey($deviceId)) {
        $signInsByDevice[$deviceId] = [Collections.Generic.List[object]]::new()
    }
    $signInsByDevice[$deviceId].Add($signIn)
}

$report = [Collections.Generic.List[object]]::new()
foreach ($device in $devices) {
    $result = [ordered]@{
        DeviceName          = $device.deviceName
        ManagedDeviceId     = $device.id
        EntraDeviceId       = $device.azureADDeviceId
        CurrentPrimaryUser  = $null
        ProposedPrimaryUser = $null
        QualifyingSignIns   = 0
        Action              = 'Informational'
        Reason              = $null
        Note                = $null
    }

    $entraDeviceId = [string]$device.azureADDeviceId
    if ([string]::IsNullOrWhiteSpace($entraDeviceId)) {
        $result.Reason = 'Intune device has no Entra device ID, so its sign-ins cannot be correlated. No assignment attempted.'
        $report.Add([pscustomobject]$result)
        continue
    }

    if ($excludedDeviceGroups.ContainsKey($entraDeviceId)) {
        $groupNames = $excludedDeviceGroups[$entraDeviceId] -join '; '
        $result.Reason = "Device is a direct or nested member of excluded Entra group(s): $groupNames. No assignment attempted."
        $report.Add([pscustomobject]$result)
        continue
    }

    try {
        $currentPrimaryUser = Get-CurrentPrimaryUser -ManagedDeviceId $device.id
        if ($null -ne $currentPrimaryUser) {
            $result.CurrentPrimaryUser = $currentPrimaryUser.userPrincipalName
        }
    }
    catch {
        $result.Action = 'Failed'
        $result.Reason = "Current primary-user lookup failed: $($_.Exception.Message)"
        $report.Add([pscustomobject]$result)
        continue
    }

    if (-not $signInsByDevice.ContainsKey($entraDeviceId)) {
        $excludedCount = if ($excludedSignInsByDevice.ContainsKey($entraDeviceId)) {
            $excludedSignInsByDevice[$entraDeviceId]
        }
        else { 0 }
        $unusableCount = if ($unusableSignInsByDevice.ContainsKey($entraDeviceId)) {
            $unusableSignInsByDevice[$entraDeviceId]
        }
        else { 0 }
        $result.Reason = "No qualifying successful interactive Windows sign-ins with a matching Entra device ID in the last $SignInLookbackDays day(s). Excluded enrollment-account sign-ins: $excludedCount; sign-ins missing usable user ID/UPN: $unusableCount. No assignment attempted."
        $report.Add([pscustomobject]$result)
        continue
    }

    $rankedUsers = @(
        $signInsByDevice[$entraDeviceId] |
            Group-Object userId |
            ForEach-Object {
                $latestSignIn = $_.Group |
                    Sort-Object createdDateTime -Descending |
                    Select-Object -First 1
                [pscustomobject]@{
                    UserId            = $_.Name
                    UserPrincipalName = $latestSignIn.userPrincipalName
                    Count             = $_.Count
                }
            } |
            Sort-Object -Property @(
                @{ Expression = 'Count'; Descending = $true },
                @{ Expression = 'UserPrincipalName'; Descending = $false }
            )
    )

    $candidate = $rankedUsers | Select-Object -First 1
    $runnerUp = $rankedUsers | Select-Object -Skip 1 -First 1
    $result.ProposedPrimaryUser = $candidate.UserPrincipalName
    $result.QualifyingSignIns = $candidate.Count

    if ($candidate.Count -lt $MinimumSignInCount) {
        $result.Reason = "Leading user '$($candidate.UserPrincipalName)' has $($candidate.Count) qualifying sign-in(s); minimum is $MinimumSignInCount. No assignment attempted."
        $report.Add([pscustomobject]$result)
        continue
    }

    if ($null -ne $runnerUp -and
        ($candidate.Count - $runnerUp.Count) -lt $MinimumSignInLead) {
        $result.Reason = "Ambiguous sign-ins: leader '$($candidate.UserPrincipalName)' has $($candidate.Count); runner-up '$($runnerUp.UserPrincipalName)' has $($runnerUp.Count); required lead is $MinimumSignInLead. No assignment attempted."
        $report.Add([pscustomobject]$result)
        continue
    }

    $validation = Get-ValidatedTargetUser -UserId $candidate.UserId -ExpectedUserPrincipalName $candidate.UserPrincipalName
    if (-not $validation.IsValid) {
        if ($validation.IsError) {
            $result.Action = 'Failed'
        }
        $result.Reason = $validation.Reason
        $report.Add([pscustomobject]$result)
        continue
    }

    $targetUser = $validation.User
    $result.ProposedPrimaryUser = $targetUser.userPrincipalName
    $result.Note = $validation.Note

    # A renamed enrollment account must remain excluded under its current UPN.
    if ($excludedUpns.Contains($targetUser.userPrincipalName)) {
        $result.Reason = "Target user's current Entra UPN '$($targetUser.userPrincipalName)' is an excluded enrollment account. No assignment attempted."
        $report.Add([pscustomobject]$result)
        continue
    }

    if ($null -ne $currentPrimaryUser -and
        $currentPrimaryUser.id -ieq $targetUser.id) {
        $result.Action = 'Unchanged'
        $result.Reason = "Validated user '$($targetUser.userPrincipalName)' is already primary."
        $report.Add([pscustomobject]$result)
        continue
    }

    if ($WhatIf) {
        $result.Action = 'WhatIf'
        $result.Reason = "Simulation only; would assign '$($targetUser.userPrincipalName)' as primary user."
        $report.Add([pscustomobject]$result)
        continue
    }

    try {
        Set-PrimaryUser -ManagedDeviceId $device.id -UserId $targetUser.id

        $verified = $false
        for ($verificationAttempt = 1; $verificationAttempt -le 3; $verificationAttempt++) {
            Start-Sleep -Seconds 5
            $verifiedPrimaryUser = Get-CurrentPrimaryUser -ManagedDeviceId $device.id
            if ($null -ne $verifiedPrimaryUser -and
                $verifiedPrimaryUser.id -ieq $targetUser.id) {
                $verified = $true
                break
            }
        }

        if (-not $verified) {
            throw 'Microsoft Graph accepted the change, but the primary-user relationship did not confirm the target after three verification attempts.'
        }

        $result.Action = 'Changed'
        $result.Reason = "Primary user changed to '$($targetUser.userPrincipalName)' and verified."
    }
    catch {
        $result.Action = 'Failed'
        $result.Reason = $_.Exception.Message
    }

    $report.Add([pscustomobject]$result)
}

$report | Sort-Object DeviceName | ForEach-Object {
    Write-Output ($_ | ConvertTo-Json -Depth 5 -Compress)
}
$report | Group-Object Action | Sort-Object Name | ForEach-Object {
    Write-Output ('Summary: {0} = {1}' -f $_.Name, $_.Count)
}

$failedCount = @($report | Where-Object { $_.Action -eq 'Failed' }).Count
if ($failedCount -gt 0) {
    Write-Output "$failedCount device(s) encountered technical failures. Review the per-device JSON Reason values in the job output. The runbook will continue and the Azure Automation job will complete successfully."
}

Write-Output ("Run completed. Processed devices: {0}; Device failures: {1}; JobStatus=Completed." -f $report.Count, $failedCount) 