param(
    [string[]]$TargetIds = @(),         # List of UserPrincipalNames or ObjectIds. Leave empty for all users.
    [int]$BlockAfterDays = 90,          # Days of inactivity threshold.
    [ValidateSet("Enforce", "Notify")]
    [string]$ComplianceAction = "Notify",
    [switch]$SkipGlobalAdmins,          # Skip blocking or reporting on Global Admins.
    [string]$ExportPath = "C:\Temp\InactiveUsersReport.csv"
)

function Get-UserLastSignIn {
    param ($UserId)
    try {
        $user = Get-MgUser -UserId $UserId -Property Id, DisplayName, UserPrincipalName, AccountEnabled, OnPremisesSyncEnabled, SignInActivity -ErrorAction Stop
        return $user
    } catch {
        Write-Warning ("Failed to get user info for $UserId: " + $_)
        return $null
    }
    }
    }

function Is-GlobalAdmin {
    param ($UserId)
    try {
        $roles = Get-MgUserMemberOf -UserId $UserId -All | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' }
        foreach ($role in $roles) {
            $roleName = (Get-MgDirectoryRole -DirectoryRoleId $role.Id).DisplayName
            if ($roleName -eq "Global Administrator") {
                return $true
            }
        }
        return $false
    } catch {
        Write-Warning ("Failed to get role info for $UserId: " + $_)
        return $false
    }
}

# Connect to Microsoft Graph (ensure you have necessary permissions!)
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "Directory.AccessAsUser.All"

if ($TargetIds.Count -eq 0) {
    Write-Output "No specific TargetIds provided. Retrieving all users..."
    $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled, OnPremisesSyncEnabled, SignInActivity
} else {
    $users = foreach ($uid in $TargetIds) {
        Get-UserLastSignIn -UserId $uid
    }
}

$results = @()
$now = Get-Date

foreach ($user in $users) {
    if (-not $user) { continue } # Skip nulls

    # Build as PSCustomObject
    $result = [PSCustomObject]@{
        UserPrincipalName   = $user.UserPrincipalName
        DisplayName         = $user.DisplayName
        Id                  = $user.Id
        IsOnPremSynced      = $user.OnPremisesSyncEnabled
        IsGlobalAdmin       = $false
        LastSignInDate      = $null
        Status              = "Unknown"
        Notes               = ""
    }

    # Skip on-premises synced users for enforcement
    if ($user.OnPremisesSyncEnabled) {
        $result.Status = "Skipped"
        $result.Notes = "On-premises synced account. No action taken."
        $results += $result
        continue
    }

    # Check for Global Admin role
    if ($SkipGlobalAdmins) {
        if (Is-GlobalAdmin -UserId $user.Id) {
            $result.Status = "Skipped"
            $result.IsGlobalAdmin = $true
            $result.Notes = "Global Admin. Skipped as per settings."
            $results += $result
            continue
        }
    }

    # Handle missing sign-in data
    $lastSignInRaw = $user.SignInActivity.LastSignInDateTime
    if ([string]::IsNullOrEmpty($lastSignInRaw)) {
        $result.Status = "Non-Compliant"
        $result.Notes = "Never signed in or data missing."
        if ($ComplianceAction -eq "Enforce") {
            try {
                Update-MgUser -UserId $user.Id -AccountEnabled:$false
                $result.Notes += " Account disabled (never signed in)."
                $result.Status = "Enforced - Disabled"
            } catch {
                $result.Notes += " Error disabling account: ${_}"
                $result.Status = "Error"
            }
        }
        $results += $result
        continue
    }

    $lastSignIn = [datetime]$lastSignInRaw
    $result.LastSignInDate = $lastSignIn
    $daysInactive = ($now - $lastSignIn).Days

    if ($daysInactive -ge $BlockAfterDays) {
        $result.Status = "Non-Compliant"
        $result.Notes = "Inactive for $daysInactive days."
        if ($ComplianceAction -eq "Enforce") {
            try {
                Update-MgUser -UserId $user.Id -AccountEnabled:$false
                $result.Notes += " Account disabled."
                $result.Status = "Enforced - Disabled"
            } catch {
                $result.Notes += " Error disabling account: ${_}"
                $result.Status = "Error"
            }
        }
    } else {
        $result.Status = "Compliant"
        $result.Notes = "Active within threshold ($daysInactive days inactive)."
    }
    $results += $result
}

# Export results: Now all entries are PSCustomObject
$results | Where-Object { $_ -ne $null } | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8

Write-Host "`nExported results to $ExportPath"

Disconnect-MgGraph

