# Import the Microsoft Graph module
Import-Module Microsoft.Graph

# Connect to Microsoft Graph interactively
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess", "Group.Read.All", "Directory.Read.All"

# --- Variables ---
$groupId = "0da8624c-3c3e-4b05-9d4e-4d26c81bd6a6" # SecurityReviewTeam group ID
$excludedRoleTemplateId = "62e90394-69f5-4237-9190-012177145e10" # Global Administrator role TemplateId
$mkLocationId = "1c971d72-2830-464a-8871-3fa846bad855" # Named Location for MK (Macedonia)

# --- Build the Conditional Access policy object ---
$policy = @{
    displayName = "Require Compliant Device and MK Location for SecurityReviewTeam (Test - No Apps)"
    state       = "enabled"
    conditions  = @{
        users = @{
            includeGroups = @($groupId)
            excludeRoles  = @($excludedRoleTemplateId)
        }
        applications = @{
            includeApplications = @("none")    # No apps targeted for testing
            excludeApplications = @()
        }
        platforms = @{
            includePlatforms = @("all")
        }
        locations = @{
            includeLocations = @($mkLocationId)
            excludeLocations = @()
        }
        clientAppTypes = @("all")
    }
    grantControls = @{
        operator = "AND"
        builtInControls = @("compliantDevice")
    }
    sessionControls = @{}
}

# --- Output the policy JSON for review (console and file) ---
$policyJson = $policy | ConvertTo-Json -Depth 8

Write-Host "`nGenerated Conditional Access Policy JSON:`n"
Write-Host $policyJson

# Save to file
$policyJson | Out-File -FilePath "C:\Temp\ConditionalAccessPolicy.json" -Encoding utf8
Write-Host "`nPolicy JSON has been saved to C:\Temp\ConditionalAccessPolicy.json."

# --- Create the policy
$createdPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
Write-Host "`nPolicy created with ID: $($createdPolicy.Id)"

Disconnect-MgGraph

