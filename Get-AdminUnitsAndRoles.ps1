<#
.SYNOPSIS
    Retrieves all Azure AD administrative units and their members or scoped roles, then exports the results to a CSV file.

.DESCRIPTION
    This script uses the Microsoft Graph API to:
      1. Retrieve all administrative units in Azure AD.
      2. For each administrative unit:
         - Fetch all member users.
         - Fetch any scoped role assignments and resolve each role's display name.
      3. Collect the data and export it to a CSV file (AdminUnitsDetailsWithRolesAndTypes.csv).

.PARAMETER Token
    The OAuth 2.0 access token (Bearer token) used to authenticate to Microsoft Graph.

.EXAMPLE
    # Example usage:
    $Token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUz..."  # Replace with your actual access token
    .\Get-AdminUnitsAndRoles.ps1 -Token $Token

    Description:
    1. Sets the $Token variable to an existing access token string.
    2. Calls the script with the -Token parameter.
    3. The script will create AdminUnitsDetailsWithRolesAndTypes.csv containing the administrative units, user members, and scoped role assignments.
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$Token
)

# Define the headers for Microsoft Graph API, requires access token
$headers = @{
    Authorization = "Bearer $Token"
    "Content-Type" = "application/json"
}

# Base URL for Graph API
$graphUrl = "https://graph.microsoft.com/v1.0"

# Initialize an array to store results
$results = @()

# Get all administrative units
try {
    $adminUnits = Invoke-RestMethod -Uri "$graphUrl/directory/administrativeUnits" -Headers $headers -Method Get
    
    if ($adminUnits.value.Count -gt 0) {
        foreach ($adminUnit in $adminUnits.value) {
            $adminUnitId   = $adminUnit.id
            $adminUnitName = $adminUnit.displayName

            # Get members of the administrative unit
            $membersUrl = "$graphUrl/directory/administrativeUnits/$adminUnitId/members/microsoft.graph.user"
            try {
                $members = Invoke-RestMethod -Uri $membersUrl -Headers $headers -Method Get
                foreach ($member in $members.value) {
                    $results += [PSCustomObject]@{
                        AdminUnitId       = $adminUnitId
                        AdminUnitName     = $adminUnitName
                        MemberId          = $member.id
                        MemberDisplayName = $member.displayName
                        RoleId            = ""
                        RoleName          = ""
                        MemberUPN         = $member.userPrincipalName
                        Type              = "Member"
                    }
                }
            } catch {
                Write-Error ("Error fetching members for Admin Unit ID " + $adminUnitId + ": " + $_)
            }

            # Get scoped roles for the administrative unit
            $rolesUrl = "$graphUrl/directory/administrativeUnits/$adminUnitId/scopedRoleMembers"
            try {
                $roles = Invoke-RestMethod -Uri $rolesUrl -Headers $headers -Method Get
                foreach ($role in $roles.value) {
                    $roleId        = $role.roleId
                    $roleName      = ""
                    $principalId   = $role.roleMemberInfo.id
                    $principalName = $role.roleMemberInfo.displayName
                    $principalUPN  = $role.roleMemberInfo.userPrincipalName

                    # Resolve Role ID to Role Name
                    try {
                        $roleInfo = Invoke-RestMethod -Uri "$graphUrl/directoryRoles?`$filter=id eq '$roleId'" -Headers $headers -Method Get
                        $roleName = if ($roleInfo.value.Count -gt 0) {
                            $roleInfo.value[0].displayName
                        } else {
                            "Unknown Role"
                        }
                    } catch {
                        Write-Error ("Error resolving role ID " + $roleId + ": " + $_)
                        $roleName = "Error Resolving Role"
                    }

                    $results += [PSCustomObject]@{
                        AdminUnitId       = $adminUnitId
                        AdminUnitName     = $adminUnitName
                        MemberId          = $principalId
                        MemberDisplayName = $principalName
                        RoleId            = $roleId
                        RoleName          = $roleName
                        MemberUPN         = $principalUPN
                        Type              = "Role"
                    }
                }
            } catch {
                Write-Error ("Error fetching roles for Admin Unit ID " + $adminUnitId + ": " + $_)
            }
        }
    } else {
        Write-Host "No administrative units found."
    }
} catch {
    Write-Error ("Error accessing administrative units: " + $_)
}

# Export results to CSV
$outputFile = "AdminUnitsDetailsWithRolesAndTypes.csv"
try {
    $results | Export-Csv -Path $outputFile -NoTypeInformation -Force
    Write-Host "Results exported to $outputFile"
} catch {
    Write-Error ("Error exporting results to CSV: " + $_)
}
