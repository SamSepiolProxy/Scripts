# Define the headers for Microsoft Graph API, requires access token
$headers = @{
    Authorization = "Bearer $token"
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
            $adminUnitId = $adminUnit.id
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
                    $roleId = $role.roleId
                    $roleName = ""
                    $principalId = $role.roleMemberInfo.id
                    $principalName = $role.roleMemberInfo.displayName
                    $principalUPN = $role.roleMemberInfo.userPrincipalName

                    # Resolve Role ID to Role Name
                    try {
                        $roleInfo = Invoke-RestMethod -Uri "$graphUrl/directoryRoles?`$filter=id eq '$roleId'" -Headers $headers -Method Get
                        $roleName = if ($roleInfo.value.Count -gt 0) { $roleInfo.value[0].displayName } else { "Unknown Role" }
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
