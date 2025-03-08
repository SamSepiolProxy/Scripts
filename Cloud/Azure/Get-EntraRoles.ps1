<#
.SYNOPSIS
    Retrieves all role assignment schedules from Microsoft Graph and resolves IDs to display names.
.DESCRIPTION
    This script uses a provided access token to call the Microsoft Graph v1.0 endpoint for
    role management role assignment schedules. For each schedule, it retrieves:
      - The Principal's display name via the directoryObjects endpoint.
      - The Role Definition's display name via the roleDefinitions endpoint.
.PARAMETER AccessToken
    A valid Bearer token with permissions such as RoleManagement.Read.Directory and Directory.Read.All.
.EXAMPLE
    .\Get-RoleAssignmentSchedulesResolved.ps1 -AccessToken "eyJ0eXAiOiJKV1QiLCJ..." 
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$AccessToken
)

# Base endpoint for role assignment schedules
$uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules"

# Common headers for API calls
$headers = @{
    "Authorization" = "Bearer $AccessToken"
    "Content-Type"  = "application/json"
}

# Function to resolve a principal ID into a display name
function Get-PrincipalDisplayName {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PrincipalId,
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    # Use directoryObjects to retrieve minimal information (selecting common display properties)
    $principalUri = "https://graph.microsoft.com/v1.0/directoryObjects/$PrincipalId`?`$select=displayName,userPrincipalName,mail"
    try {
        $principal = Invoke-RestMethod -Method Get -Uri $principalUri -Headers @{ "Authorization" = "Bearer $AccessToken" }
        if ($principal.displayName) {
            return $principal.displayName
        }
        elseif ($principal.userPrincipalName) {
            return $principal.userPrincipalName
        }
        elseif ($principal.mail) {
            return $principal.mail
        }
        else {
            return "Unknown Principal Name"
        }
    }
    catch {
        return "Error retrieving principal ($PrincipalId)"
    }
}

# Function to resolve a role definition ID into a display name
function Get-RoleDefinitionDisplayName {
    param(
        [Parameter(Mandatory=$true)]
        [string]$RoleDefinitionId,
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    $roleUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$RoleDefinitionId`?`$select=displayName"
    try {
        $roleDefinition = Invoke-RestMethod -Method Get -Uri $roleUri -Headers @{ "Authorization" = "Bearer $AccessToken" }
        if ($roleDefinition.displayName) {
            return $roleDefinition.displayName
        }
        else {
            return "Unknown Role Name"
        }
    }
    catch {
        return "Error retrieving role ($RoleDefinitionId)"
    }
}

$schedules = @()

Write-Output "Retrieving role assignment schedules from Microsoft Graph..."
# Loop through paginated results if necessary
do {
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    if ($response.value) {
        $schedules += $response.value
    }
    $uri = $response.'@odata.nextLink'
} while ($uri)

if ($schedules.Count -gt 0) {
    Write-Output "Total role assignment schedules retrieved: $($schedules.Count)`n"
    foreach ($schedule in $schedules) {
        Write-Output "Schedule ID       : $($schedule.id)"
        Write-Output "Principal ID      : $($schedule.principalId)"
        $principalName = Get-PrincipalDisplayName -PrincipalId $schedule.principalId -AccessToken $AccessToken
        Write-Output "Principal Name    : $principalName"
        Write-Output "Role Definition ID: $($schedule.roleDefinitionId)"
        $roleName = Get-RoleDefinitionDisplayName -RoleDefinitionId $schedule.roleDefinitionId -AccessToken $AccessToken
        Write-Output "Role Name         : $roleName"
        Write-Output "Schedule Type     : $($schedule.scheduleType)"
        Write-Output "-------------------------------------------"
    }
}
else {
    Write-Output "No role assignment schedules found."
}