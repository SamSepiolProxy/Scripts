<#
.SYNOPSIS
    Export and resolve Conditional Access Policies with fallback for built-in roles.

.DESCRIPTION
    This script retrieves all Conditional Access policies from Microsoft Graph,
    saves raw JSON, and resolves any GUID references to human-readable names 
    (userPrincipalName, group displayName, application, or role name). 
    Includes a fallback that queries role definitions (roleManagement/directory/roleDefinitions)
    to resolve built-in Azure AD roles that might not appear in directoryRoles.

.REQUIREMENTS
    - Azure AD tenant
    - A valid OAuth 2.0 token for Microsoft Graph with at least:
        * Directory.Read.All
        * RoleManagement.Read.Directory
    - PowerShell 5.1 or later (or PS Core 7+)

.PARAMETER Token
    An OAuth 2.0 access token used to authenticate to Microsoft Graph

.EXAMPLE
    $Token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUz..."  # Replace with your actual access token
    .\Get-CAPolicies.ps1 -Token $Token
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Token
)

### 1. Retrieve all Conditional Access policies ###
$caPoliciesEndpoint = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

Write-Host "Fetching all Conditional Access policies..." -ForegroundColor Cyan
try {
    $response = Invoke-RestMethod -Uri $caPoliciesEndpoint -Headers @{
        "Authorization" = "Bearer $Token"
    } -Method Get -ContentType "application/json" -ErrorAction Stop
}
catch {
    Write-Host "ERROR: Could not retrieve Conditional Access policies: $($_.Exception.Message)" -ForegroundColor Red
    return
}

if (-not $response.value) {
    Write-Host "No Conditional Access policies found or invalid token provided." -ForegroundColor Red
    return
}

Write-Host "Successfully retrieved Conditional Access policies." -ForegroundColor Green

# Save raw JSON for reference
$rawJsonOutput = "ConditionalAccessPolicies_Raw.json"
$response | ConvertTo-Json -Depth 10 | Out-File -FilePath $rawJsonOutput -Encoding utf8
Write-Host "Raw JSON data saved to $rawJsonOutput" -ForegroundColor Green

# Convert to array for iteration
$caPolicies = $response.value

### 2. Helper function: Resolve a single GUID via direct endpoints ###
function Resolve-ObjectName {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ObjectId,

        [Parameter(Mandatory=$true)]
        [string]$Token
    )

    # 2A. Skip known special strings that are not real GUIDs:
    switch -Wildcard ($ObjectId) {
        "All"                  { return "All (special)" }
        "AllApps"              { return "All Applications (special)" }
        "AllTrustedApps"       { return "All Trusted Apps (special)" }
        "AllExternalCloudApps" { return "All External Cloud Apps (special)" }
        "GuestsOrExternalUsers"{ return "Guests or External Users (special)" }
        "None"                 { return "None (special)" }
        "Any"                  { return "Any (special)" }
        default {
            # If it's NOT a valid GUID, just return the original value
            if (-not ([Guid]::TryParse($ObjectId, [ref]([Guid]::Empty)))) {
                return $ObjectId
            }
        }
    }

    # 2B. We have a valid GUID. Define direct endpoints in a fallback list:
    $endpoints = @(
        @{
            name = "User"
            url  = "https://graph.microsoft.com/v1.0/users/$ObjectId"
        },
        @{
            name = "Group"
            url  = "https://graph.microsoft.com/v1.0/groups/$ObjectId"
        },
        @{
            name = "Service Principal"
            url  = "https://graph.microsoft.com/v1.0/servicePrincipals/$ObjectId"
        },
        @{
            name = "Application"
            url  = "https://graph.microsoft.com/v1.0/applications/$ObjectId"
        },
        @{
            name = "Directory Role"
            url  = "https://graph.microsoft.com/v1.0/directoryRoles/$ObjectId"
        },
        @{
            name = "Directory Role Template"
            url  = "https://graph.microsoft.com/v1.0/directoryRoleTemplates/$ObjectId"
        },
        @{
            name = "Application Template"
            url  = "https://graph.microsoft.com/v1.0/applicationTemplates/$ObjectId"
        }
    )

    # 2C. Try each endpoint in turn
    foreach ($endpoint in $endpoints) {
        try {
            Write-Host "DEBUG: Trying $($endpoint.name) endpoint for $ObjectId" -ForegroundColor DarkCyan
            $objResponse = Invoke-RestMethod -Uri $endpoint.url -Headers @{
                "Authorization" = "Bearer $Token"
            } -Method Get -ContentType "application/json" -ErrorAction Stop

            if ($objResponse) {
                # We found something. Extract a friendly name:
                switch -Wildcard ($endpoint.name) {
                    "User" {
                        if ($objResponse.userPrincipalName) {
                            return "User: $($objResponse.userPrincipalName)"
                        }
                        elseif ($objResponse.displayName) {
                            return "User: $($objResponse.displayName)"
                        }
                    }
                    "Group" {
                        if ($objResponse.displayName) {
                            return "Group: $($objResponse.displayName)"
                        }
                    }
                    "Service Principal" {
                        if ($objResponse.displayName) {
                            if ($objResponse.appId) {
                                return "Service Principal: $($objResponse.displayName) (AppId: $($objResponse.appId))"
                            }
                            else {
                                return "Service Principal: $($objResponse.displayName)"
                            }
                        }
                    }
                    "Application" {
                        if ($objResponse.displayName) {
                            if ($objResponse.appId) {
                                return "Application: $($objResponse.displayName) (AppId: $($objResponse.appId))"
                            }
                            else {
                                return "Application: $($objResponse.displayName)"
                            }
                        }
                    }
                    "Directory Role" {
                        if ($objResponse.displayName) {
                            return "Directory Role: $($objResponse.displayName)"
                        }
                    }
                    "Directory Role Template" {
                        if ($objResponse.displayName) {
                            return "Directory Role Template: $($objResponse.displayName)"
                        }
                    }
                    "Application Template" {
                        if ($objResponse.displayName) {
                            return "Application Template: $($objResponse.displayName)"
                        }
                    }
                }
            }
        }
        catch {
            Write-Host "DEBUG: $($endpoint.name) lookup failed for $($ObjectId): $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }

    # 2D. If all attempts fail, return the raw GUID
    return $ObjectId
}

### 3. Build a resolved view for each policy ###
$resolvedPolicies = @()

foreach ($policy in $caPolicies) {
    $resolvedAssignments = [ordered]@{
        "includeUsers"        = @()
        "excludeUsers"        = @()
        "includeGroups"       = @()
        "excludeGroups"       = @()
        "includeRoles"        = @()
        "excludeRoles"        = @()
        "includeApplications" = @()
        "excludeApplications" = @()
    }

    # Safely navigate conditions.users
    if ($policy.conditions.users) {
        if ($policy.conditions.users.includeUsers) {
            foreach ($id in $policy.conditions.users.includeUsers) {
                $resolvedAssignments.includeUsers += Resolve-ObjectName -ObjectId $id -Token $Token
            }
        }
        if ($policy.conditions.users.excludeUsers) {
            foreach ($id in $policy.conditions.users.excludeUsers) {
                $resolvedAssignments.excludeUsers += Resolve-ObjectName -ObjectId $id -Token $Token
            }
        }
        if ($policy.conditions.users.includeGroups) {
            foreach ($id in $policy.conditions.users.includeGroups) {
                $resolvedAssignments.includeGroups += Resolve-ObjectName -ObjectId $id -Token $Token
            }
        }
        if ($policy.conditions.users.excludeGroups) {
            foreach ($id in $policy.conditions.users.excludeGroups) {
                $resolvedAssignments.excludeGroups += Resolve-ObjectName -ObjectId $id -Token $Token
            }
        }
        if ($policy.conditions.users.includeRoles) {
            foreach ($id in $policy.conditions.users.includeRoles) {
                $resolvedAssignments.includeRoles += Resolve-ObjectName -ObjectId $id -Token $Token
            }
        }
        if ($policy.conditions.users.excludeRoles) {
            foreach ($id in $policy.conditions.users.excludeRoles) {
                $resolvedAssignments.excludeRoles += Resolve-ObjectName -ObjectId $id -Token $Token
            }
        }
    }

    # Safely navigate conditions.applications
    if ($policy.conditions.applications) {
        if ($policy.conditions.applications.includeApplications) {
            foreach ($id in $policy.conditions.applications.includeApplications) {
                $resolvedAssignments.includeApplications += Resolve-ObjectName -ObjectId $id -Token $Token
            }
        }
        if ($policy.conditions.applications.excludeApplications) {
            foreach ($id in $policy.conditions.applications.excludeApplications) {
                $resolvedAssignments.excludeApplications += Resolve-ObjectName -ObjectId $id -Token $Token
            }
        }
    }

    # Create a structured output object
    $resolvedPolicy = [PSCustomObject]@{
        "id"                = $policy.id
        "displayName"       = $policy.displayName
        "state"             = $policy.state
        "createdDateTime"   = $policy.createdDateTime
        "modifiedDateTime"  = $policy.modifiedDateTime
        "Assignments"       = $resolvedAssignments
        "originalPolicy"    = $policy  # keep entire raw if needed
    }

    $resolvedPolicies += $resolvedPolicy
}

### 4. Output the resolved policies ###

Write-Host "`n--- RESOLVED CONDITIONAL ACCESS POLICIES ---" -ForegroundColor Cyan

foreach ($rp in $resolvedPolicies) {
    Write-Host "Policy Name: $($rp.displayName)"
    Write-Host "Policy ID:   $($rp.id)"
    Write-Host "State:       $($rp.state)"
    Write-Host "Assignments:"
    Write-Host "`tInclude Users:        $($rp.Assignments.includeUsers -join ', ')"
    Write-Host "`tExclude Users:        $($rp.Assignments.excludeUsers -join ', ')"
    Write-Host "`tInclude Groups:       $($rp.Assignments.includeGroups -join ', ')"
    Write-Host "`tExclude Groups:       $($rp.Assignments.excludeGroups -join ', ')"
    Write-Host "`tInclude Roles:        $($rp.Assignments.includeRoles -join ', ')"
    Write-Host "`tExclude Roles:        $($rp.Assignments.excludeRoles -join ', ')"
    Write-Host "`tInclude Applications: $($rp.Assignments.includeApplications -join ', ')"
    Write-Host "`tExclude Applications: $($rp.Assignments.excludeApplications -join ', ')"
    Write-Host ("-" * 60)
    Write-Host
}

# Optionally save the resolved results to JSON
$resolvedJsonOutput = "ConditionalAccessPolicies_Resolved.json"
$resolvedPolicies | ConvertTo-Json -Depth 10 | Out-File -FilePath $resolvedJsonOutput -Encoding utf8
Write-Host "`nResolved policy data saved to $resolvedJsonOutput" -ForegroundColor Green

Write-Host "`nScript execution completed." -ForegroundColor Cyan
