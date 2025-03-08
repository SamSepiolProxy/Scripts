<#
.SYNOPSIS
    Retrieves tenant display name information from Microsoft Graph beta based on a given Tenant ID.
.DESCRIPTION
    This script accepts a Tenant ID and a valid Microsoft Graph access token as parameters.
    It then queries the Microsoft Graph beta endpoint:
      https://graph.microsoft.com/beta/tenantRelationships/findTenantInformationByTenantId(tenantId='<TenantId>')
    The response is used to output the tenant’s display name.
.PARAMETER Token
    A valid Bearer token with appropriate permissions.
.PARAMETER TenantId
    The Tenant ID (GUID) that you wish to convert to a display name.
.EXAMPLE
    .\Convert-TenantIdToNameBeta.ps1 -Token "eyJ0eXAiOiJKV1QiLCJ..." -TenantId "72f988bf-86f1-41af-91ab-2d7cd011db47a"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Token,

    [Parameter(Mandatory = $true)]
    [string]$TenantId
)

# Construct the API URL using the tenant ID provided
$uri = "https://graph.microsoft.com/v1.0/tenantRelationships/findTenantInformationByTenantId(tenantId='$TenantId')"

# Set up the request headers with the provided access token
$headers = @{
    "Authorization" = "Bearer $Token"
    "Content-Type"  = "application/json"
}

try {
    Write-Output "Querying Microsoft Graph beta for tenant information..."
    
    # Make the GET request to the Graph beta endpoint
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers

    # Check and output the tenant display name if available.
    # The response is expected to include a property like 'displayName'
    if ($response -and $response.displayName) {
        Write-Output "Tenant ID    : $TenantId"
        Write-Output "Display Name : $($response.displayName)"
    }
    else {
        Write-Output "No display name found for Tenant ID: $TenantId"
    }
}
catch {
    Write-Error "Error retrieving tenant information: $_"
}