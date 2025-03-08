<# 
.SYNOPSIS
    Enumerates valid Microsoft 365 domains, retrieves tenant name, and checks for an MDI instance.

.DESCRIPTION
    It performs various reconnaissance checks (DNS records, HTTP endpoints, federation info, etc.)
    against a supplied domain. It supports output in JSON format as well as standard human‐readable output.
    
    In this version each section (Check-AzureServices, Check-AzureCDN, Check-PowerApps, 
    Check-StorageAccounts, and Check-AppServices) defines its own local list of prefixes.
    For these sections endpoints are constructed using three URL patterns:
      - https://$prefix$domainPrefix.$suffix
      - https://$domainPrefix$prefix.$suffix
      - https://$domainPrefix.$suffix

.PARAMETER Domain
    The input domain name (e.g. example.com).

.PARAMETER Json
    Output the results in JSON format.

.PARAMETER Gov
    Use government tenancy endpoints.

.PARAMETER Cn
    Use Chinese tenancy endpoints.

.EXAMPLE
    .\Get-OrgInfo.ps1 -Domain example.com

.NOTES
    Requires PowerShell v5+.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Input domain name, e.g. example.com")]
    [string]$Domain,

    [switch]$Json,
    [switch]$Gov,
    [switch]$Cn
)

# Global User-Agent string.
$UserAgent = "Mozilla/5.0"

#region Helper Functions

function Get-FederationInfo {
    param ([string]$Domain)
    try {
        $url = "https://login.microsoftonline.com/getuserrealm.srf?login=user@$Domain&json=1"
        $headers = @{ "User-Agent" = $UserAgent }
        return Invoke-RestMethod -Uri $url -Headers $headers -ErrorAction Stop
    }
    catch { return $null }
}

function Get-AzureADConfig {
    param ([string]$Domain)
    try {
        $url = "https://login.microsoftonline.com/$Domain/v2.0/.well-known/openid-configuration"
        $headers = @{ "User-Agent" = $UserAgent }
        return Invoke-RestMethod -Uri $url -Headers $headers -ErrorAction Stop
    }
    catch { return $null }
}

function Check-SharePoint {
    param ([string]$Domain)
    try {
        $tenantBase = $Domain.Split('.')[0]
        $url = "https://$tenantBase.sharepoint.com"
        $headers = @{ "User-Agent" = $UserAgent }
        Invoke-WebRequest -Uri $url -Headers $headers -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        if ($_.Exception.Response -and ($_.Exception.Response.StatusCode.value__ -in 401,403)) { return $true }
        return $false
    }
}

function Get-MXRecords {
    param ([string]$Domain)
    try {
        $mx = Resolve-DnsName -Name $Domain -Type MX -ErrorAction Stop
        return $mx | ForEach-Object { $_.Exchange.TrimEnd('.') }
    }
    catch { return @() }
}

function Get-TXTRecords {
    param ([string]$Domain)
    try {
        $txt = Resolve-DnsName -Name $Domain -Type TXT -ErrorAction Stop
        return $txt | ForEach-Object { ($_."Strings" -join " ") }
    }
    catch { return @() }
}

function Get-AutodiscoverEndpoint {
    param ([string]$Domain)
    try {
        $name = "autodiscover.$Domain"
        $ip = [System.Net.Dns]::GetHostEntry($name).AddressList[0].IPAddressToString
        return $ip
    }
    catch { return $null }
}

## Generate URL variations using the supplied local list of prefixes.
function Get-URLsForService {
    param (
        [string]$Domain, 
        [array]$Suffixes,
        [array]$Prefixes
    )
    $domainPrefix = $Domain.Split('.')[0]
    $urls = @()
    foreach ($prefix in $Prefixes + @($domainPrefix)) {
        foreach ($suffix in $Suffixes) {
            $urls += "https://$prefix$domainPrefix.$suffix"
            $urls += "https://$domainPrefix$prefix.$suffix"
            $urls += "https://$domainPrefix.$suffix"
        }
    }
    return $urls
}

### Service-check functions – each with its own local prefixes.

function Check-AppServices {
    param ([string]$Domain)
    $prefixes = @("appsvc", "webapp")
    $suffixes = @("azurewebsites.net", "scm.azurewebsites.net", "p.azurewebsites.net", "cloudapp.net")
    $urls = Get-URLsForService -Domain $Domain -Suffixes $suffixes -Prefixes $prefixes
    $results = @{}
    $headers = @{ "User-Agent" = $UserAgent }
    foreach ($url in $urls) {
        try {
            Invoke-WebRequest -Uri $url -Headers $headers -ErrorAction Stop | Out-Null
            $results[$url] = "accessible"
        }
        catch {
            if ($_.Exception.Response -and ($_.Exception.Response.StatusCode.value__ -in 401,403)) {
                $results[$url] = "auth_required"
            }
            else { $results[$url] = "not_found" }
        }
    }
    return $results
}

function Check-StorageAccounts {
    param ([string]$Domain)
    $prefixes = @("blob", "data", "storage")
    $suffixes = @("blob.core.windows.net", "file.core.windows.net", "queue.core.windows.net", "table.core.windows.net")
    $urls = Get-URLsForService -Domain $Domain -Suffixes $suffixes -Prefixes $prefixes
    $results = @()
    $headers = @{ "User-Agent" = $UserAgent }
    foreach ($url in $urls) {
        try {
            Invoke-WebRequest -Uri $url -Headers $headers -ErrorAction Stop | Out-Null
            $results += @{ url = $url; status = "accessible" }
        }
        catch {
            if ($_.Exception.Response -and ($_.Exception.Response.StatusCode.value__ -in 401,403)) {
                $results += @{ url = $url; status = "auth_required" }
            }
            else {
                $results += @{ url = $url; status = "not_found" }
            }
        }
    }
    return $results
}

function Check-PowerApps {
    param ([string]$Domain)
    $prefixes = @("app", "portal")
    $suffixes = @("powerappsportals.com", "portal.powerapps.com")
    $urls = Get-URLsForService -Domain $Domain -Suffixes $suffixes -Prefixes $prefixes
    $results = @()
    $headers = @{ "User-Agent" = $UserAgent }
    foreach ($url in $urls) {
        try {
            Invoke-WebRequest -Uri $url -Headers $headers -ErrorAction Stop | Out-Null
            $results += @{ url = $url; status = "accessible" }
        }
        catch {
            if ($_.Exception.Response -and ($_.Exception.Response.StatusCode.value__ -in 401,403)) {
                $results += @{ url = $url; status = "auth_required" }
            }
            else {
                $results += @{ url = $url; status = "not_found" }
            }
        }
    }
    return $results
}

function Check-AzureCDN {
    param ([string]$Domain)
    $prefixes = @("cdn")
    $suffixes = @("azureedge.net")
    $urls = Get-URLsForService -Domain $Domain -Suffixes $suffixes -Prefixes $prefixes
    $results = @()
    $headers = @{ "User-Agent" = $UserAgent }
    foreach ($url in $urls) {
        try {
            [System.Net.Dns]::GetHostEntry($url) | Out-Null
            $results += @{ url = $url; status = "accessible" }
        }
        catch { $results += @{ url = $url; status = "not_found" } }
    }
    return $results
}

function Check-AzureServices {
    param ([string]$Domain)
    $prefixes = @("svc", "api", "az")
    $suffixes = @(
        "vault.azure.net", 
        "azurewebsites.net/api", 
        "z13.web.core.windows.net", 
        "azurecr.io", 
        "cognitiveservices.azure.com", 
        "redis.cache.windows.net", 
        "documents.azure.com", 
        "database.windows.net", 
        "search.windows.net", 
        "azure-api.net"
    )
    $urls = Get-URLsForService -Domain $Domain -Suffixes $suffixes -Prefixes $prefixes
    $results = @{}
    $headers = @{ "User-Agent" = $UserAgent }
    foreach ($url in $urls) {
        try {
            Invoke-WebRequest -Uri $url -Headers $headers -ErrorAction Stop | Out-Null
            $results[$url] = @{ status = "accessible"; url = $url }
        }
        catch {
            if ($_.Exception.Response -and ($_.Exception.Response.StatusCode.value__ -in 401,403)) {
                $results[$url] = @{ status = "protected"; url = $url }
            }
            else { $results[$url] = @{ status = "not_found" } }
        }
    }
    return $results
}

function Check-B2CConfiguration {
    param ([string]$Domain)
    $results = @{
        standard_endpoint = @{ status = "not_found"; details = $null }
        custom_domain     = @{ status = "not_found"; details = $null }
    }
    $headers = @{ "User-Agent" = $UserAgent }
    $standardUrl = "https://$Domain.b2clogin.com"
    try {
        $response = Invoke-WebRequest -Uri $standardUrl -Headers $headers -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            $results.standard_endpoint.status = "found"
            $results.standard_endpoint.details = "B2C tenant endpoint accessible"
            $results.standard_endpoint.url = $standardUrl
        }
    }
    catch [System.Net.WebException] {
        $ex = $_.Exception
        if ($ex.Response -and $ex.Response.StatusCode.value__ -eq 404) {
            $results.standard_endpoint.status = "not_found"
            $results.standard_endpoint.details = "No B2C tenant configured"
        }
        else {
            $results.standard_endpoint.status = "error"
            $results.standard_endpoint.details = "HTTP $($ex.Response.StatusCode.value__)"
        }
    }
    catch {
        $results.standard_endpoint.status = "error"
        $results.standard_endpoint.details = $_.Exception.Message
    }
    try {
        $customUrl = "https://login.$Domain"
        $response = Invoke-WebRequest -Uri $customUrl -Headers $headers -ErrorAction Stop
        $content = $response.Content.ToLower()
        $b2cIndicators = @("b2c", "azure ad b2c", "microsoftonline", "login.microsoftonline")
        if ($b2cIndicators | Where-Object { $content -like "*$_*" }) {
            $results.custom_domain.status = "found"
            $results.custom_domain.details = "Custom B2C login domain detected"
            $results.custom_domain.url = $customUrl
        }
        else {
            $results.custom_domain.status = "not_b2c"
            $results.custom_domain.details = "Login page found but not B2C"
        }
    }
    catch [System.Net.WebException] {
        $ex = $_.Exception
        if ($ex.Response -and $ex.Response.StatusCode.value__ -eq 404) {
            $results.custom_domain.status = "not_found"
            $results.custom_domain.details = "No custom login domain"
        }
        else {
            $results.custom_domain.status = "error"
            $results.custom_domain.details = "HTTP $($ex.Response.StatusCode.value__)"
        }
    }
    catch {
        $results.custom_domain.status = "error"
        $results.custom_domain.details = $_.Exception.Message
    }
    return $results
}

function Check-AADApplications {
    param (
        [string]$Domain,
        [string]$TenantId
    )
    $results = @{
        enterprise_apps   = @{}
        public_apps       = @{}
        oauth_permissions = @()
        service_principals = @()
        multi_tenant_apps = @()
        permission_grants = @()
        insights          = @()
        endpoints         = @{}
    }
    $headers = @{ "User-Agent" = $UserAgent }
    if (-not $TenantId) {
        try {
            $openidUrl = "https://login.microsoftonline.com/$Domain/v2.0/.well-known/openid-configuration"
            $response = Invoke-RestMethod -Uri $openidUrl -Headers $headers -ErrorAction Stop
            if ($response.token_endpoint) {
                $parts = $response.token_endpoint.Split('/')
                if ($parts.Length -ge 4) {
                    $TenantId = $parts[3]
                    $results.endpoints.openid_config = $openidUrl
                }
            }
        }
        catch { }
    }
    if (-not $TenantId) {
        $results.error = "No tenant ID available"
        return $results
    }
    $enterpriseUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize"
    try {
        $response = Invoke-WebRequest -Uri $enterpriseUrl -Headers $headers -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            $results.endpoints.enterprise_apps = $enterpriseUrl
            $content = $response.Content
            $matches = [regex]::Matches($content, 'client_id=([0-9a-f-]{36})')
            $appIds = @()
            foreach ($match in $matches) {
                if ($match.Groups[1].Value) { $appIds += $match.Groups[1].Value }
            }
            if ($appIds.Count -gt 0) {
                $results.enterprise_apps.exposed_apps = $appIds
                $results.insights += "Found exposed enterprise application IDs - Potential OAuth abuse targets"
                foreach ($appId in $appIds) {
                    try {
                        $appUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?client_id=$appId&response_type=id_token"
                        $appResponse = Invoke-WebRequest -Uri $appUrl -Headers $headers -ErrorAction Stop
                        if ($appResponse.StatusCode -eq 200) {
                            $appContent = $appResponse.Content
                            if ($appContent -match "common" -or $appContent -match "organizations") {
                                $results.multi_tenant_apps += $appId
                                $results.insights += "Multi-tenant app found: $appId - Potential for lateral movement"
                            }
                        }
                    }
                    catch { continue }
                }
            }
        }
    }
    catch { $results.enterprise_apps.error = $_.Exception.Message }
    $publicUrl = "https://login.microsoftonline.com/$TenantId/adminconsent"
    try {
        $response = Invoke-WebRequest -Uri $publicUrl -Headers $headers -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            $results.public_apps.status = "accessible"
            $results.endpoints.admin_consent = $publicUrl
            $results.insights += "Admin consent endpoint is accessible - Check for consent phishing opportunities"
        }
        elseif ($response.StatusCode -eq 401) { $results.public_apps.status = "auth_required" }
    }
    catch { $results.public_apps.error = $_.Exception.Message }
    try {
        $spUrl = "https://graph.windows.net/$TenantId/servicePrincipals?api-version=1.6"
        $response = Invoke-WebRequest -Uri $spUrl -Headers $headers -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            $content = $response.Content
            $spNames = ([regex]::Matches($content, '"displayName":"([^"]+)"')).Groups[1].Value
            if ($spNames) {
                $results.service_principals = $spNames
                $results.insights += "Service principal names exposed - Review for sensitive application names"
            }
        }
    }
    catch { }
    try {
        $manifestUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?client_id=common&response_type=id_token&scope=openid profile"
        $response = Invoke-WebRequest -Uri $manifestUrl -Headers $headers -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            $content = $response.Content
            $scopes = ([regex]::Matches($content, 'scope="([^"]+)"')).Groups[1].Value
            if ($scopes) {
                $results.oauth_permissions = $scopes
                foreach ($scope in $scopes) {
                    if ($scope.ToLower() -match "mail" -or $scope.ToLower() -match "files" -or $scope.ToLower() -match "directory" -or $scope.ToLower() -match "user_impersonation" -or $scope.ToLower() -match "full") {
                        $results.permission_grants += $scope
                        $results.insights += "High-privilege OAuth scope found: $scope"
                    }
                }
                if ($results.permission_grants.Count -gt 0) {
                    $results.insights += "High-privilege OAuth scopes detected - Review for potential abuse vectors"
                }
            }
        }
    }
    catch { $results.oauth_permissions_error = $_.Exception.Message }
    return $results
}

function Check-MDIInstance {
    param ([string]$Domain)
    $results = @{
        detected             = $false
        details              = $null
        redteam_implications = @()
    }
    $headers = @{ "User-Agent" = $UserAgent }
    try {
        $mdiUrl = "https://sensor.atp.azure.com/test/$Domain"
        $response = Invoke-WebRequest -Uri $mdiUrl -Headers $headers -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            $results.detected = $true
            $results.details  = "MDI instance active"
            $results.redteam_implications = @(
                "MDI monitors AD authentication patterns and will detect suspicious Kerberos activity (Golden/Silver tickets, overpass-the-hash)",
                "Lateral movement techniques like remote execution and NTLM relay attacks are monitored and alerted on"
            )
        }
    }
    catch { }
    return $results
}

function Check-TeamsPresence {
    param ([string]$Domain)
    $results = @{ teams = $false; skype = $false }
    try {
        Resolve-DnsName -Name "lyncdiscover.$Domain" -Type CNAME -ErrorAction Stop | Out-Null
        $results.teams = $true
    }
    catch { }
    try {
        Resolve-DnsName -Name "sip.$Domain" -Type CNAME -ErrorAction Stop | Out-Null
        $results.skype = $true
    }
    catch { }
    return $results
}

function Check-AADConnectStatus {
    param ([string]$Domain)
    $results = @{}
    $testEmail = "nonexistent@$Domain"
    $url = "https://login.microsoftonline.com/getuserrealm.srf?login=$testEmail"
    $headers = @{ "User-Agent" = $UserAgent }
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -ErrorAction Stop
        $results.name_space_type       = $response.NameSpaceType
        $results.federation_protocol   = $response.FederationProtocol
        $results.domain_type           = $response.DomainType
        $results.federation_brand_name = $response.FederationBrandName
        $results.cloud_instance        = $response.CloudInstanceName
        if ($response.DomainType -eq "Federated") {
            $results.hybrid_config = "Federated (Hybrid Identity)"
        }
        elseif ($response.DomainType -eq "Managed") {
            $results.hybrid_config = "Managed (Cloud Only)"
        }
        else {
            $results.hybrid_config = "Unknown"
        }
        if ($response.AuthURL) { $results.auth_url = $response.AuthURL }
        if ($response.FederationGlobalVersion) { $results.federation_version = $response.FederationGlobalVersion }
    }
    catch {
        $results.error = $_.Exception.Message
    }
    return $results
}

function Get-TenantId {
    param ([string]$Domain)
    $headers = @{ "User-Agent" = $UserAgent }
    try {
        $url = "https://login.microsoftonline.com/$Domain/v2.0/.well-known/openid-configuration"
        $response = Invoke-RestMethod -Uri $url -Headers $headers -ErrorAction Stop
        $tokenEndpoint = $response.token_endpoint
        if ($tokenEndpoint) {
            $parts = $tokenEndpoint.Split('/')
            $tenantId = $parts[3]
            if ($tenantId -eq "v2.0") { return $null }
            return $tenantId
        }
        return $null
    }
    catch { return $null }
}

function Print-ReconResults {
    param (
        [hashtable]$Results,
        [switch]$JsonOutput
    )
    if ($JsonOutput) {
        $Results | ConvertTo-Json -Depth 10
        return
    }
    Write-Host "`n[+] Target Organization:"
    if ($Results.tenant) { Write-Host "Tenant Name: $($Results.tenant)" }
    if ($Results.tenant_id) { Write-Host "Tenant ID: $($Results.tenant_id)" }
    Write-Host "`n[+] Federation Information:"
    if ($Results.federation_info.name_space_type) { Write-Host "Namespace Type: $($Results.federation_info.name_space_type)" }
    if ($Results.federation_info.federation_brand_name) { Write-Host "Brand Name: $($Results.federation_info.federation_brand_name)" }
    if ($Results.federation_info.cloud_instance) { Write-Host "Cloud Instance: $($Results.federation_info.cloud_instance)" }
    Write-Host "`n[+] Azure AD Configuration:"
    if ($Results.azure_ad_config.tenant_region_scope) { Write-Host "Tenant Region: $($Results.azure_ad_config.tenant_region_scope)" }
    Write-Host "`n[+] Azure AD Connect Status:"
    if ($Results.aad_connect) {
        if (-not $Results.aad_connect.error) {
            $config = $Results.aad_connect.hybrid_config
            $auth = $Results.aad_connect.name_space_type
            Write-Host "  Identity Configuration: $config"
            Write-Host "  Authentication Type: $auth"
            if ($auth -eq "managed") {
                Write-Host "`n  [!] Identity Insights:"
                Write-Host "  * Cloud-only authentication detected - No on-premises AD present"
                Write-Host "  * All authentication handled in Azure AD"
                Write-Host "  * Focus on cloud-based attack vectors (OAuth, Device Code, Password Spray)"
            }
            elseif ($auth -eq "federated") {
                Write-Host "`n  [!] Identity Insights:"
                Write-Host "  * Hybrid identity configuration detected - On-premises AD integration"
                Write-Host "  * Authentication may be handled by on-premises ADFS"
                Write-Host "  * Consider both cloud and on-premises attack vectors"
            }
            if ($Results.aad_connect.auth_url) { Write-Host "`n  Federation Auth URL: $($Results.aad_connect.auth_url)" }
            if ($Results.aad_connect.federation_version) { Write-Host "  Federation Version: $($Results.aad_connect.federation_version)" }
        }
        else { Write-Host "  Error checking AAD Connect status: $($Results.aad_connect.error)" }
    }
    Write-Host "`n[+] Microsoft 365 Services:"
    Write-Host "SharePoint Detected: $(if ($Results.m365_services.sharepoint) { 'Yes' } else { 'No' })"
    if ($Results.m365_services.mx_records) {
        Write-Host "`nMX Records:"; foreach ($r in $Results.m365_services.mx_records) { Write-Host "  - $r" }
    }
    if ($Results.m365_services.txt_records) {
        Write-Host "`nRelevant TXT Records:"; foreach ($r in $Results.m365_services.txt_records) { if ($r.ToLower() -match "microsoft" -or $r.ToLower() -match "spf") { Write-Host "  - $r" } }
    }
    if ($Results.m365_services.autodiscover) { Write-Host "`nAutodiscover Endpoint: $($Results.m365_services.autodiscover)" }
    Write-Host "`n[+] Microsoft 365 Usage: $(if ($Results.uses_microsoft_365) { 'Confirmed' } else { 'Not Detected' })"
    Write-Host "`n[+] Azure Services:"
    if ($Results.azure_services.app_services) {
        Write-Host "`nAzure App Services:"; foreach ($a in $Results.azure_services.app_services.Keys) { Write-Host "  - $a ($($Results.azure_services.app_services[$a]))" }
    }
    if ($Results.azure_services.storage_accounts) {
        Write-Host "`nAzure Storage Accounts:"; foreach ($s in $Results.azure_services.storage_accounts) { Write-Host "  - $($s.url) ($($s.status))" }
    }
    if ($Results.azure_services.power_apps) {
        Write-Host "`nPower Apps Portals:"; foreach ($p in $Results.azure_services.power_apps) { Write-Host "  - $($p.url) ($($p.status))" }
    }
    if ($Results.azure_services.cdn_endpoints) {
        Write-Host "`nAzure CDN Endpoints:"; foreach ($c in $Results.azure_services.cdn_endpoints) { Write-Host "  - $($c.url) ($($c.status))" }
    }
    Write-Host "`nAzure B2C Configuration:"
    if ($Results.azure_services.b2c_configuration) {
        Write-Host "  Standard B2C Endpoint: $($Results.azure_services.b2c_configuration.standard_endpoint.status) ($($Results.azure_services.b2c_configuration.standard_endpoint.details))"
        if ($Results.azure_services.b2c_configuration.standard_endpoint.status -eq "found") { Write-Host "    URL: $($Results.azure_services.b2c_configuration.standard_endpoint.url)" }
        Write-Host "  Custom Domain Login: $($Results.azure_services.b2c_configuration.custom_domain.status) ($($Results.azure_services.b2c_configuration.custom_domain.details))"
        if ($Results.azure_services.b2c_configuration.custom_domain.status -eq "found") { Write-Host "    URL: $($Results.azure_services.b2c_configuration.custom_domain.url)" }
    }
    Write-Host "`n[+] Communication Services:"
    Write-Host "Microsoft Teams: $(if ($Results.communication_services.teams) { 'Detected' } else { 'Not Detected' })"
    Write-Host "Skype for Business: $(if ($Results.communication_services.skype) { 'Detected' } else { 'Not Detected' })"
    if ($Results.domains) {
        Write-Host "`n[+] Domains found:"; $Results.domains | ForEach-Object { Write-Host $_ }
    }
    Write-Host "`n[+] Microsoft Defender for Identity (MDI) Instance Detected: $($Results.mdi_instance.detected)"
    if ($Results.mdi_instance.detected) {
        Write-Host "  Details: $($Results.mdi_instance.details)"
        Write-Host "  Red Team Implications:"; foreach ($imp in $Results.mdi_instance.redteam_implications) { Write-Host "  * $imp" }
    }
    Write-Host "`n[+] Azure AD Applications:"
    if ($Results.aad_applications) {
        if (-not $Results.aad_applications.error) {
            if ($Results.aad_applications.enterprise_apps) {
                Write-Host "`n  Enterprise Applications:"; 
                if ($Results.aad_applications.enterprise_apps.exposed_apps) {
                    Write-Host "  * Exposed Application IDs:"; foreach ($id in $Results.aad_applications.enterprise_apps.exposed_apps) { Write-Host "    - $id" }
                    if ($Results.aad_applications.endpoints.enterprise_apps) { Write-Host "    Endpoint: $($Results.aad_applications.endpoints.enterprise_apps)" }
                }
                elseif ($Results.aad_applications.enterprise_apps.error) { Write-Host "  * Error checking enterprise apps: $($Results.aad_applications.enterprise_apps.error)" }
            }
            if ($Results.aad_applications.public_apps) {
                Write-Host "`n  Public Applications:"; 
                $status = $Results.aad_applications.public_apps.status
                Write-Host "  * Admin Consent Endpoint: $status"
                if ($status -eq "accessible" -and $Results.aad_applications.endpoints.admin_consent) { Write-Host "    URL: $($Results.aad_applications.endpoints.admin_consent)" }
            }
            if ($Results.aad_applications.service_principals) {
                Write-Host "`n  Service Principals:"; foreach ($sp in $Results.aad_applications.service_principals) { Write-Host "  * $sp" }
            }
            if ($Results.aad_applications.permission_grants) {
                Write-Host "`n  High-Privilege OAuth Permissions:"; foreach ($perm in $Results.aad_applications.permission_grants) { Write-Host "  * $perm" }
            }
            if ($Results.aad_applications.insights) {
                Write-Host "`n  [!] Application Security Insights:"; foreach ($insight in $Results.aad_applications.insights) { Write-Host "  * $insight" }
            }
        }
        else { Write-Host "  Error checking AAD applications: $($Results.aad_applications.error)" }
    }
}

#endregion

#region Main Logic

function Get-Domains {
    param (
        [string]$Domain,
        [switch]$Json,
        [switch]$Gov,
        [switch]$Cn
    )
    if (-not $Json) { Write-Host "`n[+] Running Azure/M365 Reconnaissance..." }
    $fedInfo = Get-FederationInfo -Domain $Domain
    $azureADConfig = Get-AzureADConfig -Domain $Domain
    $aadConnect = Check-AADConnectStatus -Domain $Domain
    $aadApplications = Check-AADApplications -Domain $Domain -TenantId $null
    $m365Services = @{
        sharepoint   = Check-SharePoint -Domain $Domain
        mx_records   = Get-MXRecords -Domain $Domain
        txt_records  = Get-TXTRecords -Domain $Domain
        autodiscover = Get-AutodiscoverEndpoint -Domain $Domain
    }
    $azureServices = @{
        app_services      = Check-AppServices -Domain $Domain
        storage_accounts  = Check-StorageAccounts -Domain $Domain
        power_apps        = Check-PowerApps -Domain $Domain
        cdn_endpoints     = Check-AzureCDN -Domain $Domain
        azure_services    = Check-AzureServices -Domain $Domain
        b2c_configuration = Check-B2CConfiguration -Domain $Domain
    }
    $communicationServices = Check-TeamsPresence -Domain $Domain
    $mdiInstance = Check-MDIInstance -Domain $Domain

    # Retrieve domains via SOAP.
    $domains = @()
    $tenant = ""
    $body = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" 
    xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" 
    xmlns:a="http://www.w3.org/2005/08/addressing" 
    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" 
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <soap:Header>
        <a:RequestedServerVersion>Exchange2010</a:RequestedServerVersion>
        <a:MessageID>urn:uuid:6389558d-9e05-465e-ade9-aae14c4bcd10</a:MessageID>
        <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
        <a:To soap:mustUnderstand="1">https://autodiscover.byfcxu-dom.extest.microsoft.com/autodiscover/autodiscover.svc</a:To>
        <a:ReplyTo>
        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
    </soap:Header>
    <soap:Body>
        <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
        <Request>
            <Domain>$Domain</Domain>
        </Request>
        </GetFederationInformationRequestMessage>
    </soap:Body>
</soap:Envelope>
"@
    $soapHeaders = @{ "Content-type" = "text/xml; charset=utf-8"; "User-agent" = $UserAgent }
    $soapUrl = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
    if ($Gov) { $soapUrl = "https://autodiscover-s.office365.us/autodiscover/autodiscover.svc" }
    elseif ($Cn) { $soapUrl = "https://autodiscover-s.partner.outlook.cn/autodiscover/autodiscover.svc" }
    try {
        $response = Invoke-WebRequest -Uri $soapUrl -Headers $soapHeaders -Method Post -Body $body -ErrorAction Stop
        $xmlResponse = [xml]$response.Content
        foreach ($elem in $xmlResponse.SelectNodes("//*[local-name()='Domain']")) {
            $domains += $elem.InnerText
        }
    }
    catch {
        if ($Json) { ConvertTo-Json @{ error = "Unable to execute request. Wrong domain" } }
        else { Write-Host "[-] Unable to execute request. Wrong domain?" }
        exit
    }
    foreach ($d in $domains) {
        if ($d -match "onmicrosoft.com") { $tenant = $d.Split('.')[0] }
    }
    $tenantId = Get-TenantId -Domain $Domain

    $reconResults = @{
        domains                = $domains
        tenant                 = $tenant
        tenant_id              = $tenantId
        federation_info        = @{
            name_space_type       = if ($fedInfo) { $fedInfo.NameSpaceType } else { $null }
            federation_brand_name = if ($fedInfo) { $fedInfo.FederationBrandName } else { $null }
            cloud_instance        = if ($fedInfo) { $fedInfo.CloudInstanceName } else { $null }
        }
        azure_ad_config        = $azureADConfig
        aad_connect            = $aadConnect
        aad_applications       = $aadApplications
        m365_services          = $m365Services
        azure_services         = $azureServices
        communication_services = $communicationServices
        mdi_instance           = $mdiInstance
    }
    $uses_m365 = ($m365Services.mx_records -match "outlook.com") -or `
                 ($m365Services.txt_records -match "protection.outlook.com") -or `
                 $m365Services.sharepoint
    $reconResults.uses_microsoft_365 = $uses_m365

    if ($Json) { $reconResults | ConvertTo-Json -Depth 10 }
    else { Print-ReconResults -Results $reconResults }
}

#endregion

# Execute main function
Get-Domains -Domain $Domain -Json:$Json -Gov:$Gov -Cn:$Cn
