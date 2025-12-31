# Azure OAuth2 Scripts - Usage Examples

## Invoke-AzureAuthCode-Enhanced.ps1

### Basic Usage
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1
```

### With Client ID
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -ClientId "1950a258-227b-4e31-a9cf-717495945fc2"
```

### With Client ID and Resource
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -ClientId "04b07795-8ddb-461a-bbee-02f9e1bf7b46" -Resource "https://management.azure.com"
```

### With Tenant
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -Tenant "contoso.onmicrosoft.com"
```

### With Custom User-Agent
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -UserAgent "AzureCLI/2.55.0 (Windows-10.0.22621.0)"
```

### Azure CLI Client
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -ClientId "04b07795-8ddb-461a-bbee-02f9e1bf7b46" -RedirectUri "http://localhost"
```

### Azure PowerShell Client
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" -RedirectUri "urn:ietf:wg:oauth:2.0:oob"
```

### Microsoft Graph PowerShell Client
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -ClientId "14d82eec-204b-4c2f-b7e8-296a70dab67e" -RedirectUri "http://localhost"
```

### Print Auth URL Only
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -PrintUrl
```

### Print Auth URL with Client ID
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -PrintUrl -ClientId "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
```

### Print Token Exchange Command Template
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -PrintCommand
```

### Print Token Exchange Command with Custom Settings
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -PrintCommand -ClientId "04b07795-8ddb-461a-bbee-02f9e1bf7b46" -Resource "https://vault.azure.net"
```

### Generate Complete Command with Auth Code
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -GenerateTokenCommand -AuthCode "0.AXXX..."
```

### Direct Token Exchange
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -AuthCode "0.AXXX..."
```

### Direct Token Exchange with All Parameters
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -AuthCode "0.AXXX..." -ClientId "04b07795-8ddb-461a-bbee-02f9e1bf7b46" -Resource "https://management.azure.com"
```

### Key Vault Token
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -Resource "https://vault.azure.net"
```

### Azure Storage Token
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -Resource "https://storage.azure.com"
```

### Azure DevOps Token
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -Resource "https://app.vssps.visualstudio.com"
```

### Complete Azure CLI Example
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -ClientId "04b07795-8ddb-461a-bbee-02f9e1bf7b46" -RedirectUri "http://localhost" -Resource "https://management.azure.com" -UserAgent "AzureCLI/2.55.0 (Windows-10.0.22621.0)"
```

### Complete Azure PowerShell Example
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" -RedirectUri "urn:ietf:wg:oauth:2.0:oob" -UserAgent "AzurePowershell/v11.1.0 PSVersion/7.4.0 (Windows 10.0.22621.0)"
```

---

## Invoke-AzureRefreshToken.ps1

### Basic Usage (Interactive)
```powershell
.\Invoke-AzureRefreshToken.ps1
```

### With Refresh Token
```powershell
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..."
```

### From File (Auto-detect)
```powershell
.\Invoke-AzureRefreshToken.ps1 -FromFile
```

### From Specific File
```powershell
.\Invoke-AzureRefreshToken.ps1 -FromFile -TokenFile "azure_tokens_20241126_153045.json"
```

### With Client ID
```powershell
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -ClientId "1950a258-227b-4e31-a9cf-717495945fc2"
```

### With Resource
```powershell
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -Resource "https://management.azure.com"
```

### With User-Agent
```powershell
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -UserAgent "AzureCLI/2.55.0 (Windows-10.0.22621.0)"
```

### With Origin Header
```powershell
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -Origin "https://portal.azure.com"
```

### Print Command Template
```powershell
.\Invoke-AzureRefreshToken.ps1 -PrintCommand
```

### Print Command with Custom Settings
```powershell
.\Invoke-AzureRefreshToken.ps1 -PrintCommand -ClientId "04b07795-8ddb-461a-bbee-02f9e1bf7b46" -Resource "https://vault.azure.net"
```

### Azure Management Token
```powershell
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -Resource "https://management.azure.com"
```

### Key Vault Token
```powershell
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -Resource "https://vault.azure.net"
```

### Azure Storage Token
```powershell
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -Resource "https://storage.azure.com"
```

### Azure CLI Style
```powershell
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -ClientId "04b07795-8ddb-461a-bbee-02f9e1bf7b46" -UserAgent "AzureCLI/2.55.0 (Windows-10.0.22621.0)"
```

### Azure PowerShell Style
```powershell
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" -UserAgent "AzurePowershell/v11.1.0 PSVersion/7.4.0 (Windows 10.0.22621.0)"
```

### Azure Portal SPA
```powershell
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -ClientId "c44b4083-3bb0-49c1-b47d-974e53cbdf3c" -Origin "https://portal.azure.com"
```

### Microsoft Teams SPA
```powershell
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" -Origin "https://teams.microsoft.com"
```

### Power BI SPA
```powershell
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -ClientId "23d8f6bd-1eb0-4cc2-a08c-7bf525c67bcd" -Origin "https://app.powerbi.com"
```

### From File with Origin
```powershell
.\Invoke-AzureRefreshToken.ps1 -FromFile -Origin "https://portal.azure.com"
```

### Complete SPA Example
```powershell
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -ClientId "c44b4083-3bb0-49c1-b47d-974e53cbdf3c" -Origin "https://portal.azure.com" -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

### Multiple Resources
```powershell
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -Resource "https://graph.microsoft.com"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -Resource "https://management.azure.com"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -Resource "https://vault.azure.net"
```

---

## Combined Workflows

### Initial Auth + Refresh
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1
.\Invoke-AzureRefreshToken.ps1 -FromFile
```

### Cross-System Workflow
```powershell
# System A
.\Invoke-AzureAuthCode-Enhanced.ps1 -PrintUrl

# System B (after auth)
.\Invoke-AzureAuthCode-Enhanced.ps1 -AuthCode "0.AXXX..."
```

### Extract and Use Refresh Token
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1
$refresh = (gc azure_tokens_*.json | ConvertFrom-Json).refresh_token
.\Invoke-AzureRefreshToken.ps1 -RefreshToken $refresh
```

### Chain Multiple Refreshes
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1
.\Invoke-AzureRefreshToken.ps1 -FromFile
.\Invoke-AzureRefreshToken.ps1 -FromFile
```

### Get Tokens for Different Resources
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1
$refresh = (gc azure_tokens_*.json | ConvertFrom-Json).refresh_token

.\Invoke-AzureRefreshToken.ps1 -RefreshToken $refresh -Resource "https://graph.microsoft.com"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken $refresh -Resource "https://management.azure.com"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken $refresh -Resource "https://vault.azure.net"
```

---

## Extracting and Using Tokens

### Extract Access Token
```powershell
$token = (gc azure_tokens_*.json | ConvertFrom-Json).access_token
```

### Extract Refresh Token
```powershell
$refresh = (gc azure_tokens_*.json | ConvertFrom-Json).refresh_token
```

### Extract from Latest File
```powershell
$tokens = gc refreshed_tokens_*.json | ConvertFrom-Json | Select-Object -First 1
$accessToken = $tokens.access_token
$refreshToken = $tokens.refresh_token
```

### Use Access Token with Graph API
```powershell
$token = (gc azure_tokens_*.json | ConvertFrom-Json).access_token
$headers = @{Authorization = "Bearer $token"}
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers
```

### Use Access Token with Azure Management
```powershell
$token = (gc refreshed_tokens_*.json | ConvertFrom-Json | Select -First 1).access_token
$headers = @{Authorization = "Bearer $token"}
Invoke-RestMethod -Uri "https://management.azure.com/subscriptions?api-version=2021-04-01" -Headers $headers
```

### Use with Origin Header
```powershell
$token = (gc refreshed_tokens_*.json | ConvertFrom-Json | Select -First 1).access_token
$headers = @{
    Authorization = "Bearer $token"
    Origin = "https://portal.azure.com"
}
Invoke-RestMethod -Uri "https://management.azure.com/subscriptions?api-version=2021-04-01" -Headers $headers
```

---

## Automation Examples

### Loop Through Resources
```powershell
$refresh = "0.AXXX..."
$resources = @(
    "https://graph.microsoft.com",
    "https://management.azure.com",
    "https://vault.azure.net"
)

foreach ($resource in $resources) {
    .\Invoke-AzureRefreshToken.ps1 -RefreshToken $refresh -Resource $resource
}
```

### Auto-Renewal Loop
```powershell
while ($true) {
    .\Invoke-AzureRefreshToken.ps1 -FromFile
    Start-Sleep -Seconds 3000
}
```

### Test Multiple Origins
```powershell
$refresh = "0.AXXX..."
$origins = @(
    "https://portal.azure.com",
    "https://teams.microsoft.com",
    "https://app.powerbi.com"
)

foreach ($origin in $origins) {
    .\Invoke-AzureRefreshToken.ps1 -RefreshToken $refresh -Origin $origin
}
```

### Batch Token Generation
```powershell
$clientIds = @(
    "1950a258-227b-4e31-a9cf-717495945fc2",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "14d82eec-204b-4c2f-b7e8-296a70dab67e"
)

foreach ($clientId in $clientIds) {
    .\Invoke-AzureAuthCode-Enhanced.ps1 -PrintUrl -ClientId $clientId
}
```

---

## One-Liner Generation

### Generate Auth Code Exchange One-Liner
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -PrintCommand
```

### Generate Refresh Token One-Liner
```powershell
.\Invoke-AzureRefreshToken.ps1 -PrintCommand
```

### Generate with Auth Code
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -GenerateTokenCommand -AuthCode "0.AXXX..."
```

### Generate for Different Client
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -PrintCommand -ClientId "04b07795-8ddb-461a-bbee-02f9e1bf7b46" -RedirectUri "http://localhost"
```

---

## Common Client IDs

### Azure PowerShell
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -ClientId "1950a258-227b-4e31-a9cf-717495945fc2" -RedirectUri "urn:ietf:wg:oauth:2.0:oob"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -ClientId "1950a258-227b-4e31-a9cf-717495945fc2"
```

### Azure CLI
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -ClientId "04b07795-8ddb-461a-bbee-02f9e1bf7b46" -RedirectUri "http://localhost"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -ClientId "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
```

### Microsoft Graph PowerShell
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -ClientId "14d82eec-204b-4c2f-b7e8-296a70dab67e" -RedirectUri "http://localhost"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -ClientId "14d82eec-204b-4c2f-b7e8-296a70dab67e"
```

### Microsoft Office
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -RedirectUri "https://login.microsoftonline.com/common/oauth2/nativeclient"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
```

### Azure Portal
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -ClientId "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -ClientId "c44b4083-3bb0-49c1-b47d-974e53cbdf3c" -Origin "https://portal.azure.com"
```

### Microsoft Teams
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" -Origin "https://teams.microsoft.com"
```

---

## Resource Examples

### Microsoft Graph
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -Resource "https://graph.microsoft.com"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -Resource "https://graph.microsoft.com"
```

### Azure Management
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -Resource "https://management.azure.com"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -Resource "https://management.azure.com"
```

### Key Vault
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -Resource "https://vault.azure.net"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -Resource "https://vault.azure.net"
```

### Azure Storage
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -Resource "https://storage.azure.com"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -Resource "https://storage.azure.com"
```

### Azure DevOps
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -Resource "https://app.vssps.visualstudio.com"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -Resource "https://app.vssps.visualstudio.com"
```

---

## User-Agent Examples

### Chrome on Windows 11
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
```

### Edge
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
```

### Firefox
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
```

### Azure CLI
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -UserAgent "AzureCLI/2.55.0 (Windows-10.0.22621.0)"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -UserAgent "AzureCLI/2.55.0 (Windows-10.0.22621.0)"
```

### Azure PowerShell
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -UserAgent "AzurePowershell/v11.1.0 PSVersion/7.4.0 (Windows 10.0.22621.0)"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -UserAgent "AzurePowershell/v11.1.0 PSVersion/7.4.0 (Windows 10.0.22621.0)"
```

### PowerShell
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -UserAgent "Microsoft.PowerShell/7.4.0 (Windows NT 10.0; Win64; x64; PowerShell 7.4.0)"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -UserAgent "Microsoft.PowerShell/7.4.0 (Windows NT 10.0; Win64; x64; PowerShell 7.4.0)"
```

### iPhone
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -UserAgent "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -UserAgent "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
```

### Android
```powershell
.\Invoke-AzureAuthCode-Enhanced.ps1 -UserAgent "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36"
.\Invoke-AzureRefreshToken.ps1 -RefreshToken "0.AXXX..." -UserAgent "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36"
```
