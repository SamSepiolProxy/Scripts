param(
    [Parameter(Mandatory=$false)]
    [string]$RefreshToken,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI default
    
    [Parameter(Mandatory=$false)]
    [string]$Resource = "https://graph.microsoft.com",
    
    [Parameter(Mandatory=$false)]
    [string]$Scope = "openid offline_access",
    
    [Parameter(Mandatory=$false)]
    [string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    
    [Parameter(Mandatory=$false)]
    [string]$Origin,
    
    [Parameter(Mandatory=$false)]
    [switch]$PrintCommand,
    
    [Parameter(Mandatory=$false)]
    [switch]$FromFile,
    
    [Parameter(Mandatory=$false)]
    [string]$TokenFile
)

function Get-NewTokensFromRefreshToken {
    param(
        [string]$ClientId,
        [string]$Scope,
        [string]$Resource,
        [string]$RefreshToken,
        [string]$UserAgent,
        [string]$Origin
    )
    
    $tokenEndpoint = "https://login.microsoftonline.com/common/oauth2/token"
    
    $body = @{
        grant_type = "refresh_token"
        client_id = $ClientId
        scope = $Scope
        resource = $Resource
        refresh_token = $RefreshToken
    }
    
    $headers = @{
        "User-Agent" = $UserAgent
        "Content-Type" = "application/x-www-form-urlencoded"
    }
    
    # Add Origin header if provided (for SPA scenarios)
    if (-not [string]::IsNullOrEmpty($Origin)) {
        $headers["Origin"] = $Origin
    }
    
    try {
        $response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body -Headers $headers
        return $response
    }
    catch {
        Write-Error "Failed to refresh tokens: $_"
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $reader.BaseStream.Position = 0
            $responseBody = $reader.ReadToEnd()
            Write-Error "Response: $responseBody"
        }
        return $null
    }
}

function Get-RefreshTokenCommand {
    param(
        [string]$ClientId,
        [string]$Scope,
        [string]$Resource,
        [string]$UserAgent,
        [string]$Origin,
        [string]$RefreshToken = "PASTE_REFRESH_TOKEN_HERE"
    )
    
    $cmd = if (-not [string]::IsNullOrEmpty($Origin)) {
        @"
`$body=@{grant_type='refresh_token';client_id='$ClientId';scope='$Scope';resource='$Resource';refresh_token='$RefreshToken'};`$headers=@{'User-Agent'='$UserAgent';'Origin'='$Origin'};Invoke-RestMethod -Method Post -Uri 'https://login.microsoftonline.com/common/oauth2/token' -Body `$body -Headers `$headers
"@
    } else {
        @"
`$body=@{grant_type='refresh_token';client_id='$ClientId';scope='$Scope';resource='$Resource';refresh_token='$RefreshToken'};`$headers=@{'User-Agent'='$UserAgent'};Invoke-RestMethod -Method Post -Uri 'https://login.microsoftonline.com/common/oauth2/token' -Body `$body -Headers `$headers
"@
    }
    
    return $cmd
}

function Show-TokenInfo {
    param($TokenResponse)
    
    if ($null -eq $TokenResponse) {
        Write-Host "`n[!] Failed to retrieve tokens" -ForegroundColor Red
        return
    }
    
    Write-Host "`n=== New Token Information ===" -ForegroundColor Green
    
    if ($TokenResponse.access_token) {
        Write-Host "`n[+] Access Token:" -ForegroundColor Cyan
        Write-Host $TokenResponse.access_token
        Write-Host "`n    Token Type: $($TokenResponse.token_type)"
        Write-Host "    Expires In: $($TokenResponse.expires_in) seconds"
        Write-Host "    Expires On: $($TokenResponse.expires_on)"
    }
    
    if ($TokenResponse.refresh_token) {
        Write-Host "`n[+] New Refresh Token:" -ForegroundColor Cyan
        Write-Host $TokenResponse.refresh_token
    }
    
    if ($TokenResponse.id_token) {
        Write-Host "`n[+] ID Token:" -ForegroundColor Cyan
        Write-Host $TokenResponse.id_token
    }
    
    if ($TokenResponse.resource) {
        Write-Host "`n[+] Resource:" -ForegroundColor Cyan
        Write-Host "    $($TokenResponse.resource)"
    }
    
    if ($TokenResponse.scope) {
        Write-Host "`n[+] Granted Scopes:" -ForegroundColor Cyan
        Write-Host "    $($TokenResponse.scope)"
    }
    
    # Save to file
    $outputFile = "refreshed_tokens_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $TokenResponse | ConvertTo-Json -Depth 10 | Out-File $outputFile
    Write-Host "`n[*] Tokens saved to: $outputFile" -ForegroundColor Yellow
}

# Mode 1: Print command template
if ($PrintCommand) {
    Write-Host "=== PowerShell One-Liner for Refresh Token Flow ===" -ForegroundColor Green
    Write-Host ""
    $cmd = Get-RefreshTokenCommand -ClientId $ClientId -Scope $Scope -Resource $Resource -UserAgent $UserAgent -Origin $Origin
    Write-Host $cmd -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Replace 'PASTE_REFRESH_TOKEN_HERE' with your actual refresh token" -ForegroundColor Cyan
    exit 0
}

# Mode 2: Load refresh token from file
if ($FromFile) {
    if ([string]::IsNullOrEmpty($TokenFile)) {
        # Try to find the most recent token file
        $tokenFiles = Get-ChildItem -Path "." -Filter "azure_tokens_*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
        if ($tokenFiles.Count -eq 0) {
            $tokenFiles = Get-ChildItem -Path "." -Filter "refreshed_tokens_*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
        }
        
        if ($tokenFiles.Count -eq 0) {
            Write-Host "[!] Error: No token files found in current directory" -ForegroundColor Red
            Write-Host "[!] Use -TokenFile to specify a file path" -ForegroundColor Red
            exit 1
        }
        
        $TokenFile = $tokenFiles[0].FullName
        Write-Host "[*] Using token file: $TokenFile" -ForegroundColor Cyan
    }
    
    if (-not (Test-Path $TokenFile)) {
        Write-Host "[!] Error: Token file not found: $TokenFile" -ForegroundColor Red
        exit 1
    }
    
    try {
        $tokenData = Get-Content $TokenFile -Raw | ConvertFrom-Json
        $RefreshToken = $tokenData.refresh_token
        
        if ([string]::IsNullOrEmpty($RefreshToken)) {
            Write-Host "[!] Error: No refresh_token found in file" -ForegroundColor Red
            exit 1
        }
        
        Write-Host "[*] Refresh token loaded from file" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error reading token file: $_" -ForegroundColor Red
        exit 1
    }
}

# Mode 3: Interactive or direct refresh
if ([string]::IsNullOrEmpty($RefreshToken)) {
    Write-Host "=== Azure OAuth2 Refresh Token Flow ===" -ForegroundColor Green
    Write-Host "`nConfiguration:" -ForegroundColor Cyan
    Write-Host "  Client ID: $ClientId"
    Write-Host "  Resource: $Resource"
    Write-Host "  Scope: $Scope"
    Write-Host "  User-Agent: $UserAgent"
    if (-not [string]::IsNullOrEmpty($Origin)) {
        Write-Host "  Origin: $Origin" -ForegroundColor Yellow
    }
    
    Write-Host "`n[1] Paste your refresh token below and press ENTER:" -ForegroundColor Yellow
    Write-Host ">" -NoNewline -ForegroundColor Green
    $RefreshToken = Read-Host
    
    if ([string]::IsNullOrEmpty($RefreshToken)) {
        Write-Host "`n[!] Error: Refresh token is required" -ForegroundColor Red
        exit 1
    }
}
else {
    Write-Host "=== Azure OAuth2 Refresh Token Flow ===" -ForegroundColor Green
    Write-Host "[*] Using provided refresh token" -ForegroundColor Cyan
}

# Perform token refresh
Write-Host "`n[*] Refreshing tokens..." -ForegroundColor Yellow

# Show the one-liner option
Write-Host "`n    === OR use this PowerShell one-liner on another system ===" -ForegroundColor Magenta
$oneLiner = Get-RefreshTokenCommand -ClientId $ClientId -Scope $Scope -Resource $Resource -UserAgent $UserAgent -Origin $Origin -RefreshToken $RefreshToken
Write-Host "    " -NoNewline
Write-Host $oneLiner -ForegroundColor DarkGray

Write-Host "`n[*] Exchanging refresh token for new tokens..." -ForegroundColor Yellow
$tokens = Get-NewTokensFromRefreshToken -ClientId $ClientId -Scope $Scope -Resource $Resource -RefreshToken $RefreshToken -UserAgent $UserAgent -Origin $Origin

if ($null -ne $tokens) {
    Show-TokenInfo -TokenResponse $tokens
    Write-Host "`n[*] Done! You can use the new refresh token to get tokens again later." -ForegroundColor Green
}
else {
    Write-Host "`n[!] Token refresh failed" -ForegroundColor Red
    exit 1
}
