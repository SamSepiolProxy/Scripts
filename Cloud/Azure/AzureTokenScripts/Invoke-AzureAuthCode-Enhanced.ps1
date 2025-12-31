param(
    [Parameter(Mandatory=$false)]
    [string]$ClientId = "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell default
    
    [Parameter(Mandatory=$false)]
    [string]$Resource = "https://graph.microsoft.com",
    
    [Parameter(Mandatory=$false)]
    [string]$RedirectUri = "urn:ietf:wg:oauth:2.0:oob",
    
    [Parameter(Mandatory=$false)]
    [string]$Scope = "openid profile offline_access",
    
    [Parameter(Mandatory=$false)]
    [string]$Tenant = "common",
    
    [Parameter(Mandatory=$false)]
    [string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0",
    
    [Parameter(Mandatory=$false)]
    [switch]$PrintUrl,
    
    [Parameter(Mandatory=$false)]
    [switch]$PrintCommand,
    
    [Parameter(Mandatory=$false)]
    [string]$AuthCode,
    
    [Parameter(Mandatory=$false)]
    [switch]$GenerateTokenCommand
)

function Build-AuthUrl {
    param(
        [string]$ClientId,
        [string]$Scope,
        [string]$RedirectUri
    )
    
    $authEndpoint = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/authorize"
    
    $params = @{
        client_id = $ClientId
        response_type = "code"
        redirect_uri = $RedirectUri
        scope = $Scope
        response_mode = "query"
    }
    
    $queryString = ($params.GetEnumerator() | ForEach-Object {
        "$($_.Key)=$([System.Uri]::EscapeDataString($_.Value))"
    }) -join "&"
    
    return "$authEndpoint`?$queryString"
}

function Get-TokenExchangeCommand {
    param(
        [string]$ClientId,
        [string]$RedirectUri,
        [string]$Scope,
        [string]$Tenant,
        [string]$AuthCode = "PASTE_AUTH_CODE_HERE",
        [string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )
    
    $cmd = @"
`$body=@{client_id='$ClientId';redirect_uri='$RedirectUri';grant_type='authorization_code';scope='$Scope';code='$AuthCode'};`$headers=@{'User-Agent'='$UserAgent'};Invoke-RestMethod -Method Post -Uri 'https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token' -Body `$body -ContentType 'application/x-www-form-urlencoded' -Headers `$headers
"@
    
    return $cmd
}

function Request-TokenFromAuthCode {
    param(
        [string]$ClientId,
        [string]$RedirectUri,
        [string]$Scope,
        [string]$AuthCode,
        [string]$UserAgent
    )
    
    $tokenEndpoint = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token"
    
    $body = @{
        client_id = $ClientId
        redirect_uri = $RedirectUri
        grant_type = "authorization_code"
        scope = $Scope
        code = $AuthCode
    }
    
    $headers = @{
        "User-Agent" = $UserAgent
    }
    
    try {
        $response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body -ContentType "application/x-www-form-urlencoded" -Headers $headers
        return $response
    }
    catch {
        Write-Error "Failed to get tokens: $_"
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $reader.BaseStream.Position = 0
            $responseBody = $reader.ReadToEnd()
            Write-Error "Response: $responseBody"
        }
        return $null
    }
}

function Show-TokenInfo {
    param($TokenResponse)
    
    if ($null -eq $TokenResponse) {
        Write-Host "`n[!] Failed to retrieve tokens" -ForegroundColor Red
        return
    }
    
    Write-Host "`n=== Token Information ===" -ForegroundColor Green
    
    if ($TokenResponse.access_token) {
        Write-Host "`n[+] Access Token:" -ForegroundColor Cyan
        Write-Host $TokenResponse.access_token
        Write-Host "`n    Token Type: $($TokenResponse.token_type)"
        Write-Host "    Expires In: $($TokenResponse.expires_in) seconds"
    }
    
    if ($TokenResponse.refresh_token) {
        Write-Host "`n[+] Refresh Token:" -ForegroundColor Cyan
        Write-Host $TokenResponse.refresh_token
    }
    
    if ($TokenResponse.id_token) {
        Write-Host "`n[+] ID Token:" -ForegroundColor Cyan
        Write-Host $TokenResponse.id_token
    }
    
    if ($TokenResponse.scope) {
        Write-Host "`n[+] Granted Scopes:" -ForegroundColor Cyan
        Write-Host "    $($TokenResponse.scope)"
    }
    
    # Save to file
    $outputFile = "azure_tokens_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $TokenResponse | ConvertTo-Json -Depth 10 | Out-File $outputFile
    Write-Host "`n[*] Tokens saved to: $outputFile" -ForegroundColor Yellow
}

# Build the full scope
$fullScope = if ($Resource -eq "https://graph.microsoft.com") {
    "$Scope $Resource/.default"
} else {
    "$Scope $Resource/.default"
}

# Mode 1: Just print the auth URL
if ($PrintUrl) {
    $authUrl = Build-AuthUrl -ClientId $ClientId -Scope $fullScope -RedirectUri $RedirectUri
    Write-Output $authUrl
    exit 0
}

# Mode 2: Print the complete PowerShell command for token exchange
if ($PrintCommand) {
    Write-Host "=== Copy this command to run on another system ===" -ForegroundColor Green
    Write-Host ""
    $cmd = Get-TokenExchangeCommand -ClientId $ClientId -RedirectUri $RedirectUri -Scope $fullScope -Tenant $Tenant -UserAgent $UserAgent
    Write-Host $cmd -ForegroundColor Yellow
    Write-Host ""
    Write-Host "After authenticating, replace 'PASTE_AUTH_CODE_HERE' with the actual auth code from the redirect URL" -ForegroundColor Cyan
    exit 0
}

# Mode 3: Generate the token exchange command with auth code
if ($GenerateTokenCommand) {
    if ([string]::IsNullOrEmpty($AuthCode)) {
        Write-Host "[!] Error: -AuthCode parameter required when using -GenerateTokenCommand" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "=== PowerShell One-Liner for Token Exchange ===" -ForegroundColor Green
    Write-Host ""
    $cmd = Get-TokenExchangeCommand -ClientId $ClientId -RedirectUri $RedirectUri -Scope $fullScope -Tenant $Tenant -AuthCode $AuthCode -UserAgent $UserAgent
    Write-Host $cmd -ForegroundColor Yellow
    exit 0
}

# Mode 4: Direct token exchange if auth code provided
if (-not [string]::IsNullOrEmpty($AuthCode)) {
    Write-Host "=== Azure OAuth2 Authorization Code Flow ===" -ForegroundColor Green
    Write-Host "[*] Exchanging authorization code for tokens..." -ForegroundColor Yellow
    
    $tokens = Request-TokenFromAuthCode -ClientId $ClientId -RedirectUri $RedirectUri -Scope $fullScope -AuthCode $AuthCode -UserAgent $UserAgent
    Show-TokenInfo -TokenResponse $tokens
    exit 0
}

# Mode 5: Interactive mode (default)
Write-Host "=== Azure OAuth2 Authorization Code Flow ===" -ForegroundColor Green
Write-Host "`nConfiguration:" -ForegroundColor Cyan
Write-Host "  Client ID: $ClientId"
Write-Host "  Resource: $Resource"
Write-Host "  Redirect URI: $RedirectUri"
Write-Host "  Tenant: $Tenant"
Write-Host "  User-Agent: $UserAgent"

$authUrl = Build-AuthUrl -ClientId $ClientId -Scope $fullScope -RedirectUri $RedirectUri

Write-Host "`n[1] Visit this URL in a browser and authenticate:" -ForegroundColor Yellow
Write-Host $authUrl -ForegroundColor White

Write-Host "`n    === OR copy this URL for another system ===" -ForegroundColor Magenta
Write-Host "    " -NoNewline
Write-Host $authUrl -ForegroundColor DarkGray

Write-Host "`n[2] After authentication:" -ForegroundColor Yellow
if ($RedirectUri -eq "urn:ietf:wg:oauth:2.0:oob") {
    Write-Host "    The browser will display your authorization code on the page." -ForegroundColor Yellow
    Write-Host "    Copy just the code (it looks like: 0.AXXX...)" -ForegroundColor Yellow
    Write-Host "`n[3] Paste the authorization code below and press ENTER:" -ForegroundColor Yellow
} elseif ($RedirectUri -like "http://localhost*") {
    Write-Host "    The browser will redirect to localhost (may show an error - that's OK!)." -ForegroundColor Yellow
    Write-Host "    Copy the entire URL from the address bar." -ForegroundColor Yellow
    Write-Host "    It should look like: http://localhost?code=0.AXXX..." -ForegroundColor Yellow
    Write-Host "`n[3] Paste the URL below and press ENTER:" -ForegroundColor Yellow
} else {
    Write-Host "    The browser will redirect to a blank page." -ForegroundColor Yellow
    Write-Host "    Copy the entire URL from the address bar." -ForegroundColor Yellow
    Write-Host "    It should look like: $RedirectUri`?code=0.AXXX..." -ForegroundColor Yellow
    Write-Host "`n[3] Paste the URL below and press ENTER:" -ForegroundColor Yellow
}
Write-Host ">" -NoNewline -ForegroundColor Green

$redirectUrlPostAuth = Read-Host

# Extract authorization code - handle both direct code and URL with code parameter
$authCode = $null

# Check if input looks like a direct code (starts with 0. and no http/urn)
if ($redirectUrlPostAuth -match '^0\.' -and $redirectUrlPostAuth -notmatch '^http' -and $redirectUrlPostAuth -notmatch '^urn') {
    # Direct code input (OOB style)
    $authCode = $redirectUrlPostAuth.Trim()
    Write-Host "`n[*] Direct authorization code detected" -ForegroundColor Green
}
# Otherwise try to extract from URL
elseif ($redirectUrlPostAuth -match "code=([^&]+)") {
    $authCode = $matches[1]
    Write-Host "`n[*] Authorization code extracted from URL" -ForegroundColor Green
}

if (-not [string]::IsNullOrEmpty($authCode)) {
    Write-Host "[*] Code: $authCode" -ForegroundColor Green
    
    # Show the PowerShell one-liner option
    Write-Host "`n    === OR use this PowerShell one-liner on another system ===" -ForegroundColor Magenta
    $oneLiner = Get-TokenExchangeCommand -ClientId $ClientId -RedirectUri $RedirectUri -Scope $fullScope -Tenant $Tenant -AuthCode $authCode -UserAgent $UserAgent
    Write-Host "    " -NoNewline
    Write-Host $oneLiner -ForegroundColor DarkGray
    
    Write-Host "`n[*] Exchanging code for tokens on this system..." -ForegroundColor Yellow
    $tokens = Request-TokenFromAuthCode -ClientId $ClientId -RedirectUri $RedirectUri -Scope $fullScope -AuthCode $authCode -UserAgent $UserAgent
    Show-TokenInfo -TokenResponse $tokens
}
else {
    Write-Host "`n[!] Error: Could not find authorization code" -ForegroundColor Red
    Write-Host "[!] Please paste either:" -ForegroundColor Red
    Write-Host "    - The authorization code directly (for OOB flow): 0.AXXX..." -ForegroundColor Red
    Write-Host "    - The complete redirect URL with code parameter" -ForegroundColor Red
    exit 1
}

Write-Host "`n[*] Done!" -ForegroundColor Green
