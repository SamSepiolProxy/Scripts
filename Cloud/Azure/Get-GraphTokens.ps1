
function Get-GraphTokens{
    <#
        .SYNOPSIS
        Get-GraphTokens is the main user authentication module for GraphRunner. Upon authenticating it will store your tokens in the global $tokens variable as well as the tenant ID in $tenantid. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       Get-GraphTokens is the main user authentication module for GraphRunner. Upon authenticating it will store your tokens in the global $tokens variable as well as the tenant ID in $tenantid. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)     
    
    .PARAMETER UserPasswordAuth
        
        Provide a username and password for authentication instead of using a device code auth.
    
    .PARAMETER Client
        
        Provide a Client to authenticate to. Use Custom to provide your own ClientID.

    .PARAMETER ClientID
        
        Provide a ClientID to use with the Custom client option.

    .PARAMETER Resource

        Provide a resource to authenticate to such as https://graph.microsoft.com/

    .PARAMETER Device
        
        Provide a device type to use such as Windows or Android.

    .PARAMETER Browser
        
        Provide a Browser to spoof.
    


    .EXAMPLE
        
        C:\PS> Get-GraphTokens
        Description
        -----------
        This command will initiate a device code auth where you can authenticate the terminal from an already authenticated browser session.
     #>
    [CmdletBinding()]
    param(
    [Parameter(Position = 0,Mandatory=$False)]
    [switch]$ExternalCall,
    [Parameter(Position = 1,Mandatory=$False)]
    [switch]$UserPasswordAuth,
    [Parameter(Position = 2,Mandatory=$False)]
    [ValidateSet("Yammer","Outlook","MSTeams","Graph","AzureCoreManagement","AzureManagement","MSGraph","DODMSGraph","Custom","Substrate")]
    [String[]]$Client = "MSGraph",
    [Parameter(Position = 3,Mandatory=$False)]
    [String]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",    
    [Parameter(Position = 4,Mandatory=$False)]
    [String]$Resource = "https://graph.microsoft.com",
    [Parameter(Position = 5,Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Position = 6,Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}
    if($UserPasswordAuth){
        Write-Host -ForegroundColor Yellow "[*] Initiating the User/Password authentication flow"
        $username = Read-Host -Prompt "Enter username"
        $password = Read-Host -Prompt "Enter password" -AsSecureString

        $passwordText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

        $url = "https://login.microsoft.com/common/oauth2/token"
        $headers = @{
            "Accept" = "application/json"
            "Content-Type" = "application/x-www-form-urlencoded"
            "User-Agent" = $UserAgent
        }
        $body = "grant_type=password&password=$passwordText&client_id=$ClientID&username=$username&resource=$Resource&client_info=1&scope=openid"


        try{
            Write-Host -ForegroundColor Yellow "[*] Trying to authenticate with the provided credentials"
            $tokens = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body

            if ($tokens) {
                $tokenPayload = $tokens.access_token.Split(".")[1].Replace('-', '+').Replace('_', '/')
                while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
                $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
                $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
                $tokobj = $tokenArray | ConvertFrom-Json
                $global:tenantid = $tokobj.tid
                Write-Output "Decoded JWT payload:"
                $tokobj
                Write-Host -ForegroundColor Green '[*] Successful authentication. Access and refresh tokens have been written to the global $tokens variable. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)'
                $baseDate = Get-Date -date "01-01-1970"
                $tokenExpire = $baseDate.AddSeconds($tokobj.exp).ToLocalTime()
                Write-Host -ForegroundColor Yellow "[!] Your access token is set to expire on: $tokenExpire"
            }
        } catch {
            $details = $_.ErrorDetails.Message | ConvertFrom-Json
            Write-Output $details.error
        }
        $global:tokens = $tokens
        if($ExternalCall){
            return $tokens
        }
    
    }
    else{
        If($tokens){
            $newtokens = $null
            while($newtokens -notlike "Yes"){
                Write-Host -ForegroundColor cyan "[*] It looks like you already tokens set in your `$tokens variable. Are you sure you want to authenticate again?"
                $answer = Read-Host 
                $answer = $answer.ToLower()
                if ($answer -eq "yes" -or $answer -eq "y") {
                    Write-Host -ForegroundColor yellow "[*] Initiating device code login..."
                    $global:tokens = ""
                    $newtokens = "Yes"
                } elseif ($answer -eq "no" -or $answer -eq "n") {
                    Write-Host -ForegroundColor Yellow "[*] Quitting..."
                    return
                } else {
                    Write-Host -ForegroundColor red "Invalid input. Please enter Yes or No."
                }
            }
        }

        $body = @{
            "client_id" =     $ClientID
            "resource" =      $Resource
        }
        $Headers=@{}
        $Headers["User-Agent"] = $UserAgent
        $authResponse = Invoke-RestMethod `
            -UseBasicParsing `
            -Method Post `
            -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" `
            -Headers $Headers `
            -Body $body
        Write-Host -ForegroundColor yellow $authResponse.Message

        $continue = "authorization_pending"
        while ($continue) {
            $body = @{
                "client_id"   = $ClientID
                "grant_type"  = "urn:ietf:params:oauth:grant-type:device_code"
                "code"        = $authResponse.device_code
                "scope"       = "openid"
            }

            try {
                $tokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" -Headers $Headers -Body $body

                if ($tokens) {
                    $tokenPayload = $tokens.access_token.Split(".")[1].Replace('-', '+').Replace('_', '/')
                    while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
                    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
                    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
                    $tokobj = $tokenArray | ConvertFrom-Json
                    $global:tenantid = $tokobj.tid
                    Write-Output "Decoded JWT payload:"
                    $tokobj
                    $baseDate = Get-Date -date "01-01-1970"
                    $tokenExpire = $baseDate.AddSeconds($tokobj.exp).ToLocalTime()
                    Write-Host -ForegroundColor Green '[*] Successful authentication. Access and refresh tokens have been written to the global $tokens variable. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)'
                    Write-Host -ForegroundColor Yellow "[!] Your access token is set to expire on: $tokenExpire"
                    $continue = $null
                }
            } catch {
                $details = $_.ErrorDetails.Message | ConvertFrom-Json
                $continue = $details.error -eq "authorization_pending"
                Write-Output $details.error
            }

            if ($continue) {
                Start-Sleep -Seconds 3
            }
            else{
                $global:tokens = $tokens
                if($ExternalCall){
                    return $tokens
                }
            }
        }
    }
}
function Invoke-ForgeUserAgent
{
      <#
    .DESCRIPTION
        Forge the User-Agent when sending requests to the Microsoft API's. Useful for bypassing device specific Conditional Access Policies. Defaults to Windows Edge.
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser
    )
    Process
    {
        if ($Device -eq 'Mac')
        {
            if ($Browser -eq 'Chrome')
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            }
            elseif ($Browser -eq 'Firefox')
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0'
            }
            elseif ($Browser -eq 'Edge')
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/604.1 Edg/91.0.100.0'
            }
            elseif ($Browser -eq 'Safari')
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
            }
            else 
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
            }
        }
        elseif ($Device -eq 'Windows')
        {
            if ($Browser -eq 'IE')
            {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
            }
            elseif ($Browser -eq 'Chrome')
            {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            }
            elseif ($Browser -eq 'Firefox')
            {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:70.0) Gecko/20100101 Firefox/70.0'
            }
            elseif ($Browser -eq 'Edge')
            {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
            }
            else 
            {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
            }
        }
        elseif ($Device -eq 'AndroidMobile')
        {
            if ($Browser -eq 'Android')
            {
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            }
            elseif ($Browser -eq 'Chrome')
            {
                $UserAgent = 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36'
            }
            elseif ($Browser -eq 'Firefox')
            {
                $UserAgent = 'Mozilla/5.0 (Android 4.4; Mobile; rv:70.0) Gecko/70.0 Firefox/70.0'
            }
            elseif ($Browser -eq 'Edge')
            {
                $UserAgent = 'Mozilla/5.0 (Linux; Android 8.1.0; Pixel Build/OPM4.171019.021.D1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.109 Mobile Safari/537.36 EdgA/42.0.0.2057'
            }
            else 
            {
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            }
        }
        elseif ($Device -eq 'iPhone')
        {
            if ($Browser -eq 'Chrome')
            {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.114 Mobile/15E148 Safari/604.1'
            }
            elseif ($Browser -eq 'Firefox')
            {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) FxiOS/1.0 Mobile/12F69 Safari/600.1.4'
            }
            elseif ($Browser -eq 'Edge')
            {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 EdgiOS/44.5.0.10 Mobile/15E148 Safari/604.1'
            }
            elseif ($Browser -eq 'Safari')
            {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1'
            }
            else 
            {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1'
            }
        }
        else 
        {
            #[ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
            if ($Browser -eq 'Android')
            {
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            }
            elseif($Browser -eq 'IE')
            { 
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
            }
            elseif($Browser -eq 'Chrome')
            { 
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            }
            elseif($Browser -eq 'Firefox')
            { 
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:70.0) Gecko/20100101 Firefox/70.0'
            }
            elseif($Browser -eq 'Safari')
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15' 
            }
            else
            {
                $UserAgent = $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'
            } 
        }
        return $UserAgent
   }   
}