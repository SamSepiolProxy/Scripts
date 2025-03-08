function Get-GraphTokens {
    [CmdletBinding()]
    param(
        # Specify the client ID to be used for authentication. A default is provided.
        [Parameter(Mandatory = $false)]
        [string]$ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e",

        # Specify the scope for authentication. This will be URL encoded for the initial request.
        [Parameter(Mandatory = $false)]
        [string]$Scope = "RoleEligibilitySchedule.Read.Directory RoleAssignmentSchedule.Read.Directory RoleManagement.Read.Directory offline_access profile openid"
    )
    <#
        .SYNOPSIS
        Get-GraphTokens is a user authentication script.
        Upon authenticating it will store your tokens in the global $tokens variable and the tenant ID in $tenantid.

        .DESCRIPTION
        This function initiates a device code flow that lets you authenticate via a browser session.
        It then polls the token endpoint until authentication is complete and decodes the JWT to extract the tenant ID.

        .EXAMPLE
            C:\PS> Get-GraphTokens -ClientId "your-client-id" -Scope "your scope here"
    #>

    # If tokens are already set, prompt the user for reauthentication confirmation.
    if ($tokens) {
        $newtokens = $null
        while ($newtokens -notlike "Yes") {
            Write-Host -ForegroundColor cyan "[*] It looks like you already have tokens set in your `$tokens variable. Are you sure you want to authenticate again?"
            $answer = Read-Host
            $answer = $answer.ToLower()
            if ($answer -eq "yes" -or $answer -eq "y") {
                Write-Host -ForegroundColor yellow "[*] Initiating device code login..."
                # Clear the existing tokens to proceed with a fresh authentication.
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

    # Set up the HTTP headers for the authentication requests.
    $headers = @{
        "Host"                          = "login.microsoftonline.com"
        "X-Client-Sku"                  = "MSAL.Desktop"
        "X-Client-Ver"                  = "4.61.3.0"
        "X-Client-Os"                   = "Windows 10 Pro"
        "Client-Request-Id"             = "b86490af-0d7c-4510-ac4f-eb0b6a9c2ff0"
        "Return-Client-Request-Id"      = "true"
        "X-App-Name"                    = "UnknownClient"
        "X-App-Ver"                     = "0.0.0.0"
        "Content-Type"                  = "application/x-www-form-urlencoded"
        "X-Ms-Client-Request-Id"        = "6121e2fb-8d02-4559-954a-7f7b24ddb757"
        "X-Ms-Return-Client-Request-Id" = "true"
        "User-Agent"                    = "azsdk-net-Identity/1.11.4 (.NET Framework 4.8.9290.0; Microsoft Windows 10.0.19045 )"
    }

    # URL encode the scope for the first POST request.
    $encodedScope = [System.Uri]::EscapeDataString($Scope)
    # Prepare the request body for obtaining the device code.
    $body = "client_id=$ClientId&scope=$encodedScope"

    # Initiate the device code flow by calling the device code endpoint.
    $authResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode" -Method Post -Body $body -Headers $headers

    # Display the instructions provided by the authentication response.
    Write-Host -ForegroundColor yellow $authResponse.Message

    # Begin polling the token endpoint until authorization is complete.
    $continue = "authorization_pending"
    while ($continue) {
        # Prepare the body for the token request.
        # Note: The scope here is unencoded.
        $body = @{
            "client_id"  = $ClientId
            "grant_type" = "device_code"
            "client_info"= "1"
            "code"       = $authResponse.device_code
            "scope"      = $Scope
        }

        try {
            # Attempt to retrieve tokens using the device code.
            $tokens = Invoke-RestMethod -Uri "https://login.microsoftonline.com/organizations/oauth2/v2.0/token" -Method Post -Body $body -Headers $headers

            if ($tokens) {
                # Decode the JWT access token payload (the second part of the token).
                $tokenPayload = $tokens.access_token.Split(".")[1].Replace('-', '+').Replace('_', '/')
                # Add proper Base64 padding.
                while ($tokenPayload.Length % 4) { 
                    Write-Verbose "Invalid length for a Base-64 char array or string, adding ="
                    $tokenPayload += "=" 
                }
                $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
                $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
                $tokobj = $tokenArray | ConvertFrom-Json

                # Store the tenant ID globally for further use.
                $global:tenantid = $tokobj.tid

                Write-Output "Decoded JWT payload:"
                $tokobj

                # Calculate the token expiration date/time.
                $baseDate = Get-Date -Date "01-01-1970"
                $tokenExpire = $baseDate.AddSeconds($tokobj.exp).ToLocalTime()

                # Inform the user of successful authentication.
                Write-Host -ForegroundColor Green '[*] Successful authentication. Access and refresh tokens have been written to the global $tokens variable. To use them with other scripts use the Tokens flag (Example. Get-CAPolicies.ps1 -Tokens $tokens.access_token)'
                Write-Host -ForegroundColor Yellow "[!] Your access token is set to expire on: $tokenExpire"
                $continue = $null
            }
        } catch {
            # If an error occurs (likely due to the token not being ready), parse the error details.
            $details = $_.ErrorDetails.Message | ConvertFrom-Json
            # Continue polling if the error indicates that authorization is still pending.
            $continue = $details.error -eq "authorization_pending"
            Write-Output $details.error
        }

        # Wait a few seconds before retrying if authorization is still pending.
        if ($continue) {
            Start-Sleep -Seconds 3
        }
        else {
            # Store the retrieved tokens in the global variable.
            $global:tokens = $tokens
            # Return tokens if this function is called externally.
            if ($ExternalCall) {
                return $tokens
            }
        }
    }
}
