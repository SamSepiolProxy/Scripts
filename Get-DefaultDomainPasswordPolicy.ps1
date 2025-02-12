# Function to get the default domain password policy including reversible encryption and observation window
function Get-DefaultPasswordPolicy {
    try {
        # Get the domain context
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $defaultNamingContext = $rootDSE.defaultNamingContext
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]("LDAP://" + $defaultNamingContext)
        $searcher.Filter = "(objectClass=domain)"

        # Add properties to retrieve (including lockoutObservationWindow)
        $properties = @(
            "minPwdLength", 
            "maxPwdAge", 
            "pwdHistoryLength", 
            "pwdProperties", 
            "lockoutDuration", 
            "lockoutThreshold", 
            "ms-DS-Password-Reversible-Encryption-Enabled",
            "lockoutObservationWindow"
        )
        foreach ($prop in $properties) {
            $searcher.PropertiesToLoad.Add($prop) | Out-Null
        }

        # Execute search
        $result = $searcher.FindOne()

        if ($result -ne $null) {
            $domain = $result.Properties

            # Convert maxPwdAge to days (stored in 100-nanosecond intervals)
            $maxPwdAge = if ($domain["maxPwdAge"].Count -gt 0) { [timespan]::FromTicks([int64]$domain["maxPwdAge"][0]) } else { $null }
            $maxPwdAgeDays = if ($maxPwdAge -ne $null) { -$maxPwdAge.Days } else { "Not Set" }

            # Convert lockoutDuration to minutes
            $lockoutDuration = if ($domain["lockoutDuration"].Count -gt 0) { [timespan]::FromTicks([int64]$domain["lockoutDuration"][0]) } else { $null }
            $lockoutDurationMinutes = if ($lockoutDuration -ne $null) { -$lockoutDuration.TotalMinutes } else { "Not Set" }

            # Convert lockoutObservationWindow to minutes
            $lockoutObservationWindow = if ($domain["lockoutObservationWindow"].Count -gt 0) { [timespan]::FromTicks([int64]$domain["lockoutObservationWindow"][0]) } else { $null }
            $lockoutObservationWindowMinutes = if ($lockoutObservationWindow -ne $null) { -$lockoutObservationWindow.TotalMinutes } else { "Not Set" }

            # Get password properties
            $pwdProperties = if ($domain["pwdProperties"].Count -gt 0) { $domain["pwdProperties"][0] -as [int] } else { 0 }

            # Password Complexity (Bit 0 - Value 1)
            $passwordComplexityEnabled = if (($pwdProperties -band 1) -eq 1) { "Enabled" } else { "Disabled" }

            # Store Passwords Using Reversible Encryption
            $reversibleEncryption = if ($domain["ms-DS-Password-Reversible-Encryption-Enabled"].Count -gt 0) {
                if ($domain["ms-DS-Password-Reversible-Encryption-Enabled"][0] -eq "TRUE") { "Enabled" } else { "Disabled" }
            } else {
                "Not Set"
            }

            # Display results
            Write-Host "Default Domain Password Policy:"
            Write-Host "----------------------------------"
            Write-Host "Minimum Password Length: " ($domain["minPwdLength"][0] -as [int])
            Write-Host "Maximum Password Age (Days): " $maxPwdAgeDays
            Write-Host "Password History Length: " ($domain["pwdHistoryLength"][0] -as [int])
            Write-Host "Password Complexity: " $passwordComplexityEnabled
            Write-Host "Store Passwords Using Reversible Encryption: " $reversibleEncryption
            Write-Host "Account Lockout Duration (Minutes): " $lockoutDurationMinutes
            Write-Host "Account Lockout Observation Window (Minutes): " $lockoutObservationWindowMinutes
            Write-Host "Account Lockout Threshold: " ($domain["lockoutThreshold"][0] -as [int])
        } else {
            Write-Host "Could not retrieve password policy."
        }
    } catch {
        Write-Host "Error: $_"
    }
}

# Call the function
Get-DefaultPasswordPolicy
