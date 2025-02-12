param (
    [string]$OutputFile = "CombinedPasswordPolicy.txt"
)

# -------------------------------
# Function: Get-LocalPasswordPolicy
# -------------------------------
function Get-LocalPasswordPolicy {
    $output = @()
    $output += "==============================="
    $output += "Local Password Policy Settings:"
    $output += "==============================="

    # Export security policy settings to a temporary file
    $TempFile = "$env:TEMP\secpol.cfg"
    secedit /export /areas SECURITYPOLICY /cfg $TempFile > $null

    if (Test-Path $TempFile) {
        $PolicyContent = Get-Content $TempFile | Where-Object {
            $_ -match "^(MinimumPasswordAge|MaximumPasswordAge|MinimumPasswordLength|PasswordComplexity|PasswordHistorySize|LockoutBadCount|ResetLockoutCount|LockoutDuration|AllowAdministratorLockout|ClearTextPassword)"
        }
        $output += $PolicyContent
        Remove-Item $TempFile -Force
        $output += "Local password policy settings displayed above."
    }
    else {
        $output += "Failed to export security policy settings."
    }
    return $output
}

# -------------------------------
# Function: Get-DomainPasswordPolicy
# -------------------------------
function Get-DomainPasswordPolicy {
    $output = @()
    try {
        # Retrieve the default naming context
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $defaultNamingContext = $rootDSE.defaultNamingContext
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]("LDAP://" + $defaultNamingContext)
        $searcher.Filter = "(objectClass=domain)"

        # Specify properties to retrieve
        $properties = @("minPwdLength", "maxPwdAge", "pwdHistoryLength", "pwdProperties", 
                        "lockoutDuration", "lockoutThreshold", "ms-DS-Password-Reversible-Encryption-Enabled")
        foreach ($prop in $properties) {
            $searcher.PropertiesToLoad.Add($prop) | Out-Null
        }

        $result = $searcher.FindOne()
        if ($result -ne $null) {
            $domain = $result.Properties

            # Convert maxPwdAge to days (stored as negative ticks)
            $maxPwdAge = if ($domain["maxPwdAge"].Count -gt 0) { [timespan]::FromTicks([int64]$domain["maxPwdAge"][0]) } else { $null }
            $maxPwdAgeDays = if ($maxPwdAge -ne $null) { -$maxPwdAge.Days } else { "Not Set" }

            # Convert lockoutDuration to minutes
            $lockoutDuration = if ($domain["lockoutDuration"].Count -gt 0) { [timespan]::FromTicks([int64]$domain["lockoutDuration"][0]) } else { $null }
            $lockoutDurationMinutes = if ($lockoutDuration -ne $null) { -$lockoutDuration.TotalMinutes } else { "Not Set" }
            
            # Determine password complexity from pwdProperties (bit 0)
            $pwdProperties = if ($domain["pwdProperties"].Count -gt 0) { $domain["pwdProperties"][0] -as [int] } else { 0 }
            $passwordComplexityEnabled = if (($pwdProperties -band 1) -eq 1) { "Enabled" } else { "Disabled" }
            
            # Check for reversible encryption
            $reversibleEncryption = if ($domain["ms-DS-Password-Reversible-Encryption-Enabled"].Count -gt 0) {
                if ($domain["ms-DS-Password-Reversible-Encryption-Enabled"][0] -eq "TRUE") { "Enabled" } else { "Disabled" }
            } else {
                "Not Set"
            }
            
            $output += "----------------------------------"
            $output += "Default Domain Password Policy:"
            $output += "----------------------------------"
            $output += ("Minimum Password Length: " + ($domain["minPwdLength"][0] -as [int]))
            $output += ("Maximum Password Age (Days): " + $maxPwdAgeDays)
            $output += ("Password History Length: " + ($domain["pwdHistoryLength"][0] -as [int]))
            $output += ("Password Complexity: " + $passwordComplexityEnabled)
            $output += ("Store Passwords Using Reversible Encryption: " + $reversibleEncryption)
            $output += ("Account Lockout Duration (Minutes): " + $lockoutDurationMinutes)
            $output += ("Account Lockout Threshold: " + ($domain["lockoutThreshold"][0] -as [int]))
        }
        else {
            $output += "Could not retrieve default domain password policy."
        }
    }
    catch {
        $output += "Error retrieving default domain password policy: $_"
    }
    return $output
}

# -------------------------------
# Helper Function: Convert-LdapFileTimeToRealTime
# -------------------------------
function Convert-LdapFileTimeToRealTime {
    param (
        [long]$fileTime
    )
    if ($fileTime -lt 0) {
        $fileTime = -$fileTime
    }
    return [TimeSpan]::FromTicks($fileTime).ToString("hh\:mm\:ss")
}

# -------------------------------
# Function: Get-FineGrainedPasswordPolicy
# -------------------------------
function Get-FineGrainedPasswordPolicy {
    $output = @()
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter = "(objectClass=msDS-PasswordSettings)"
    $searchResults = $searcher.FindAll()

    if ($searchResults.Count -gt 0) {
        foreach ($result in $searchResults) {
            $properties = $result.Properties
            $output += "--------------------------------"
            $output += "Fine-Grained Password Policy:"
            $output += "--------------------------------"
            $output += ("Name: " + $properties['cn'][0])
            $output += ("Precedence: " + $properties['msDS-PasswordSettingsPrecedence'][0])
            $output += ("Complexity Enabled: " + $properties['msDS-PasswordComplexityEnabled'][0])
            $output += ("Min Password Length: " + $properties['msDS-MinimumPasswordLength'][0])
            
            # Convert Maximum Password Age from ticks to days
            $maxPwdAgeTicks = $properties['msDS-MaximumPasswordAge'][0]
            $maxPwdAgeDays = [TimeSpan]::FromTicks($maxPwdAgeTicks).TotalDays
            $output += ("Max Password Age (Days): " + $maxPwdAgeDays)
            
            $output += ("Lockout Threshold: " + $properties['msDS-LockoutThreshold'][0])
            $output += ("Lockout Observation Window (HH:mm:ss): " + (Convert-LdapFileTimeToRealTime -fileTime $properties['msDS-LockoutObservationWindow'][0]))
            $output += ("Lockout Duration (HH:mm:ss): " + (Convert-LdapFileTimeToRealTime -fileTime $properties['msDS-LockoutDuration'][0]))
            
            if ($properties['msDS-PSOAppliesTo']) {
                $output += "PSO Applies To:"
                foreach ($applyTo in $properties['msDS-PSOAppliesTo']) {
                    $output += ("  " + $applyTo)
                }
            }
            else {
                $output += "PSO Applies To: Not Set"
            }
            # Add a blank line between policies
            $output += ""
        }
    }
    else {
        $output += "No Fine-Grained Password Policies found."
    }
    return $output
}

# -------------------------------
# Main Script: Call the functions and combine their output
# -------------------------------
$combinedOutput = @()

$combinedOutput += Get-LocalPasswordPolicy
$combinedOutput += ""  # blank line separator
$combinedOutput += Get-DomainPasswordPolicy
$combinedOutput += ""  # blank line separator
$combinedOutput += Get-FineGrainedPasswordPolicy

# Write the combined output to the specified file and also display it on the console.
$combinedOutput | Out-File -FilePath $OutputFile -Encoding utf8
$combinedOutput | Write-Output