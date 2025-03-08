# Function to convert ticks/filetime to readable time
function Convert-LdapFileTimeToRealTime {
    param (
        [long]$fileTime
    )
    # Handle negative values (convert to positive for calculation)
    if ($fileTime -lt 0) {
        $fileTime = -$fileTime
    }
    return [TimeSpan]::FromTicks($fileTime).ToString("hh\:mm\:ss")
}

# Create the DirectorySearcher object
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=msDS-PasswordSettings)"

# Perform the search
$searchResults = $searcher.FindAll()

# Loop through the results and directly access the properties
foreach ($result in $searchResults) {
    $properties = $result.Properties
    
    Write-Output "Fine-Grained Password Policy:"
    Write-Output "Name: $($properties['cn'][0])"
    Write-Output "Precedence: $($properties['msDS-PasswordSettingsPrecedence'][0])"
    Write-Output "Complexity Enabled: $($properties['msDS-PasswordComplexityEnabled'][0])"
    Write-Output "Min Password Length: $($properties['msDS-MinimumPasswordLength'][0])"
    Write-Output "Max Password Age (Days): $([TimeSpan]::FromTicks($properties['msDS-MaximumPasswordAge'][0]).TotalDays)"
    Write-Output "Lockout Threshold: $($properties['msDS-LockoutThreshold'][0])"
    Write-Output "Lockout Observation Window (HH:mm:ss): $(Convert-LdapFileTimeToRealTime -fileTime $properties['msDS-LockoutObservationWindow'][0])"
    Write-Output "Lockout Duration (HH:mm:ss): $(Convert-LdapFileTimeToRealTime -fileTime $properties['msDS-LockoutDuration'][0])"

    # Dump msDS-PSOAppliesTo (multi-valued attribute, list distinguished names of users/groups)
    if ($properties['msDS-PSOAppliesTo']) {
        Write-Output "PSO Applies To:"
        foreach ($applyTo in $properties['msDS-PSOAppliesTo']) {
            Write-Output "  $applyTo"
        }
    } else {
        Write-Output "PSO Applies To: Not Set"
    }
    
    Write-Output "`n"
}
