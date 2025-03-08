# Function to check various SmartScreen-related registry entries and interpret their values
function Get-SmartScreenStatus {
    $results = @()

    # Define registry entries to check
    $entries = @(
        @{
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\Edge\SmartScreenEnabled"
            "Path" = "HKLM:\Software\Policies\Microsoft\Edge"
            "Name" = "SmartScreenEnabled"
        },
        @{
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\Windows\System\EnableSmartScreen"
            "Path" = "HKLM:\Software\Policies\Microsoft\Windows\System"
            "Name" = "EnableSmartScreen"
        },
        @{
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\Windows\System\ShellSmartScreenLevel"
            "Path" = "HKLM:\Software\Policies\Microsoft\Windows\System"
            "Name" = "ShellSmartScreenLevel"
        },
        @{
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\EnabledV9"
            "Path" = "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
            "Name" = "EnabledV9"
        },
        @{
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverride"
            "Path" = "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
            "Name" = "PreventOverride"
        },
        @{
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverrideAppRepUnknown"
            "Path" = "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
            "Name" = "PreventOverrideAppRepUnknown"
        }
    )

    # Query each registry entry and interpret the value
    foreach ($entry in $entries) {
        try {
            # Attempt to get the registry value
            $value = Get-ItemPropertyValue -Path $entry.Path -Name $entry.Name -ErrorAction Stop
            
            # Interpret the value
            $interpretedValue = switch ($entry.Name) {
                "SmartScreenEnabled" {
                    switch ($value) {
                        1 { "SmartScreen is enabled" }
                        0 { "SmartScreen is disabled" }
                        default { "Not configured" }
                    }
                }
                "EnableSmartScreen" {
                    switch ($value) {
                        1 { "SmartScreen is enabled" }
                        0 { "SmartScreen is disabled" }
                        default { "Not configured" }
                    }
                }
                "ShellSmartScreenLevel" {
                    switch ($value) {
                        "RequireAdmin" { "SmartScreen requires admin approval" }
                        "Warn" { "SmartScreen warns the user" }
                        "Off" { "SmartScreen is turned off" }
                        default { "Not configured or unknown level" }
                    }
                }
                "EnabledV9" {
                    switch ($value) {
                        1 { "Phishing Filter is enabled" }
                        0 { "Phishing Filter is disabled" }
                        default { "Not configured" }
                    }
                }
                "PreventOverride" {
                    switch ($value) {
                        1 { "Override is prevented" }
                        0 { "Override is allowed" }
                        default { "Not configured" }
                    }
                }
                "PreventOverrideAppRepUnknown" {
                    switch ($value) {
                        1 { "Unknown app reputation overrides are prevented" }
                        0 { "Unknown app reputation overrides are allowed" }
                        default { "Not configured" }
                    }
                }
                default { "Unknown setting" }
            }
        } catch {
            # Handle missing registry keys or values
            $interpretedValue = "Registry entry or value does not exist"
        }

        $results += [PSCustomObject]@{
            "Registry Entry" = $entry."Registry Entry"
            "Value"          = $interpretedValue
        }
    }

    # Return the results as a formatted table
    $results | Format-Table -AutoSize
}

# Call the function
Get-SmartScreenStatus
