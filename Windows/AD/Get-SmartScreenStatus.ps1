# Function to check various SmartScreen-related registry entries and interpret their values
function Get-SmartScreenStatus {
    $results = @()

    # Define registry entries to check (HKLM + HKCU)
    $entries = @(
        # --- HKLM entries ---
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
        },

        # --- HKCU entries ---
        @{
            "Registry Entry" = "HKCU:Software\Microsoft\Edge\SmartScreenEnabled"
            "Path" = "HKCU:\Software\Microsoft\Edge"
            "Name" = "SmartScreenEnabled"
        },
        @{
            "Registry Entry" = "HKCU:Software\Microsoft\Windows\CurrentVersion\AppHost\EnableWebContentEvaluation"
            "Path" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost"
            "Name" = "EnableWebContentEvaluation"
        },
        @{
            "Registry Entry" = "HKCU:Software\Microsoft\Windows\CurrentVersion\AppHost\SmartScreenEnabled"
            "Path" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost"
            "Name" = "SmartScreenEnabled"
        },
        @{
            "Registry Entry" = "HKCU:Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\EnabledV9"
            "Path" = "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
            "Name" = "EnabledV9"
        },
        @{
            "Registry Entry" = "HKCU:Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverride"
            "Path" = "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
            "Name" = "PreventOverride"
        },
        @{
            "Registry Entry" = "HKCU:Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverrideAppRepUnknown"
            "Path" = "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
            "Name" = "PreventOverrideAppRepUnknown"
        }
    )

    # Query each registry entry and interpret the value
    foreach ($entry in $entries) {
        try {
            $value = Get-ItemPropertyValue -Path $entry.Path -Name $entry.Name -ErrorAction Stop
            
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
                "EnableWebContentEvaluation" {
                    switch ($value) {
                        1 { "SmartScreen web content evaluation is enabled" }
                        0 { "SmartScreen web content evaluation is disabled" }
                        default { "Not configured" }
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
            $interpretedValue = "Registry entry or value does not exist"
        }

        $results += [PSCustomObject]@{
            "Registry Entry" = $entry."Registry Entry"
            "Value"          = $interpretedValue
        }
    }

    # Output file path in current directory
    $outputPath = Join-Path -Path (Get-Location) -ChildPath "SmartScreenStatus.txt"

    # Write formatted output to text file
    $results | Format-Table -AutoSize | Out-String | Set-Content -Path $outputPath -Encoding UTF8

    # Display on screen
    Write-Host "SmartScreen status written to: $outputPath`n" -ForegroundColor Cyan
    $results | Format-Table -AutoSize
}

# Call the function
Get-SmartScreenStatus
