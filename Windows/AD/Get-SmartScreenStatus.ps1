# Function to check SmartScreen-related registry entries (HKLM + HKCU) and write results to a text file
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
            "Path" = "HKCU:\Software\Microsoft\Edge\SmartScreenEnabled"
            "Name" = "(default)"  # unnamed default value
        },
        @{
            "Registry Entry" = "HKCU:Software\Microsoft\Edge\SmartScreenPUAEnabled"
            "Path" = "HKCU:\Software\Microsoft\Edge\SmartScreenPUAEnabled"
            "Name" = ""  # unnamed default value
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

    foreach ($entry in $entries) {
        try {
            # Retrieve registry value (handles unnamed default value correctly)
            if ($entry.Name -eq "") {
                $key = Get-Item -Path $entry.Path -ErrorAction Stop
                $value = $key.GetValue('')
            } else {
                $value = Get-ItemPropertyValue -Path $entry.Path -Name $entry.Name -ErrorAction Stop
            }

            # Interpret meaning
            $interpretedValue = switch -Regex ($entry."Registry Entry") {
                "SmartScreenPUAEnabled" {
                    switch ($value) {
                        1 { "SmartScreen PUA protection is enabled" }
                        0 { "SmartScreen PUA protection is disabled" }
                        default { "Value exists but unknown" }
                    }
                }
                "SmartScreenEnabled" {
                    switch ($value) {
                        1 { "SmartScreen is enabled" }
                        0 { "SmartScreen is disabled" }
                        default { "Value exists but unknown" }
                    }
                }
                "EnableSmartScreen" {
                    switch ($value) {
                        1 { "SmartScreen is enabled" }
                        0 { "SmartScreen is disabled" }
                        default { "Value exists but unknown" }
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
                        default { "Value exists but unknown" }
                    }
                }
                "EnabledV9" {
                    switch ($value) {
                        1 { "Phishing Filter is enabled" }
                        0 { "Phishing Filter is disabled" }
                        default { "Value exists but unknown" }
                    }
                }
                "PreventOverride" {
                    switch ($value) {
                        1 { "Override is prevented" }
                        0 { "Override is allowed" }
                        default { "Value exists but unknown" }
                    }
                }
                "PreventOverrideAppRepUnknown" {
                    switch ($value) {
                        1 { "Unknown app reputation overrides are prevented" }
                        0 { "Unknown app reputation overrides are allowed" }
                        default { "Value exists but unknown" }
                    }
                }
                default { "Unknown setting" }
            }

        } catch {
            $value = $null
            $interpretedValue = "Registry entry or value does not exist"
        }

        $results += [PSCustomObject]@{
            "Registry Entry" = $entry."Registry Entry"
            "Raw Value"      = if ($null -ne $value) { $value } else { "N/A" }
            "Interpretation" = $interpretedValue
        }
    }

    # Output file in current directory
    $outputPath = Join-Path -Path (Get-Location) -ChildPath "SmartScreenStatus.txt"

    # Write formatted table to text file
    $results | Format-Table -AutoSize | Out-String | Set-Content -Path $outputPath -Encoding UTF8

    Write-Host "`nSmartScreen status written to: $outputPath`n" -ForegroundColor Cyan
    $results | Format-Table -AutoSize
}

# Run it
Get-SmartScreenStatus