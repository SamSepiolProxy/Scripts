# Enhanced SmartScreen Registry Status Checker
# Checks all known SmartScreen-related registry entries across HKLM and HKCU

function Get-SmartScreenStatus {
    param(
        [switch]$ExportToCSV,
        [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath "SmartScreenStatus.txt")
    )

    $results = @()

    # Define all SmartScreen registry entries organized by category
    $entries = @(
        # ===== WINDOWS SMARTSCREEN (SYSTEM-WIDE) =====
        @{
            "Category" = "Windows SmartScreen (System)"
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\Windows\System\EnableSmartScreen"
            "Path" = "HKLM:\Software\Policies\Microsoft\Windows\System"
            "Name" = "EnableSmartScreen"
            "Description" = "Master SmartScreen enable/disable switch"
        },
        @{
            "Category" = "Windows SmartScreen (System)"
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\Windows\System\ShellSmartScreenLevel"
            "Path" = "HKLM:\Software\Policies\Microsoft\Windows\System"
            "Name" = "ShellSmartScreenLevel"
            "Description" = "File Explorer SmartScreen enforcement level for downloaded files"
        },
        @{
            "Category" = "Windows SmartScreen (System)"
            "Registry Entry" = "HKLM:Software\Microsoft\Windows\CurrentVersion\Explorer\SmartScreenEnabled"
            "Path" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer"
            "Name" = "SmartScreenEnabled"
            "Description" = "Explorer SmartScreen status"
        },

        # ===== WINDOWS SMARTSCREEN (USER) =====
        @{
            "Category" = "Windows SmartScreen (User)"
            "Registry Entry" = "HKCU:Software\Microsoft\Windows\CurrentVersion\AppHost\EnableWebContentEvaluation"
            "Path" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost"
            "Name" = "EnableWebContentEvaluation"
            "Description" = "SmartScreen for Windows Store apps"
        },
        @{
            "Category" = "Windows SmartScreen (User)"
            "Registry Entry" = "HKCU:Software\Microsoft\Windows\CurrentVersion\AppHost\PreventOverride"
            "Path" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost"
            "Name" = "PreventOverride"
            "Description" = "Prevent user override of SmartScreen warnings"
        },
        @{
            "Category" = "Windows SmartScreen (User)"
            "Registry Entry" = "HKCU:Software\Microsoft\Windows\CurrentVersion\AppHost\SmartScreenEnabled"
            "Path" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost"
            "Name" = "SmartScreenEnabled"
            "Description" = "User-level SmartScreen for apps"
        },

        # ===== MICROSOFT EDGE (CHROMIUM) - SYSTEM POLICIES =====
        @{
            "Category" = "Edge Chromium (System Policy)"
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\Edge\SmartScreenEnabled"
            "Path" = "HKLM:\Software\Policies\Microsoft\Edge"
            "Name" = "SmartScreenEnabled"
            "Description" = "Edge SmartScreen master switch"
        },
        @{
            "Category" = "Edge Chromium (System Policy)"
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\Edge\SmartScreenPuaEnabled"
            "Path" = "HKLM:\Software\Policies\Microsoft\Edge"
            "Name" = "SmartScreenPuaEnabled"
            "Description" = "Edge potentially unwanted app blocking"
        },
        @{
            "Category" = "Edge Chromium (System Policy)"
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverride"
            "Path" = "HKLM:\Software\Policies\Microsoft\Edge"
            "Name" = "PreventSmartScreenPromptOverride"
            "Description" = "Prevent bypassing SmartScreen warnings for sites"
        },
        @{
            "Category" = "Edge Chromium (System Policy)"
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverrideForFiles"
            "Path" = "HKLM:\Software\Policies\Microsoft\Edge"
            "Name" = "PreventSmartScreenPromptOverrideForFiles"
            "Description" = "Prevent bypassing SmartScreen warnings for downloads"
        },
        @{
            "Category" = "Edge Chromium (System Policy)"
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\Edge\SmartScreenForTrustedDownloadsEnabled"
            "Path" = "HKLM:\Software\Policies\Microsoft\Edge"
            "Name" = "SmartScreenForTrustedDownloadsEnabled"
            "Description" = "Force SmartScreen checks even for trusted sources"
        },
        @{
            "Category" = "Edge Chromium (System Policy)"
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\Edge\SmartScreenDnsRequestsEnabled"
            "Path" = "HKLM:\Software\Policies\Microsoft\Edge"
            "Name" = "SmartScreenDnsRequestsEnabled"
            "Description" = "Enable DNS requests to SmartScreen service"
        },

        # ===== MICROSOFT EDGE (CHROMIUM) - USER PREFERENCES =====
        @{
            "Category" = "Edge Chromium (User Preferences)"
            "Registry Entry" = "HKCU:Software\Microsoft\Edge\SmartScreenEnabled"
            "Path" = "HKCU:\Software\Microsoft\Edge\SmartScreenEnabled"
            "Name" = "(default)"
            "Description" = "User preference for Edge SmartScreen"
        },
        @{
            "Category" = "Edge Chromium (User Preferences)"
            "Registry Entry" = "HKCU:Software\Microsoft\Edge\SmartScreenPUAEnabled"
            "Path" = "HKCU:\Software\Microsoft\Edge\SmartScreenPUAEnabled"
            "Name" = "(default)"
            "Description" = "User preference for PUA blocking"
        },
        @{
            "Category" = "Edge Chromium (User Preferences)"
            "Registry Entry" = "HKCU:Software\Policies\Microsoft\Edge\SmartScreenEnabled"
            "Path" = "HKCU:\Software\Policies\Microsoft\Edge"
            "Name" = "SmartScreenEnabled"
            "Description" = "User policy for Edge SmartScreen"
        },

        # ===== MICROSOFT EDGE (LEGACY) - SYSTEM =====
        @{
            "Category" = "Edge Legacy (System Policy)"
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\EnabledV9"
            "Path" = "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
            "Name" = "EnabledV9"
            "Description" = "Legacy Edge SmartScreen/PhishingFilter"
        },
        @{
            "Category" = "Edge Legacy (System Policy)"
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverride"
            "Path" = "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
            "Name" = "PreventOverride"
            "Description" = "Prevent override of site warnings"
        },
        @{
            "Category" = "Edge Legacy (System Policy)"
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverrideAppRepUnknown"
            "Path" = "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
            "Name" = "PreventOverrideAppRepUnknown"
            "Description" = "Prevent override of download warnings"
        },

        # ===== MICROSOFT EDGE (LEGACY) - USER =====
        @{
            "Category" = "Edge Legacy (User Policy)"
            "Registry Entry" = "HKCU:Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\EnabledV9"
            "Path" = "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
            "Name" = "EnabledV9"
            "Description" = "User-level Legacy Edge SmartScreen"
        },
        @{
            "Category" = "Edge Legacy (User Policy)"
            "Registry Entry" = "HKCU:Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverride"
            "Path" = "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
            "Name" = "PreventOverride"
            "Description" = "User-level prevent site warning override"
        },
        @{
            "Category" = "Edge Legacy (User Policy)"
            "Registry Entry" = "HKCU:Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverrideAppRepUnknown"
            "Path" = "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
            "Name" = "PreventOverrideAppRepUnknown"
            "Description" = "User-level prevent download warning override"
        },
        @{
            "Category" = "Edge Legacy (User Preferences)"
            "Registry Entry" = "HKCU:Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter\EnabledV9"
            "Path" = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter"
            "Name" = "EnabledV9"
            "Description" = "Edge Legacy AppContainer SmartScreen setting"
        },

        # ===== INTERNET EXPLORER - SYSTEM =====
        @{
            "Category" = "Internet Explorer (System)"
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\Internet Explorer\PhishingFilter\EnabledV9"
            "Path" = "HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter"
            "Name" = "EnabledV9"
            "Description" = "IE SmartScreen Filter"
        },
        @{
            "Category" = "Internet Explorer (System)"
            "Registry Entry" = "HKLM:Software\Policies\Microsoft\Internet Explorer\PhishingFilter\PreventOverride"
            "Path" = "HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter"
            "Name" = "PreventOverride"
            "Description" = "IE prevent SmartScreen warning override"
        },
        @{
            "Category" = "Internet Explorer (System)"
            "Registry Entry" = "HKLM:Software\Microsoft\Internet Explorer\PhishingFilter\EnabledV9"
            "Path" = "HKLM:\Software\Microsoft\Internet Explorer\PhishingFilter"
            "Name" = "EnabledV9"
            "Description" = "IE SmartScreen default setting"
        },

        # ===== INTERNET EXPLORER - USER =====
        @{
            "Category" = "Internet Explorer (User)"
            "Registry Entry" = "HKCU:Software\Policies\Microsoft\Internet Explorer\PhishingFilter\EnabledV9"
            "Path" = "HKCU:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter"
            "Name" = "EnabledV9"
            "Description" = "User-level IE SmartScreen policy"
        },
        @{
            "Category" = "Internet Explorer (User)"
            "Registry Entry" = "HKCU:Software\Policies\Microsoft\Internet Explorer\PhishingFilter\PreventOverride"
            "Path" = "HKCU:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter"
            "Name" = "PreventOverride"
            "Description" = "User-level IE prevent override"
        },
        @{
            "Category" = "Internet Explorer (User)"
            "Registry Entry" = "HKCU:Software\Microsoft\Internet Explorer\PhishingFilter\EnabledV9"
            "Path" = "HKCU:\Software\Microsoft\Internet Explorer\PhishingFilter"
            "Name" = "EnabledV9"
            "Description" = "User IE SmartScreen preference"
        },

        # ===== WINDOWS DEFENDER / SECURITY CENTER =====
        @{
            "Category" = "Windows Defender"
            "Registry Entry" = "HKLM:Software\Microsoft\Windows Defender\Features\SmartScreen"
            "Path" = "HKLM:\Software\Microsoft\Windows Defender\Features"
            "Name" = "SmartScreen"
            "Description" = "Windows Defender SmartScreen feature flag"
        },
        @{
            "Category" = "Windows Defender"
            "Registry Entry" = "HKLM:Software\Microsoft\Windows Defender\SmartScreen\ConfigureAppInstallControlEnabled"
            "Path" = "HKLM:\Software\Microsoft\Windows Defender\SmartScreen"
            "Name" = "ConfigureAppInstallControlEnabled"
            "Description" = "App install control via SmartScreen"
        },
        @{
            "Category" = "Windows Defender"
            "Registry Entry" = "HKLM:Software\Microsoft\Windows Defender\SmartScreen\ConfigureAppInstallControl"
            "Path" = "HKLM:\Software\Microsoft\Windows Defender\SmartScreen"
            "Name" = "ConfigureAppInstallControl"
            "Description" = "App install control policy level"
        },

        # ===== WINDOWS SECURITY / APP & BROWSER CONTROL =====
        @{
            "Category" = "Windows Security Center"
            "Registry Entry" = "HKLM:Software\Microsoft\Windows Security Health\State\AppAndBrowser_EdgeSmartScreenOff"
            "Path" = "HKLM:\Software\Microsoft\Windows Security Health\State"
            "Name" = "AppAndBrowser_EdgeSmartScreenOff"
            "Description" = "Security Center Edge SmartScreen state"
        },
        @{
            "Category" = "Windows Security Center"
            "Registry Entry" = "HKLM:Software\Microsoft\Windows Security Health\State\AppAndBrowser_StoreAppsSmartScreenOff"
            "Path" = "HKLM:\Software\Microsoft\Windows Security Health\State"
            "Name" = "AppAndBrowser_StoreAppsSmartScreenOff"
            "Description" = "Security Center Store apps SmartScreen state"
        },

        # ===== ADDITIONAL SMARTSCREEN SETTINGS =====
        @{
            "Category" = "Additional Settings"
            "Registry Entry" = "HKLM:Software\Microsoft\PolicyManager\default\SmartScreen\EnableSmartScreenInShell"
            "Path" = "HKLM:\Software\Microsoft\PolicyManager\default\SmartScreen"
            "Name" = "EnableSmartScreenInShell"
            "Description" = "Policy Manager SmartScreen in Shell"
        },
        @{
            "Category" = "Additional Settings"
            "Registry Entry" = "HKLM:Software\Microsoft\PolicyManager\default\SmartScreen\EnableAppInstallControl"
            "Path" = "HKLM:\Software\Microsoft\PolicyManager\default\SmartScreen"
            "Name" = "EnableAppInstallControl"
            "Description" = "Policy Manager app install control"
        },
        @{
            "Category" = "Additional Settings"
            "Registry Entry" = "HKLM:Software\Microsoft\PolicyManager\default\SmartScreen\PreventOverrideForFilesInShell"
            "Path" = "HKLM:\Software\Microsoft\PolicyManager\default\SmartScreen"
            "Name" = "PreventOverrideForFilesInShell"
            "Description" = "Prevent override for files in Explorer"
        },
        @{
            "Category" = "Additional Settings"
            "Registry Entry" = "HKCU:Software\Microsoft\Windows Security Health\State\AppAndBrowser_EdgeSmartScreenOff"
            "Path" = "HKCU:\Software\Microsoft\Windows Security Health\State"
            "Name" = "AppAndBrowser_EdgeSmartScreenOff"
            "Description" = "User Security Center Edge SmartScreen state"
        }
    )

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "SmartScreen Registry Status Checker" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    Write-Host "Checking $($entries.Count) registry entries...`n" -ForegroundColor Yellow

    $progressCount = 0
    foreach ($entry in $entries) {
        $progressCount++
        Write-Progress -Activity "Scanning SmartScreen Registry Entries" -Status "Checking entry $progressCount of $($entries.Count)" -PercentComplete (($progressCount / $entries.Count) * 100)

        try {
            # Retrieve registry value
            if ($entry.Name -eq "" -or $entry.Name -eq "(default)") {
                $key = Get-Item -Path $entry.Path -ErrorAction Stop
                $value = $key.GetValue('')
            } else {
                $value = Get-ItemPropertyValue -Path $entry.Path -Name $entry.Name -ErrorAction Stop
            }

            # Interpret the value
            $interpretedValue = Get-InterpretedValue -Entry $entry -Value $value

        } catch {
            $value = $null
            $interpretedValue = "Not Configured (registry entry does not exist)"
        }

        $results += [PSCustomObject]@{
            "Category"        = $entry.Category
            "Registry Entry"  = $entry."Registry Entry"
            "Raw Value"       = if ($null -ne $value) { $value } else { "N/A" }
            "Status"          = $interpretedValue
            "Description"     = $entry.Description
        }
    }

    Write-Progress -Activity "Scanning SmartScreen Registry Entries" -Completed

    # Display summary
    $configured = ($results | Where-Object { $_."Raw Value" -ne "N/A" }).Count
    $notConfigured = ($results | Where-Object { $_."Raw Value" -eq "N/A" }).Count

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Scan Complete" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Total Entries Checked: $($entries.Count)" -ForegroundColor White
    Write-Host "Configured: $configured" -ForegroundColor Green
    Write-Host "Not Configured: $notConfigured" -ForegroundColor Yellow
    Write-Host "`n"

    # Export results
    if ($ExportToCSV) {
        $csvPath = $OutputPath -replace '\.txt$', '.csv'
        $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Results exported to CSV: $csvPath`n" -ForegroundColor Cyan
    }

    # Write formatted output to text file
    $outputContent = @"
========================================
SmartScreen Registry Status Report
========================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Computer: $env:COMPUTERNAME
User: $env:USERNAME

Summary:
--------
Total Entries: $($entries.Count)
Configured: $configured
Not Configured: $notConfigured

========================================
Detailed Results by Category
========================================

"@

    $groupedResults = $results | Group-Object -Property Category

    foreach ($group in $groupedResults) {
        $outputContent += "`n----- $($group.Name) -----`n"
        foreach ($item in $group.Group) {
            $outputContent += "`nRegistry: $($item.'Registry Entry')`n"
            $outputContent += "Description: $($item.Description)`n"
            $outputContent += "Raw Value: $($item.'Raw Value')`n"
            $outputContent += "Status: $($item.Status)`n"
            $outputContent += "-" * 60 + "`n"
        }
    }

    $outputContent | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "Full report saved to: $OutputPath`n" -ForegroundColor Cyan

    # Display in console (grouped by category)
    foreach ($group in $groupedResults) {
        Write-Host "`n===== $($group.Name) =====" -ForegroundColor Magenta
        $group.Group | Format-Table -Property @{Label="Registry Entry"; Expression={$_."Registry Entry"}; Width=70}, 
                                              @{Label="Value"; Expression={$_."Raw Value"}; Width=10}, 
                                              @{Label="Status"; Expression={$_.Status}; Width=50} -Wrap
    }

    # Display recommendations
    Show-SmartScreenRecommendations -Results $results

    return $results
}

function Show-SmartScreenRecommendations {
    param($Results)

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "RECOMMENDED SETTINGS FOR MODERN SYSTEMS" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "For Windows 10/11, you should configure these ESSENTIAL settings:`n" -ForegroundColor Yellow

    # Define recommended settings
    $recommendations = @(
        @{
            Priority = "[***] CRITICAL"
            Path = "HKLM:\Software\Policies\Microsoft\Windows\System"
            Name = "EnableSmartScreen"
            Value = "1 (DWORD)"
            Current = ($Results | Where-Object { $_."Registry Entry" -eq "HKLM:Software\Policies\Microsoft\Windows\System\EnableSmartScreen" }).'Raw Value'
            Purpose = "Master switch for Windows SmartScreen"
        },
        @{
            Priority = "[***] CRITICAL"
            Path = "HKLM:\Software\Policies\Microsoft\Windows\System"
            Name = "ShellSmartScreenLevel"
            Value = "'Block' (String) or 'Warn'"
            Current = ($Results | Where-Object { $_."Registry Entry" -eq "HKLM:Software\Policies\Microsoft\Windows\System\ShellSmartScreenLevel" }).'Raw Value'
            Purpose = "File Explorer enforcement (Block = max security)"
        },
        @{
            Priority = "[***] CRITICAL"
            Path = "HKLM:\Software\Policies\Microsoft\Edge"
            Name = "SmartScreenEnabled"
            Value = "1 (DWORD)"
            Current = ($Results | Where-Object { $_."Registry Entry" -eq "HKLM:Software\Policies\Microsoft\Edge\SmartScreenEnabled" }).'Raw Value'
            Purpose = "Enable SmartScreen in Edge browser"
        },
        @{
            Priority = "[***] CRITICAL"
            Path = "HKLM:\Software\Policies\Microsoft\Edge"
            Name = "SmartScreenPuaEnabled"
            Value = "1 (DWORD)"
            Current = ($Results | Where-Object { $_."Registry Entry" -eq "HKLM:Software\Policies\Microsoft\Edge\SmartScreenPuaEnabled" }).'Raw Value'
            Purpose = "Block potentially unwanted apps in Edge"
        },
        @{
            Priority = "[**] IMPORTANT"
            Path = "HKLM:\Software\Policies\Microsoft\Edge"
            Name = "PreventSmartScreenPromptOverride"
            Value = "1 (DWORD)"
            Current = ($Results | Where-Object { $_."Registry Entry" -eq "HKLM:Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverride" }).'Raw Value'
            Purpose = "Prevent bypassing warnings for websites"
        },
        @{
            Priority = "[**] IMPORTANT"
            Path = "HKLM:\Software\Policies\Microsoft\Edge"
            Name = "PreventSmartScreenPromptOverrideForFiles"
            Value = "1 (DWORD)"
            Current = ($Results | Where-Object { $_."Registry Entry" -eq "HKLM:Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverrideForFiles" }).'Raw Value'
            Purpose = "Prevent bypassing warnings for downloads"
        },
        @{
            Priority = "[**] IMPORTANT"
            Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost"
            Name = "EnableWebContentEvaluation"
            Value = "1 (DWORD)"
            Current = ($Results | Where-Object { $_."Registry Entry" -eq "HKCU:Software\Microsoft\Windows\CurrentVersion\AppHost\EnableWebContentEvaluation" }).'Raw Value'
            Purpose = "SmartScreen for Windows Store apps"
        }
    )

    # Display each recommendation with current status
    foreach ($rec in $recommendations) {
        $currentValue = if ($rec.Current -eq "N/A" -or $null -eq $rec.Current) { "NOT SET" } else { $rec.Current }
        
        # Determine if setting is correct
        $isCorrect = $false
        if ($rec.Value -like "*1 (DWORD)*" -and $currentValue -eq "1") {
            $isCorrect = $true
        } elseif ($rec.Value -like "*'Block'*" -and $currentValue -eq "Block") {
            $isCorrect = $true
        } elseif ($rec.Value -like "*'Warn'*" -and $currentValue -eq "Warn") {
            $isCorrect = $true
        }

        $statusSymbol = if ($isCorrect) { "[OK]" } else { "[X]" }
        $statusColor = if ($isCorrect) { "Green" } else { "Red" }

        Write-Host "$($rec.Priority)" -ForegroundColor Cyan
        Write-Host "  Registry: $($rec.Path)" -ForegroundColor White
        Write-Host "  Value Name: $($rec.Name)" -ForegroundColor White
        Write-Host "  Recommended: $($rec.Value)" -ForegroundColor White
        Write-Host "  Current: " -NoNewline -ForegroundColor White
        Write-Host "$statusSymbol $currentValue" -ForegroundColor $statusColor
        Write-Host "  Purpose: $($rec.Purpose)" -ForegroundColor Gray
        Write-Host ""
    }

    Write-Host "========================================" -ForegroundColor Green
    Write-Host "SETTINGS YOU SHOULD NOT CONFIGURE" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "[X] DO NOT SET - Legacy/Deprecated:" -ForegroundColor Red
    Write-Host "   - Microsoft Edge Legacy (MicrosoftEdge\PhishingFilter) - Edge Legacy retired 2021" -ForegroundColor Gray
    Write-Host "   - Internet Explorer (Internet Explorer\PhishingFilter) - IE deprecated" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "[X] DO NOT SET - User Preferences (use policy keys instead):" -ForegroundColor Red
    Write-Host "   - HKCU:\Software\Microsoft\Edge\SmartScreenEnabled" -ForegroundColor Gray
    Write-Host "   - HKCU:\Software\Microsoft\Edge\SmartScreenPUAEnabled" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "[X] DO NOT SET - Read-Only Status Indicators:" -ForegroundColor Red
    Write-Host "   - Windows Security Health\State (written by system)" -ForegroundColor Gray
    Write-Host "   - Windows Defender\Features (internal feature flags)" -ForegroundColor Gray
    Write-Host ""

    Write-Host "========================================" -ForegroundColor Green
    Write-Host "COMPLIANCE STANDARDS" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "These settings align with:" -ForegroundColor White
    Write-Host "  - DISA STIG V-63685: EnableSmartScreen=1, ShellSmartScreenLevel='Block'" -ForegroundColor Gray
    Write-Host "  - CIS Benchmark 18.9.85.1.1: Configure Windows Defender SmartScreen" -ForegroundColor Gray
    Write-Host "  - Microsoft Security Baseline: Windows 10/11 recommended settings" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "For detailed guidance, see: SmartScreen-Recommended-Settings.md" -ForegroundColor Yellow
    Write-Host ""
}

function Get-InterpretedValue {
    param($Entry, $Value)

    $entryName = $Entry."Registry Entry"
    
    switch -Regex ($entryName) {
        "SmartScreenPuaEnabled|SmartScreenPUAEnabled" {
            switch ($Value) {
                1 { return "[OK] Enabled - PUA protection active" }
                0 { return "[X] Disabled - PUA protection off" }
                default { return "[?] Unknown value: $Value" }
            }
        }
        "SmartScreenEnabled|EnableSmartScreen" {
            switch ($Value) {
                1 { return "[OK] Enabled - SmartScreen active" }
                0 { return "[X] Disabled - SmartScreen off" }
                default { return "[?] Unknown value: $Value" }
            }
        }
        "ShellSmartScreenLevel" {
            switch ($Value) {
                "Block" { return "[OK] Block - Prevents execution without user bypass option" }
                "Warn" { return "[WARN] Warn - Shows warning, users can bypass" }
                default { return "[?] Unknown/Invalid value: $Value (valid: 'Block' or 'Warn')" }
            }
        }
        "EnableWebContentEvaluation" {
            switch ($Value) {
                1 { return "[OK] Enabled - Web content evaluation active" }
                0 { return "[X] Disabled - Web content evaluation off" }
                default { return "[?] Unknown value: $Value" }
            }
        }
        "EnabledV9" {
            switch ($Value) {
                1 { return "[OK] Enabled - Phishing/SmartScreen Filter active" }
                0 { return "[X] Disabled - Phishing/SmartScreen Filter off" }
                default { return "[?] Unknown value: $Value" }
            }
        }
        "PreventOverride|PreventSmartScreenPromptOverride" {
            switch ($Value) {
                1 { return "[OK] Enforced - Users cannot bypass warnings" }
                0 { return "[WARN] Allowed - Users can bypass warnings" }
                default { return "[?] Unknown value: $Value" }
            }
        }
        "PreventOverrideAppRepUnknown|PreventSmartScreenPromptOverrideForFiles" {
            switch ($Value) {
                1 { return "[OK] Enforced - Cannot bypass download warnings" }
                0 { return "[WARN] Allowed - Can bypass download warnings" }
                default { return "[?] Unknown value: $Value" }
            }
        }
        "SmartScreenForTrustedDownloadsEnabled" {
            switch ($Value) {
                1 { return "[OK] Enabled - Checks even trusted downloads" }
                0 { return "[X] Disabled - Skips trusted downloads" }
                default { return "[?] Unknown value: $Value" }
            }
        }
        "SmartScreenDnsRequestsEnabled" {
            switch ($Value) {
                1 { return "[OK] Enabled - DNS lookups active" }
                0 { return "[X] Disabled - DNS lookups off" }
                default { return "[?] Unknown value: $Value" }
            }
        }
        "ConfigureAppInstallControl" {
            switch ($Value) {
                "Anywhere" { return "[WARN] Anywhere - No restrictions" }
                "StoreOnly" { return "[OK] Store Only - Maximum security" }
                "Recommendations" { return "[WARN] Warn - Shows recommendations" }
                default { return "[?] Unknown value: $Value" }
            }
        }
        "AppAndBrowser.*SmartScreenOff" {
            switch ($Value) {
                0 { return "[OK] On - SmartScreen active" }
                1 { return "[X] Off - SmartScreen disabled" }
                default { return "[?] Unknown value: $Value" }
            }
        }
        default {
            if ($null -ne $Value) {
                return "Value: $Value"
            } else {
                return "Not set"
            }
        }
    }
}

# Run the function
Write-Host "`nSmartScreen Registry Status Checker v2.0" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Uncomment the line below to also export to CSV
# Get-SmartScreenStatus -ExportToCSV

Get-SmartScreenStatus
