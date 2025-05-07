# ========================================================================
# Script Name: Get-ASRRules.ps1
# Description: Retrieves current Attack Surface Reduction (ASR) rules and
#              ASR-only exclusions from Windows Defender using Get-MpPreference
#              and outputs the findings to a specified text file.
# Usage:       .\Get-ASRRules.ps1 [-OutputPath <path_to_output_file>]
# ========================================================================

param(
    [string]$OutputPath = "$PSScriptRoot\Get-ASRRules_Output.txt"
)

# Remove existing output file if it exists
if (Test-Path $OutputPath) {
    Remove-Item $OutputPath -Force
}

# Define ASR rules and their GUIDs
$asrrules = @(
    @{ Name = "Block executable content from email client and webmail"; GUID = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" }
    @{ Name = "Block all Office applications from creating child processes"; GUID = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" }
    @{ Name = "Block Office applications from creating executable content"; GUID = "3B576869-A4EC-4529-8536-B80A7769E899" }
    @{ Name = "Block Office applications from injecting code into other processes"; GUID = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" }
    @{ Name = "Block JavaScript or VBScript from launching downloaded executable content"; GUID = "D3E037E1-3EB8-44C8-A917-57927947596D" }
    @{ Name = "Block execution of potentially obfuscated scripts"; GUID = "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" }
    @{ Name = "Block Win32 API calls from Office macros"; GUID = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" }
    @{ Name = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"; GUID = "01443614-cd74-433a-b99e-2ecdc07bfc25" }
    @{ Name = "Use advanced protection against ransomware"; GUID = "c1db55ab-c21a-4637-bb3f-a12568109d35" }
    @{ Name = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"; GUID = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" }
    @{ Name = "Block process creations originating from PSExec and WMI commands"; GUID = "d1e49aac-8f56-4280-b9ba-993a6d77406c" }
    @{ Name = "Block untrusted and unsigned processes that run from USB"; GUID = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" }
    @{ Name = "Block Office communication application from creating child processes"; GUID = "26190899-1602-49e8-8b27-eb1d0a1ce869" }
    @{ Name = "Block Adobe Reader from creating child processes"; GUID = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" }
    @{ Name = "Block persistence through WMI event subscription"; GUID = "e6db77e5-3df2-4cf1-b95a-636979351e5b" }
    @{ Name = "Block abuse of exploited vulnerable signed drivers"; GUID = "56a863a9-875e-4185-98a7-b882c64b5ce5" }
    @{ Name = "Block rebooting machine in Safe Mode (preview)"; GUID = "33ddedf1-c6e0-47cb-833e-de6133960387" }
    @{ Name = "Block use of copied or impersonated system tools (preview)"; GUID = "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" }
    @{ Name = "Block Webshell creation for Servers"; GUID = "a8f5898e-1dc8-49a9-9878-85004b8a61e6" }
)

$enabledvalues = "Not Enabled", "Enabled", "Audit", "NA3", "NA4", "NA5", "Warning"

# Retrieve current ASR settings
$results = Get-MpPreference

# --- Part 1: ASR rule status ---
"Attack Surface Reduction Rules" | Out-File -FilePath $OutputPath -Encoding UTF8 -Append

# Summary count
"$($results.AttackSurfaceReductionRules_ids.Count) of $($asrrules.Count) ASR rules found active" | Out-File -FilePath $OutputPath -Append

if (-not [string]::IsNullOrEmpty($results.AttackSurfaceReductionRules_ids)) {
    foreach ($rule in $asrrules) {
        $id = $rule.GUID
        $index = [array]::IndexOf($asrrules.GUID, $id)
        $found = $false

        for ($i = 0; $i -lt $results.AttackSurfaceReductionRules_ids.Count; $i++) {
            if ($results.AttackSurfaceReductionRules_ids[$i] -eq $id) {
                $state = $results.AttackSurfaceReductionRules_actions[$i]
                if ($state -in 0,1,2,6) {
                    "$($rule.Name) = $($enabledvalues[$state])" | Out-File -FilePath $OutputPath -Append
                }
                $found = $true
                break
            }
        }

        if (-not $found) {
            "$($rule.Name) = Not found" | Out-File -FilePath $OutputPath -Append
        }
    }
} else {
    "$($asrrules.Count) ASR rules empty" | Out-File -FilePath $OutputPath -Append
}

# --- Part 2: ASR-only exclusions ---
"`nAttack Surface Reduction Exclusions`n" | Out-File -FilePath $OutputPath -Append

# Fetch and expand exclusions
$exclusions = $results.AttackSurfaceReductionOnlyExclusions

if ($exclusions -and $exclusions.Count -gt 0) {
    foreach ($ex in $exclusions) {
        $ex | Out-File -FilePath $OutputPath -Append
    }
} else {
    "None" | Out-File -FilePath $OutputPath -Append
}

"`nScript completed`n" | Out-File -FilePath $OutputPath -Append