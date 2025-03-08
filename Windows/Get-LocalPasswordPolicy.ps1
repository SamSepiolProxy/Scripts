# PowerShell script to dump specific local password policy settings

param (
    [string]$OutputFile = "LocalPasswordPolicy.txt"
)

# Export security policy settings
$TempFile = "$env:TEMP\secpol.cfg"
secedit /export /areas SECURITYPOLICY /cfg $TempFile > $null

# Read and filter the exported file
if (Test-Path $TempFile) {
    $PolicyContent = Get-Content $TempFile | Where-Object {
        $_ -match "^(MinimumPasswordAge|MaximumPasswordAge|MinimumPasswordLength|PasswordComplexity|PasswordHistorySize|LockoutBadCount|ResetLockoutCount|LockoutDuration|AllowAdministratorLockout|ClearTextPassword)"
    }
    
    # Display results
    Write-Output "Local Password Policy Settings:" 
    Write-Output "--------------------------------------"
    $PolicyContent | ForEach-Object { Write-Output $_ }
    
    # Save results to file
    $PolicyContent | Out-File -FilePath $OutputFile -Encoding utf8
    Remove-Item $TempFile -Force
    Write-Output "Local password policy has been saved to: $OutputFile"
} else {
    Write-Output "Failed to export security policy settings."
}