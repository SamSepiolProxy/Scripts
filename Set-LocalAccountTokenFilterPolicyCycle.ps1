<#
.SYNOPSIS
    Continuously sets the LocalAccountTokenFilterPolicy registry value to 1 every 5 seconds.
.DESCRIPTION
    This script ensures that the LocalAccountTokenFilterPolicy remains enabled (set to 1).
    It modifies the registry key:
        HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    The script runs in a loop every 5 seconds and automatically corrects the value if changed.
    It listens for Ctrl+C (CancelKeyPress) to allow safe termination of the script.
.NOTES
    - Requires Administrator privileges.
    - Press Ctrl+C to stop the script gracefully.
    - Useful in environments where this policy keeps getting reset.
.AUTHOR
    Your Name (Optional)
.VERSION
    1.0
#>

$stopFlag = $false

# Function to handle Ctrl+C to stop the script
$global:EventHandler = {
    Write-Host "`nStopping the script..."
    $global:stopFlag = $true
}

# Register the Ctrl+C event
$null = Register-ObjectEvent -InputObject ([System.Console]) -EventName 'CancelKeyPress' -Action $global:EventHandler

Write-Host "Setting LocalAccountTokenFilterPolicy to 1 every 5 seconds..."
Write-Host "Press Ctrl+C to stop the script."

while (-not $stopFlag) {
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWord
        Write-Host "$(Get-Date): Policy set to 1."
    } catch {
        Write-Host "Error: $_"
    }
    
    Start-Sleep -Seconds 5
}

Write-Host "Script stopped."
