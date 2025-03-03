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