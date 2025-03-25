<#
.SYNOPSIS
    Checks Windows for prerequisites required for Nessus Windows Credentialed Scanning.
.DESCRIPTION
    This script verifies the necessary configurations for a successful Nessus credentialed scan:
    - LocalAccountTokenFilterPolicy (Registry setting)
    - Remote Registry Service status (Should not be Disabled)
    - WMI Service status (Should not be Disabled)
    - File and Printer Sharing (Checking SMB1 & SMB2 Protocols)
    - Administrative Shares (C$, ADMIN$)
    - SMB and WMI ports (445, 135) instead of relying on firewall rule names.

    It outputs the status of each requirement and provides recommendations if issues are found.
.NOTES
    - Requires Administrator privileges.
    - Can be used to troubleshoot credentialed scan failures.
.VERSION
    1.6
#>

# Check if the script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator!" -ForegroundColor Red
    exit
}

Write-Host "Checking Nessus Credentialed Scan prerequisites..." -ForegroundColor Cyan

# Check LocalAccountTokenFilterPolicy
$tokenFilterPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -ErrorAction SilentlyContinue
if ($tokenFilterPolicy.LocalAccountTokenFilterPolicy -eq 1) {
    Write-Host "LocalAccountTokenFilterPolicy is set correctly." -ForegroundColor Green
} else {
    Write-Host "LocalAccountTokenFilterPolicy is NOT set. Run: Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 1 -Type DWord" -ForegroundColor Red
}

# Check Remote Registry Service (Only fails if Disabled)
$remoteRegistry = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
if ($remoteRegistry.StartType -eq 'Disabled') {
    Write-Host "Remote Registry Service is DISABLED. Enable it with: Set-Service -Name RemoteRegistry -StartupType Manual" -ForegroundColor Red
} else {
    Write-Host "Remote Registry Service is enabled (" $remoteRegistry.StartType ")." -ForegroundColor Green
}

# Check Windows Management Instrumentation (WMI) Service (Only fails if Disabled)
$wmiService = Get-Service -Name Winmgmt -ErrorAction SilentlyContinue
if ($wmiService.StartType -eq 'Disabled') {
    Write-Host "WMI Service is DISABLED. Enable it with: Set-Service -Name Winmgmt -StartupType Automatic" -ForegroundColor Red
} else {
    Write-Host "WMI Service is enabled (" $wmiService.StartType ")." -ForegroundColor Green
}

# Check if File and Printer Sharing is enabled using SMB1 and SMB2 Protocols
$smbConfig = Get-SmbServerConfiguration
$smb1Enabled = $smbConfig.EnableSMB1Protocol
$smb2Enabled = $smbConfig.EnableSMB2Protocol

if ($smb1Enabled -or $smb2Enabled) {
    Write-Host "File and Printer Sharing is enabled (SMB1: $smb1Enabled, SMB2: $smb2Enabled)." -ForegroundColor Green
} else {
    Write-Host "File and Printer Sharing is DISABLED. Enable SMB2 with: Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force" -ForegroundColor Red
}

# Check if Admin Shares (C$, ADMIN$) exist
$adminShares = Get-SmbShare | Where-Object { $_.Name -match 'C\$|ADMIN\$' }
if ($adminShares) {
    Write-Host "Administrative Shares (C$, ADMIN$) exist." -ForegroundColor Green
} else {
    Write-Host "Administrative Shares are MISSING. Ensure they are enabled or create them manually." -ForegroundColor Red
}

# Check if SMB port (445) is listening
$smbPort = Get-NetTCPConnection -LocalPort 445 -ErrorAction SilentlyContinue
if ($smbPort) {
    Write-Host "SMB port (TCP 445) is open and listening." -ForegroundColor Green
    Write-Host "Use Nessus and NMAP to confirm access." -ForegroundColor Green
} else {
    Write-Host "SMB port (TCP 445) is BLOCKED. Check firewall or enable File Sharing." -ForegroundColor Red
}

# Check if WMI port (135) is listening
$wmiPort = Get-NetTCPConnection -LocalPort 135 -ErrorAction SilentlyContinue
if ($wmiPort) {
    Write-Host "WMI RPC port (TCP 135) is open and listening." -ForegroundColor Green
    Write-Host "Use Nessus and NMAP to confirm access." -ForegroundColor Green
} else {
    Write-Host "WMI RPC port (TCP 135) is BLOCKED. Check firewall rules for WMI/DCOM." -ForegroundColor Red
}

Write-Host "Scan check complete. Review the results above." -ForegroundColor Cyan
