<#
.SYNOPSIS
    This PowerShell script extracts Intune and related configuration details from the Windows registry.
.DESCRIPTION
    - Identifies the GUID dynamically from "C:\ProgramData\Microsoft\DMClient".
    - Uses the extracted GUID to locate the relevant registry path for Intune settings.
    - Exports the following registry subtrees to text files:
        1. HKLM:\SOFTWARE\Microsoft\PolicyManager\providers\{GUID}\default (Intune policies for the specific device)
        2. HKLM:\SOFTWARE\Microsoft\Policies\LAPS (Local Administrator Password Solution policies)
        3. HKLM:\SOFTWARE\Microsoft\PolicyManager\current (Current applied policies)
        4. HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork (Windows Hello for Business / Passport for Work policies)
    - Saves the exported registry configurations in "C:\Temp\RegistryDumps".
.NOTES
    - This script must be run with administrative privileges.
    - Output files are stored as .txt files for easy review.
#>

# Define the base directory to search for the GUID
$basePath = "C:\ProgramData\Microsoft\DMClient"

# Get the GUID dynamically (assuming it's a directory name)
$guid = Get-ChildItem -Path $basePath -Directory | Select-Object -ExpandProperty Name

if (-not $guid) {
    Write-Host "No GUID found in $basePath"
    exit
}

Write-Host "Using GUID: $guid"

# Define registry paths using the extracted GUID
$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\PolicyManager\providers\$guid\default",
    "HKLM:\SOFTWARE\Microsoft\Policies\LAPS",
    "HKLM:\SOFTWARE\Microsoft\PolicyManager\current",
    "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork"
)

# Output directory for text files
$outputDir = "C:\Temp\RegistryDumps"
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

# Loop through registry paths and export them to text files
foreach ($regPath in $registryPaths) {
    # Generate a filename by replacing "HKLM:\" with empty string and converting backslashes to underscores
    $fileName = $regPath -replace "^HKLM:\\", "" -replace "\\", "_"
    $outputFile = Join-Path $outputDir "$fileName.txt"
    
    # Check if registry path exists before exporting
    if (Test-Path $regPath) {
        Write-Host "Exporting $regPath to $outputFile"
        reg export "HKLM\$($regPath -replace 'HKLM:\\', '')" $outputFile /y
    } else {
        Write-Host "Registry path not found: $regPath"
    }
}

Write-Host "Registry export completed. Files are located in $outputDir"
