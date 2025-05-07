# PowerShell script to dump Microsoft Defender AV exclusions

param (
    [string]$OutputFile = "DefenderExclusions.txt"
)

# Get Defender Exclusions
$FileExclusions      = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
$ProcessExclusions   = Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess
$ExtensionExclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension
$IpExclusions        = Get-MpPreference | Select-Object -ExpandProperty ExclusionIpAddress

# Get Defender Status
$DefenderStatus = Get-MpComputerStatus | Select-Object -Property `
    AntivirusEnabled,
    AMServiceEnabled,
    AntispywareEnabled,
    BehaviorMonitorEnabled,
    IoavProtectionEnabled,
    NISEnabled,
    OnAccessProtectionEnabled,
    RealTimeProtectionEnabled,
    IsTamperProtected,
    AntivirusSignatureLastUpdated

# Output to console
Write-Output "Microsoft Defender AV Exclusions:"
Write-Output "----------------------------------"

Write-Output "Excluded Files & Folders:"
$FileExclusions | ForEach-Object { Write-Output $_ }

Write-Output "`nExcluded Processes:"
$ProcessExclusions | ForEach-Object { Write-Output $_ }

Write-Output "`nExcluded Extensions:"
$ExtensionExclusions | ForEach-Object { Write-Output $_ }

Write-Output "`nExcluded IP Addresses:"
$IpExclusions | ForEach-Object { Write-Output $_ }

Write-Output "`nMicrosoft Defender Status:"
$DefenderStatus | Format-List

# Export to a file
$OutputContent = @(
    "Microsoft Defender AV Exclusions:",
    "----------------------------------",
    "Excluded Files & Folders:"
)
$OutputContent += $FileExclusions
$OutputContent += "", "Excluded Processes:"
$OutputContent += $ProcessExclusions
$OutputContent += "", "Excluded Extensions:"
$OutputContent += $ExtensionExclusions
$OutputContent += "", "Excluded IP Addresses:"
$OutputContent += $IpExclusions
$OutputContent += "", "Microsoft Defender Status:", ($DefenderStatus | Out-String)

$OutputContent | Out-File -FilePath $OutputFile -Encoding utf8

Write-Output "`nExclusions have been saved to: $OutputFile"
