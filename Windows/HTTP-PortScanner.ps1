﻿# PowerShell Port Scanner using HTTP requests
param(
    [string]$Target = "google.co.uk", # Default target is localhost
    [int[]]$Ports = @(80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199,1720,465,548,113,81,6001,10000,514,5060,179,1026,2000,8443,8000,32768,554,26,1433,49152,2001,515,8008,49154,1027,5666,646,5000,5631,631,49153,8081,2049,88,79,5800,106,2121,1110,49155,6000,513,990,5357,427,49156,543,544,5101,144,7,389,8009,3128,444,9999,5009,7070,5190,3000,5432,3986,13,1029,9,6646,49157,1028,873,1755,2717,4899,9100,119,37,1000,3001,5001,82,10010,1030,9090,2107,1024,2103,6004,1801,19,8031,1041,255,3703,17,808,3689,1031,1071,5901,9102,9000,2105,636,1038,2601,7000,5985), # Default ports to scan
    [int]$Timeout = 3000 # Timeout in milliseconds
)

function Test-Port {
    param (
        [string]$Target,
        [int]$Port,
        [int]$Timeout
    )

    try {
        # Attempt an HTTP request to the target port
        $response = Invoke-WebRequest -Uri "http://${Target}:$Port" -TimeoutSec ($Timeout / 1000) -ErrorAction Stop
        Write-Host "Port $Port on $Target is OPEN." -ForegroundColor Green
    } catch {
        Write-Host "Port $Port on $Target is CLOSED." -ForegroundColor Red
    }
}

# Iterate through each port
foreach ($port in $Ports) {
    Test-Port -Target $Target -Port $port -Timeout $Timeout
}
