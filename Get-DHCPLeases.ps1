<#
.SYNOPSIS
    Retrieves DHCP lease reservations from all DHCP servers in Active Directory and exports unique entries (based on IPAddress) to a CSV file.

.DESCRIPTION
    This script performs the following steps:
    1. Retrieves a list of DHCP servers from Active Directory using Get-DhcpServerInDC.
    2. Iterates through each server to obtain its DHCP scopes using Get-DHCPServerv4Scope.
    3. For each scope, retrieves lease reservation information using Get-DHCPServerv4Lease.
    4. Aggregates all lease reservations into an array.
    5. Uses a hashtable to filter out duplicates based on the IPAddress property.
    6. Exports the unique lease reservations to a CSV file named 'DHCPReservations.csv'.

.NOTES
    Ensure you run this script with appropriate permissions and that the DHCP server cmdlets are available.
#>

# Enable verbose output for detailed logging (adjust as needed)
$VerbosePreference = "Continue"

# Step 1: Retrieve DHCP servers from Active Directory.
Write-Verbose "Retrieving DHCP servers from Active Directory..."
$ServerList = Get-DhcpServerInDC | Select-Object IPAddress, DNSName

if (-not $ServerList) {
    Write-Host "No DHCP servers found in Active Directory."
    exit
}

# Step 2: Initialize an array to collect lease reservations.
$LeaseReservations = @()

# Step 3: Loop through each DHCP server and its scopes.
foreach ($server in $ServerList) {
    Write-Verbose "Processing server: $($server.DNSName) ($($server.IPAddress))"
    try {
        # Retrieve all scopes for the current DHCP server.
        $scopes = Get-DHCPServerv4Scope -ComputerName $server.IPAddress -ErrorAction Stop | Select-Object -ExpandProperty ScopeID
    }
    catch {
        Write-Host "Failed to retrieve scopes for server: $($server.DNSName) ($($server.IPAddress)): $_"
        continue
    }
    
    foreach ($scope in $scopes) {
        Write-Verbose "Processing scope: $scope on server: $($server.DNSName)"
        try {
            # Retrieve lease reservations for the current scope.
            $leases = Get-DHCPServerv4Lease -ScopeId $scope -ComputerName $server.DNSName -AllLeases -ErrorAction Stop |
                Select-Object ScopeId, IPAddress, HostName, ClientID, AddressState
        }
        catch {
            Write-Host "Failed to retrieve leases for scope: $scope on server: $($server.DNSName): $_"
            continue
        }
        # Append the leases from this scope to our overall collection.
        $LeaseReservations += $leases
    }
}

if ($LeaseReservations.Count -eq 0) {
    Write-Host "No lease reservations found."
    exit
}

# Step 4: Use a hashtable to filter unique lease reservations by IPAddress.
Write-Verbose "Grouping lease reservations by IPAddress to ensure uniqueness..."
$UniqueLeaseReservations = @{}
foreach ($lease in $LeaseReservations) {
    # If the IPAddress is not already a key in the hashtable, add it.
    if (-not $UniqueLeaseReservations.ContainsKey($lease.IPAddress)) {
        $UniqueLeaseReservations[$lease.IPAddress] = $lease
    }
}

$UniqueCount = $UniqueLeaseReservations.Values.Count
Write-Host "Exporting $UniqueCount unique lease reservations to CSV..."

# Step 5: Export the unique lease reservations to a CSV file.
$UniqueLeaseReservations.Values | Export-Csv -Path ".\DHCPReservations.csv" -NoTypeInformation
Write-Host "Export complete."
