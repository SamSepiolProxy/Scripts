# Get all DHCP Servers from Active Directory
$ServerList = Get-DhcpServerInDC | Select-Object IPAddress, DNSName

# Initialize an array to collect lease reservations
$LeaseReservations = @()

foreach ($server in $ServerList) {
    # Get the scopes for the current DHCP server
    $scopes = Get-DHCPServerv4Scope -ComputerName $server.IPAddress | Select-Object -ExpandProperty ScopeID
    
    foreach ($scope in $scopes) {
        # Get the lease information for each scope filtering for reservations only
        $leases = Get-DHCPServerv4Lease -ScopeId $scope -ComputerName $server.DNSName -AllLeases |
            Select-Object ScopeId, IPAddress, HostName, ClientID, AddressState
        
        # Append the leases from this scope to our overall collection
        $LeaseReservations += $leases
    }
}

# Export the collected lease reservations to a CSV file
$LeaseReservations | Export-Csv -Path ".\DHCPReservations.csv" -NoTypeInformation