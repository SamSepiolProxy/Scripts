# Scripts
## AllPorts Script
For all ports to work spin up a server on port 80 such as python3 -m http.server 80

## Custom Queries
Its a combination of the following:  
https://github.com/CompassSecurity/BloodHoundQueries  
https://github.com/fin3ss3g0d/cypherhound  
https://github.com/LuemmelSec/Custom-BloodHound-Queries  

## Azure-Admin-Unit-Dump
If no UPN appears in the role dump it's possible the role is assigned to a service principal

# Scripts Repository

Welcome to the **Scripts** repository by [SamSepiolProxy](https://github.com/SamSepiolProxy). This collection comprises various scripts and tools designed to assist with system administration, network security assessments, and other IT-related tasks.

## Contents

The repository includes scripts written in multiple languages, such as PowerShell, Python, Shell, and VBScript. Below is an overview of some notable scripts:

- **PowerShell Scripts**:
  - `AdminReport.ps1`: Generates administrative reports.
  - `Dump-AlwaysOnVPNClientConfig.ps1`: Extracts Always On VPN client configurations.
  - `Dump-FineGrainedPasswordPolicy.ps1`: Retrieves fine-grained password policies from Active Directory.
  - `HTTP-PortScanner.ps1`: Performs HTTP port scanning.
  - `PortScan-Top128.ps1`: Scans the top 128 commonly used ports.
  - `SmartScreenConfigCheck.ps1`: Checks SmartScreen configurations.
  - `sendmail.ps1`: Automates the process of sending emails to a list of recipients. This was developed for direct-send via the Azure CLI.
  - `Azure-Admin-Unit-Dump.ps1`: Automates the dumping of Azure Admin Units including members and assigned roles. If no UPN appears in the role dump it's possible the role is assigned to a service principal.

- **Python Scripts**:
  - `iker.py`: A Python script for network-related tasks.
  - `ip-range.py`: Calculates IP address ranges.
  - `machineaccountquota.py`: Checks the machine account quota in Active Directory.
  - `namemash.py`: Generates name permutations for user enumeration or other purposes.

- **Shell Scripts**:
  - `ap.sh`: Sets up an access point using specified interfaces.
  - `bloodhound-merger.sh`: Merges custom BloodHound queries from various sources.
  - `kubernetesreview.sh`: Performs a review of Kubernetes configurations.
  - `makecert.sh`: Generates SSL/TLS certificates.
  - `portscanlinux.sh`: Conducts a port scan on a Linux system.
  - `rogueap.sh`: Sets up a rogue access point for testing purposes.

- **VBScript Files**:
  - `adinfo.vbs` & `adinfov2.vbs`: Gather Active Directory information.

- **Executable Files**:
  - `SOAPHound.exe`: An executable tool included in the repository for the enumeration of AD.

- **Other Files**:
  - `customqueries.json`: Contains custom queries, possibly for BloodHound.
  - `luemmelseccustomqueries.json`: Another set of custom queries.
  - `clickjacking.html`: An HTML file related to clickjacking testing.

## Usage

Each script is intended for specific tasks. It's recommended to review the code and understand its functionality before execution. Ensure you have the necessary permissions and have met all prerequisites for running these scripts in your environment.

## Contributions

Contributions to this repository are welcome. Feel free to fork the repository, make improvements, and submit pull requests.

## License

This project is licensed under the [MIT License](LICENSE).

---

*Note: This repository is a collection of scripts for various administrative and security tasks. Use them responsibly and ensure compliance with your organization's policies and applicable laws.*

