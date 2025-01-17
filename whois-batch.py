import argparse
import csv
from ipwhois import IPWhois
from concurrent.futures import ThreadPoolExecutor

#pip install ipwhois
# Function to perform WHOIS lookup for an IP address or domain
def perform_whois(ip_or_domain):
    try:
        obj = IPWhois(ip_or_domain)
        data = obj.lookup_rdap()
        # Extract only netname and descr if available
        netname = data.get('network', {}).get('name', 'N/A')
        descr = data.get('network', {}).get('remarks', 'N/A')
        return {
            'IP or Domain': ip_or_domain,
            'Netname': netname,
            'Description': descr
        }
    except Exception as e:
        return {
            'IP or Domain': ip_or_domain,
            'Netname': 'Error',
            'Description': str(e)
        }

# Main function
def whois_from_file_to_csv(input_file, output_csv):
    # Read IPs or domains from the input file
    with open(input_file, 'r', encoding='utf-8') as file:
        ip_or_domain_list = [line.strip() for line in file if line.strip()]

    # Open CSV file for writing
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['IP or Domain', 'Netname', 'Description']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        # Perform WHOIS lookup concurrently
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(perform_whois, ip_or_domain_list)

            for result in results:
                writer.writerow(result)

    print(f"WHOIS data saved to {output_csv}")

# Entry point
if __name__ == "__main__":
    # Define command-line arguments
    parser = argparse.ArgumentParser(description="Perform WHOIS lookups for a list of IPs or domains and save the results to a CSV file.")
    parser.add_argument("input_file", help="Path to the input file containing IPs or domains (one per line).")
    parser.add_argument("output_csv", help="Path to the output CSV file to save WHOIS results.")

    # Parse arguments
    args = parser.parse_args()

    # Run the WHOIS lookup
    whois_from_file_to_csv(args.input_file, args.output_csv)