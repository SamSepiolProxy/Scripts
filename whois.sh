#!/bin/bash

# Check if at least one argument (file) is provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 <input_file> [<output_file>]"
    exit 1
fi

# Default output file name
OUTPUT_FILE="whois_output.csv"

# If the last argument is a valid file name, set it as the output file
if [[ "${!#}" != -* && -n "${!#}" ]]; then
    OUTPUT_FILE="${!#}"
    set -- "${@:1:$(($#-1))}"  # Remove the output file argument from the list
fi

# Input file
INPUT_FILE=$1

# Write the headers to the CSV file
echo "domain/ip,information" > "$OUTPUT_FILE"

# Function to perform a WHOIS lookup for domain and IP
whois_lookup() {
    local input=$1
    local result=""
    
    # Check if input is an IP or domain
    if [[ "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # It's an IP address, perform IP WHOIS lookup
        result=$(whois $input | awk '
        BEGIN { 
            FS=": ";
            info="";
        } 
        /NetRange/ { info="IP whois data\nNetRange: " $2; }
        /CIDR/ { info=info "\nCIDR: " $2; }
        /NetName/ { info=info "\nNetName: " $2; }
        /Organization/ { info=info "\nOrganization: " $2; }
        /OrgName/ { info=info "\nOrgName: " $2; }
        /OrgId/ { info=info "\nOrgId: " $2; }
        /Address/ { info=info "\nAddress: " $2; }
        /OrgAbuseEmail/ { info=info "\nOrgAbuseEmail: " $2; }
        /OrgTechEmail/ { info=info "\nOrgTechEmail: " $2; }
        END { print info; }')
    else
        # It's a domain, perform domain WHOIS lookup
        result=$(whois $input | awk '
        BEGIN { 
            FS=": ";
            info="";
        } 
        /Domain Name/ { info="Domain whois data\nDomain Name: " $2; }
        /Registrar/ { info=info "\nRegistrar: " $2; }
        /Registrar Abuse Contact Email/ { info=info "\nRegistrar Abuse Contact Email: " $2; }
        /Registrant Organization/ { info=info "\nRegistrant Organization: " $2; }
        /Registrant Email/ { info=info "\nRegistrant Email: " $2; }
        /Admin Organization/ { info=info "\nAdmin Organization: " $2; }
        /Admin Email/ { info=info "\nAdmin Email: " $2; }
        /Tech Organization/ { info=info "\nTech Organization: " $2; }
        /Tech Email/ { info=info "\nTech Email: " $2; }
        END { print info; }')
    fi

    # Output the result to the CSV file
    echo "\"$input\",\"$result\"" >> "$OUTPUT_FILE"
}

# Check if the input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "The file '$INPUT_FILE' does not exist."
    exit 1
fi

# Iterate over each line in the input file
while IFS= read -r line; do
    # Skip empty lines and lines that start with '#'
    if [[ -n "$line" && "$line" != \#* ]]; then
        # Perform WHOIS lookup and save to the CSV file
        whois_lookup "$line"
    fi
done < "$INPUT_FILE"

echo "WHOIS data has been written to $OUTPUT_FILE."
