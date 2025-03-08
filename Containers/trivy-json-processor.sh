#!/bin/bash

# Usage message function
usage() {
  cat <<EOF
Usage: $0 [-l list_file] [-o output_csv] [json_file1 json_file2 ...]
  -l list_file   : File containing a list of JSON file paths (one per line)
  -o output_csv  : Output CSV file name (default: output.csv)
  json_file      : One or more JSON files as arguments
EOF
  exit 1
}

# Default output CSV file name
output_file="output.csv"
json_files=()

# Process command-line options
while getopts "l:o:" opt; do
  case $opt in
    l)
      list_file="$OPTARG"
      if [ ! -f "$list_file" ]; then
        echo "Error: List file '$list_file' does not exist."
        exit 1
      fi
      while IFS= read -r line; do
        # Skip empty lines
        if [ -n "$line" ]; then
          json_files+=("$line")
        fi
      done < "$list_file"
      ;;
    o)
      output_file="$OPTARG"
      ;;
    \?)
      usage
      ;;
    :)
      echo "Option -$OPTARG requires an argument."
      usage
      ;;
  esac
done

# Remove the options processed by getopts
shift $((OPTIND - 1))

# If additional arguments are provided, add them to the json_files array
if [ "$#" -gt 0 ]; then
  for arg in "$@"; do
    json_files+=("$arg")
  done
fi

# Check that at least one JSON file is provided
if [ "${#json_files[@]}" -eq 0 ]; then
  echo "Error: No JSON files provided."
  usage
fi

# Create or overwrite the output CSV file with a header row
# The header includes:
#   File, PkgName, InstalledVersion, FixedVersion, Status, VulnerabilityID, Severity, CVSS_V3Score
echo "File,PkgName,InstalledVersion,FixedVersion,Status,VulnerabilityID,Severity,CVSS_V3Score" > "$output_file"

# Process each JSON file
for json_file in "${json_files[@]}"; do
  if [ ! -f "$json_file" ]; then
    echo "Warning: JSON file '$json_file' does not exist. Skipping." >&2
    continue
  fi

  echo "Processing $json_file..."

  # Use jq to extract fields and add the source file name as the first column.
  # The 'CVSS.nvd.V3Score' field is handled with a default of "null" if not present.
  jq --arg file "$json_file" -r '
    .Results[]?.Vulnerabilities[]? |
    [
      $file,
      .PkgName,
      .InstalledVersion,
      .FixedVersion,
      .Status,
      .VulnerabilityID,
      .Severity,
      (.CVSS.nvd.V3Score // "null")
    ] | @csv
  ' "$json_file" >> "$output_file"
done

echo "CSV output written to $output_file"