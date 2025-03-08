#!/bin/bash

# Check if the input file is provided as an argument
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <domains_file>"
  exit 1
fi

# Input file containing the list of domains (one domain per line)
DOMAINS_FILE="$1"

# Output directory for the generated PoC files
OUTPUT_DIR="clickjacking_poc"

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Check if the domains file exists
if [[ ! -f "$DOMAINS_FILE" ]]; then
  echo "Error: Domains file '$DOMAINS_FILE' not found!"
  exit 1
fi

# Iterate through each domain in the file
while IFS= read -r DOMAIN || [[ -n "$DOMAIN" ]]; do
  # Strip carriage return characters and skip empty lines
  DOMAIN=$(echo "$DOMAIN" | tr -d '\r')
  if [[ -z "$DOMAIN" ]]; then
    continue
  fi

  # Generate the HTML content for the PoC
  HTML_CONTENT="<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>Clickjacking PoC for $DOMAIN</title>
    <style>
        iframe {
            width: 800px;
            height: 600px;
            border: none;
            opacity: 0.8;
        }
    </style>
</head>
<body>
    <h1>Clickjacking PoC for $DOMAIN</h1>
    <iframe src=\"$DOMAIN\"></iframe>
</body>
</html>"

  # Save the HTML content to a file
  OUTPUT_FILE="$OUTPUT_DIR/${DOMAIN//[^a-zA-Z0-9]/_}_poc.html"
  echo "$HTML_CONTENT" > "$OUTPUT_FILE"
  echo "Generated PoC: $OUTPUT_FILE"
done < "$DOMAINS_FILE"

# Notify the user that the process is complete
echo "All PoC files have been generated in the '$OUTPUT_DIR' directory."
