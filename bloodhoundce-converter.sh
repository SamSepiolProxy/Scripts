#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

rm ./existing_queries.json
rm ./customqueries.json

echo "[*] Creating temporary directory..."
TMPDIR="$(mktemp -d --suffix=_bloodhound-customqueries)"

# ZephrFish BloodHound Customqueries
echo "[*] Downloading Compass BloodHound customqueries..."
curl -s -o "$TMPDIR/customqueries-ZephrFish-bloodhound-queries.json" "https://raw.githubusercontent.com/ZephrFish/Bloodhound-CustomQueries/refs/heads/main/customqueries.json"

# Certipy BloodHound Customqueries
#echo "[*] Downloading Certipy BloodHound customqueries..."
#curl -s -o "$TMPDIR/customqueries-certipy-bloodhound-queries.json" "https://raw.githubusercontent.com/ly4k/Certipy/main/customqueries.json"

echo "[*] Merging queries..."
cat "$TMPDIR/"*-bloodhound-queries.json | jq -s 'add + {queries: map(.queries[] | {name: .name, description: .description, query: (.queryList[0].query // empty)})}' > customqueries.json

# Fetch existing saved queries
echo "[*] Fetching existing saved queries from API..."
API_URL="http://localhost:8080/api/v2/saved-queries"
JWT_TOKEN="Session Token Here"

curl -X GET \
  "$API_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" > existing_queries.json

echo "[*] Existing queries saved to existing_queries.json."

# Delete existing saved queries based on IDs
echo "[*] Deleting existing saved queries..."
jq -r '.data[].id' existing_queries.json | while read -r id; do
  curl -X DELETE \
    "$API_URL/$id" \
    -H "Authorization: Bearer $JWT_TOKEN"
done

# Upload formatted queries to API
echo "[*] Uploading queries to API..."
INPUT_FILE="customqueries.json"

jq -c '.queries[] | {name: .name, description: .description, query: .query}' "$INPUT_FILE" | while read -r query; do
  curl -X POST \
    "$API_URL" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $JWT_TOKEN" \
    --data-raw "$query"
done

echo "[*] Queries successfully uploaded."
echo "[*] Bye."
