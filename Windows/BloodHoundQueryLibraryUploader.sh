#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

# API endpoint and auth
API_URL="http://localhost:8080/api/v2/saved-queries"
JWT_TOKEN="TOKEN GOES HERE"

echo "[*] Downloading custom queries from SpecterOps repository..."
curl -sSL \
  -o customqueries.json \
  "https://raw.githubusercontent.com/SpecterOps/BloodHoundQueryLibrary/refs/heads/main/Queries.json"

echo "[*] Fetching existing saved queries from API..."
curl -sSL \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  "$API_URL" > existing_queries.json

echo "[*] Deleting existing saved queries..."
jq -r '.data[].id' existing_queries.json | while read -r id; do
  curl -sSL -X DELETE \
    -H "Authorization: Bearer $JWT_TOKEN" \
    "$API_URL/$id"
  sleep 0.1
 done

echo "[*] Uploading new custom queries to API..."
jq -c '.[] | {name: .name, description: .description, query: .query}' customqueries.json | \
while read -r payload; do
  curl -sSL -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $JWT_TOKEN" \
    --data-raw "$payload" \
    "$API_URL"
  sleep 0.1
done

echo "[*] Cleaning up files..."
rm -f existing_queries.json customqueries.json

echo "[*] All queries successfully uploaded."
