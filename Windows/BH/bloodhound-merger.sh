#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

echo "[*] Creating temporary directory..."
TMPDIR="$(mktemp -d --suffix=_bloodhound-customqueries)"

# Compass BloodHound Customqueries
echo "[*] Downloading Compass BloodHound customqueries..."
curl -s -o "$TMPDIR/customqueries-compass.json" "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/BloodHound_Custom_Queries/customqueries.json"

echo "[*] Modifying category on Compass BloodHound customqueries..."
jq '.queries[].category |= (sub("^";"🧭 Compass: "))' < "$TMPDIR/customqueries-compass.json" > "$TMPDIR/customqueries-01-compass-modified.json"

# Certipy BloodHound Customqueries
echo "[*] Downloading Certipy BloodHound customqueries..."
curl -s -o "$TMPDIR/customqueries-certipy.json" "https://raw.githubusercontent.com/ly4k/Certipy/main/customqueries.json"

echo "[*] Modifying category on Certipy BloodHound customqueries..."
jq '.queries[].category |= (sub("^";"🔏 Certipy: "))' < "$TMPDIR/customqueries-certipy.json" > "$TMPDIR/customqueries-02-certipy-modified.json"

# Hausec BloodHound Customqueries
echo "[*] Downloading Hausec BloodHound customqueries..."
curl -s -o "$TMPDIR/customqueries-hausec.json" "https://raw.githubusercontent.com/hausec/Bloodhound-Custom-Queries/master/customqueries.json"

echo "[*] Adding category to Hausec BloodHound customqueries..."
jq '.queries[] |= { "category": "💻 Hausec" } +. ' < "$TMPDIR/customqueries-hausec.json" > "$TMPDIR/customqueries-02-hausec-modified.json"

#Cypherhound BloodHound Customqueries
echo "[*] Downloading Cypherhound BloodHound customqueries..."
curl -s -o "$TMPDIR/customqueries-cypherhound.json" "https://raw.githubusercontent.com/fin3ss3g0d/cypherhound/main/customqueries.json"

echo "[*] Modifying category on Cypherhound BloodHound customqueries..."
jq '.queries[].category |= (sub("^";"🔑 Cypherhound: "))' < "$TMPDIR/customqueries-cypherhound.json" > "$TMPDIR/customqueries-02-cypherhound-modified.json"

#LuemmelSec BloodHound Customqueries
echo "[*] Downloading LuemmelSec BloodHound customqueries..."
curl -s -o "$TMPDIR/customqueries-luemmelsec.json" "https://raw.githubusercontent.com/SamSepiolProxy/Scripts/main/luemmelseccustomqueries.json"

echo "[*] Modifying category on LuemmelSec BloodHound customqueries..."
jq '.queries[].category |= (sub("^";"☁️ LuemmelSec: "))' < "$TMPDIR/customqueries-luemmelsec.json" > "$TMPDIR/customqueries-02-luemmelsec-modified.json"

echo "[*] Merging queries..."
cat "$TMPDIR/"*-modified.json | jq -s 'add + {queries: map(.queries[])}' > customqueries.json

echo "[*] Done. Please copy to your config directory:"
echo "cp customqueries.json ~/.config/bloodhound/"

echo "[*] Bye."