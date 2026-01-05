# DPAT (Slim) — NTDS + Hashcat Potfile → HTML Report (with BloodHound CE Enrichment)

A slimmed-down **Domain Password Audit Tool (DPAT)** workflow that ingests an **NTDS extract** (e.g., `secretsdump`-style output) and a **Hashcat potfile** (`hash:password`) and produces an **interactive HTML report** (plus CSV exports of the report tables).  
Optionally, it can enrich results via **BloodHound CE** (read-only API queries).

## Attribution

This project is based on the original **DPAT** by `clr2of8`:

- Repository: https://github.com/clr2of8/DPAT

## What this tool does

- Parses an NTDS dump in `DOMAIN\user:RID:LMHASH:NTHASH:...` format.
- Maps cracked passwords from a potfile (`<32-hex-nt-hash>:<password>`).
- Generates a single **HTML report** with:
  - Summary metrics and crack coverage chart
  - Password length statistics and distributions
  - “Cracked passwords” table (top 200 by length)
  - Reused password counts (top 50)
  - LM-hash-present table (non-blank LM hashes)
  - Password policy violation table (min length)
  - Username-as-password findings:
    - Direct (cracked set)
    - **Hash-match** (detects username-as-password even if not cracked)
- Exports each report table to CSV under `DPAT Report/tables_csv/`.

Optional (BloodHound CE):
- Adds BloodHound-linked indicators (e.g., **Enabled**, **Tier Zero**) where the NTDS user can be matched to a BH `User` node.
- Adds additional BloodHound-derived tables, including a **Kerberoastable users** table (see below).

## Repository contents

- `dpat_slim_bloodhound.py` — main tool script  
- `report.css` — styling for the HTML report (dark/light theme support)

## Requirements

- Python 3.9+ recommended
- Python package: `requests`

Install dependency:

```bash
python -m pip install requests
```

## Quick start

```bash
python dpat_slim_bloodhound.py \
  -n customer.ntds \
  -c hashcat.potfile \
  -p 12
```

Output (default):
- `./DPAT Report/_DomainPasswordAuditReport.html`
- `./DPAT Report/report.css`
- `./DPAT Report/tables_csv/*.csv`

## Inputs

### NTDS file format (expected)

Lines must match (others are skipped):

```
DOMAIN\user:RID:LMHASH:NTHASH:...
```

Notes:
- Machine accounts (`something$`) are excluded by default.
- `krbtgt` is excluded by default.
- Entries with `NT` hash as 32 asterisks are skipped.

### Potfile format (expected)

Each line must be:

```
<hash>:<password>
```

Where `<hash>` is typically a 32-hex NT hash.

Supported:
- `$NT$` prefix is stripped (John common format)
- Hashcat `$HEX[...]` passwords are decoded

## Usage

### Core options

```bash
python dpat_slim_bloodhound.py -n <ntds> -c <potfile> -p <min_length>
```

| Option | Description |
|---|---|
| `-n, --ntdsfile` | NTDS input file (required) |
| `-c, --potfile` | Potfile input (required) |
| `-p, --minpasslen` | Minimum password length for “policy violation” checks (required) |
| `-d, --reportdirectory` | Output directory (default: `DPAT Report`) |
| `-o, --outputfile` | HTML report filename (default: `_DomainPasswordAuditReport.html`) |
| `-s, --sanitize` | Sanitize passwords/hashes in report output |
| `-m, --machineaccts` | Include machine accounts (ending with `$`) |
| `-k, --krbtgt` | Include `krbtgt` |
| `--css` | Path to `report.css` (defaults to `./report.css` if present) |

### BloodHound CE enrichment (optional)

If you provide **all** of the following, the report will add BH-matched sections and indicators:

```bash
python dpat_slim_bloodhound.py \
  -n customer.ntds \
  -c hashcat.potfile \
  -p 12 \
  --bh-url "http://127.0.0.1:8080/" \
  --bh-user "admin" \
  --bh-pass "password"
```

Additional options:
- `--bh-no-verify` disables TLS certificate validation (use only when appropriate).
- `--bh-timeout <seconds>` controls request timeout (default: 30).

BloodHound notes:
- The client authenticates via `POST /api/v2/login` and executes **read-only** Cypher queries via `POST /api/v2/graphs/cypher`.

#### BloodHound tables

When BloodHound CE enrichment is enabled, the report adds a dedicated table:

**“All Enabled Kerberoastable Users”**

This is sourced from the following Cypher query:

```
MATCH (u:User)
WHERE u.hasspn=true
AND u.enabled = true
AND NOT u.objectid ENDS WITH '-502'
AND NOT COALESCE(u.gmsa, false) = true
AND NOT COALESCE(u.msa, false) = true
RETURN u
```

This table is intended to highlight *enabled* Kerberoastable user accounts while excluding:
- RID `-502` (typically the built-in `KRBTGT`-style exclusion pattern used in some datasets)
- gMSA (`u.gmsa`)
- MSA (`u.msa`)

**“All Enabled Tier Zero”**

This is sourced from the following Cypher query (as requested):

```
MATCH (n:Base)
WHERE ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
AND n.enabled = true
RETURN n
```

Tier Zero is inferred via the `Tag_Tier_Zero` label and/or `system_tags` containing `admin_tier_0`.

The table is further enriched (where possible) with the NTDS/potfile-derived fields such as cracked status and (optionally sanitised) password/hash values.

## Report output

The HTML report uses:
- Bootstrap
- jQuery + DataTables (sortable/filterable tables)
- Chart.js
- Local theme toggle (dark/light), persisted in `localStorage`

CSV exports:
- Each table included in the report is also exported to `tables_csv/` within the report directory.

## Security considerations

- The report can contain sensitive material (plaintext passwords / NT hashes). Use `-s/--sanitize` when you need to share results more broadly.
- Treat the potfile and generated report as **high sensitivity** artifacts. Restrict storage, access, and distribution appropriately.

## Troubleshooting

- **0 cracked rows mapped**: confirm the potfile hashes are **NT hashes** (32 hex) and match the `NTHASH` values in your NTDS extract (case-insensitive).
- **$HEX passwords look wrong**: ensure your potfile uses Hashcat’s `$HEX[...]` convention (the tool decodes this automatically).
- **BloodHound errors**:
  - Confirm CE URL includes scheme and correct base path (e.g., `http://127.0.0.1:8080/`).
  - If using HTTPS with a self-signed cert, consider `--bh-no-verify` (risk accepted case-by-case).
  - Ensure the account can login via `/api/v2/login`.

## Disclaimer

This tool is intended for **authorised security assessment** and internal auditing. Ensure you have explicit permission before processing credential material and distributing outputs.
