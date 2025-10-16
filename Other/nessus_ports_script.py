#!/usr/bin/env python3
import pandas as pd
import sys
import os
import glob

if len(sys.argv) < 2:
    print("Usage:")
    print("  python3 combine_nessus_syn_hosts.py <file1.csv> <file2.csv> ...")
    print("  OR")
    print("  python3 combine_nessus_syn_hosts.py <folder_path>")
    sys.exit(1)

# Collect CSV files
paths = sys.argv[1:]
csv_files = []

if len(paths) == 1 and os.path.isdir(paths[0]):
    folder = paths[0]
    csv_files = glob.glob(os.path.join(folder, "*.csv"))
    if not csv_files:
        print(f"⚠️ No CSV files found in folder: {folder}")
        sys.exit(1)
    print(f"📂 Found {len(csv_files)} CSV file(s) in folder '{folder}'")
else:
    for p in paths:
        if os.path.isfile(p) and p.lower().endswith(".csv"):
            csv_files.append(p)
        else:
            print(f"⚠️ Skipping {p} (not found or not a CSV)")

if not csv_files:
    print("❌ No valid CSV input provided.")
    sys.exit(1)

dfs = []
wanted_cols = ['Host', 'Protocol', 'Port', 'Service', 'Plugin ID']

for file in csv_files:
    try:
        df = pd.read_csv(file, low_memory=False)
        # Filter for SYN scanner Plugin ID 11219
        if 'Plugin ID' in df.columns:
            df = df[df['Plugin ID'] == 11219]
        else:
            print(f"⚠️ Plugin ID column not found in {file}")
            continue

        # Keep only needed columns
        df = df[[c for c in wanted_cols if c in df.columns]]
        dfs.append(df)
        print(f"✅ Loaded {file} ({len(df)} SYN scan rows)")
    except Exception as e:
        print(f"❌ Error reading {file}: {e}")

if not dfs:
    print("❌ No data found for Plugin ID 11219.")
    sys.exit(1)

# Combine all
combined = pd.concat(dfs, ignore_index=True)

# Group by Port/Protocol/Service and aggregate all hosts into one comma-separated list
group_cols = [c for c in ['Port','Protocol','Service'] if c in combined.columns]
if 'Host' not in combined.columns:
    print("❌ No Host column found in any file.")
    sys.exit(1)

result = (
    combined.groupby(group_cols, dropna=False)['Host']
            .apply(lambda x: ", ".join(sorted(set(x))))
            .reset_index()
)

# Output
output_file = "nessus_syn_hosts.csv"
result.to_csv(output_file, index=False)

print(f"\n✅ Combined SYN scanner results saved to: {output_file}")
print(f"📊 Total rows: {len(result)}")
