#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path


def load_reference_set(path: Path) -> set:
    """
    Load reference lines into a set for fast lookup.
    Blank lines are ignored and whitespace is stripped.
    """
    try:
        with path.open("r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip()}
    except Exception as e:
        print(f"[!] Failed to read reference file '{path}': {e}", file=sys.stderr)
        sys.exit(1)


def filter_target_file(reference: set, target_path: Path) -> list:
    """
    Return lines from target file that do NOT appear in the reference set.
    Original line order is preserved.
    """
    try:
        with target_path.open("r", encoding="utf-8") as f:
            return [
                line for line in f
                if line.strip() and line.strip() not in reference
            ]
    except Exception as e:
        print(f"[!] Failed to read target file '{target_path}': {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Remove lines from a second file if they also appear in a first file. "
            "Line order in the second file is preserved."
        )
    )

    parser.add_argument(
        "reference_file",
        help="File containing lines to remove (order does not matter)"
    )

    parser.add_argument(
        "target_file",
        help="File to be filtered"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output file (default: stdout)",
        default=None
    )

    args = parser.parse_args()

    reference_path = Path(args.reference_file)
    target_path = Path(args.target_file)

    if not reference_path.is_file():
        print(f"[!] Reference file not found: {reference_path}", file=sys.stderr)
        sys.exit(1)

    if not target_path.is_file():
        print(f"[!] Target file not found: {target_path}", file=sys.stderr)
        sys.exit(1)

    reference_set = load_reference_set(reference_path)
    filtered_lines = filter_target_file(reference_set, target_path)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as out:
                out.writelines(filtered_lines)
        except Exception as e:
            print(f"[!] Failed to write output file '{args.output}': {e}", file=sys.stderr)
            sys.exit(1)
    else:
        for line in filtered_lines:
            print(line, end="")


if __name__ == "__main__":
    main()

