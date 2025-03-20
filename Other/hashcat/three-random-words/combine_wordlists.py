#!/usr/bin/env python3
import sys
from itertools import product, permutations

def read_lines(filename):
    """Read a file and return a list of non-empty, stripped lines."""
    with open(filename, "r") as f:
        return [line.strip() for line in f if line.strip()]

def main():
    # Check for correct number of command-line arguments
    if len(sys.argv) != 5:
        print("Usage: {} wordlist1.txt wordlist2.txt wordlist3.txt output.txt".format(sys.argv[0]))
        sys.exit(1)
    
    file1, file2, file3, output_file = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    
    # Read each file, treating each line as a complete candidate
    lines1 = read_lines(file1)
    lines2 = read_lines(file2)
    lines3 = read_lines(file3)
    
    # Open the output file for writing
    with open(output_file, "w") as out:
        # For every combination (Cartesian product) of one line from each file...
        for combo in product(lines1, lines2, lines3):
            # ...generate every permutation of the three words.
            # Using set() to remove duplicates in case any words are identical.
            for perm in set(permutations(combo, 3)):
                out.write(" ".join(perm) + "\n")
    
    print(f"Combined wordlist with all permutations written to {output_file}")

if __name__ == "__main__":
    main()
