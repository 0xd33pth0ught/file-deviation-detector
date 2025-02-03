#!/usr/bin/env python3
"""
Author: 0xd33pth0ught
Date: 3 February 2025
Version: 1.3

File Integrity
This script computes hash values (MD5 or SHA-256) of a file to verify its integrity.
"""

import argparse, sys
import hashlib
import os
import csv
import time

def compute_hash(file_path, algorithm="sha256", block_size=65536):
    """
    Compute the hash of a file using a specified (sha256) algorithm
    
    :param file_path: Path to the file
    :param algorithm: Hashing algotithm to use. Default is sha256
    :param block_size: Number of bytes to read at a time
    :return: the hexidecimal hash string
    :raises: ValueError: If an unsupported algorithm is provided
    """

    # Check if the file_path is a directory
    if os.path.isdir(file_path):
        print(f"[!] Skipping directory: {file_path}", file=sys.stderr)
        return None

    if algorithm not in("md5", "sha256"):
        raise ValueError("[!] Unsupported algorithm::requires 'md5' or 'sha256'.")
    
    hash_func = hashlib.md5() if algorithm == "md5" else hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(block_size), b""):
                hash_func.update(block)
        return hash_func.hexdigest()
    except FileNotFoundError:
        print(f"[!# If CSV output is requested, write the rows to the specified CSV file.] Error -> File `{file_path}` not found.", file=sys.stderr)
        sys.exit(1)


def main():
    print("--------- File Integrity Check ---------")
    parser = argparse.ArgumentParser(description="File Integrity Checker")
    parser.add_argument("files", nargs="+", help="Path(s) to the file(s) to check")
    parser.add_argument("-a", "--algorithm", choices=["md5", "sha256"], default="sha256", help="Hash Algorithm to use (default: sha256)")
    parser.add_argument("--csv", help="Path to output CSV file")
    args = parser.parse_args()

    # Prepare a list to hold CSV rows if the user requested this function
    csv_rows = []
    if args.csv:
        print(f"\n[+] CSV output will be written to: {args.csv}.\n")
        time.sleep(2)

    # Process each file provided on the command line.
    for file_path in args.files:
        computed_hash = compute_hash(file_path, args.algorithm)
        if computed_hash:
            # Print to Console
            print(f"{args.algorithm.upper()} hash of {file_path}: {computed_hash}")

            # Prepar CSV output
            if args.algorithm == "sha256":
                row = {"Filename": file_path, "SHA256": computed_hash, "MD5": ""}
            elif args.algorithm == "md5":
                row = {"Filename": file_path, "SHA256": "", "MD5": computed_hash}
            csv_rows.append(row)

    # If CSV output is requested, write the rows to the specified CSV file.
    if args.csv:
        try:
            with open(args.csv, "w", newline="") as csvfile:
                fieldnames = ["Filename", "SHA256", "MD5"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for row in csv_rows:
                    writer.writerow(row)
            print(f"\n[+] Results written to {args.csv}!")
            time.sleep(2)
        except Exception as e:
            print(f"[!] Error writing CSV file: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
