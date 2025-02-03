#!/usr/bin/env python3

"""
Developer: 0xd33pth0ught
Date: 3/2/2025
Version: 2.0
"""

import argparse
import hashlib
import csv 
import glob
import os
import sys

# ANSI escape sequences for colored output.
RED = "\033[91m"
RESET = "\033[0m"

def compute_hash(file_path):
    """
    Compute both SHA-256 and MD5 Hashes of the given file
    Return a tuple: (sha256_hexdigest, md5_hexdigest)
    """

    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()

    try:
        with open(file_path, 'rb') as f:
            # Read file in 8K chunks
            while chunk := f.read(8192):
                sha256_hash.update(chunk)
                md5_hash.update(chunk)
    except Exception as e:
        print(f"[!] Error Processing File ({file_path}): {e}", file=sys.stderr)
        return None, None
    return sha256_hash.hexdigest(), md5_hash.hexdigest()

def write_csv(output_path, data):
    """
    Write list of dictionaries (data) to a CSV file with its headers:
    Filename, SHA256, and MD5
    """
    try:
        with open(output_path, 'w', newline='') as csvfile:
            fieldnames = ['Filename', 'SHA256', 'MD5']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in data:
                writer.writerow(row)
        print(f"[+] Results written to CSV ({output_path})")
    except Exception as e:
        print(f"[!] Error writing CSV file ({output_path}): {e}", file=sys.stderr)
        sys.exit(1)

def read_baseline_csv(baseline_path):
    """
    Reads the baseline CSV and returns a dictionary mapping each file (absolute path)
    to its expected SHA256 and MD5 Hash values. The CSV must have headers such as 
    Filename, SHA256, and MD5
    """

    baseline_dict = {}
    try:
        with open(baseline_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # Convert filename to an absolute path
                abs_filename = os.path.abspath(row['Filename'])
                baseline_dict[abs_filename] = {'SHA256': row['SHA256'], 'MD5': row['MD5']}
    except Exception as e:
        print(f"[!] Error reading baseline CSV file ({baseline_path}): {e}", file=sys.stderr)
        sys.exit(1)
    return baseline_dict

def append_suspicious_entry(suspicious_file, row):
    """
    Append a row (dictionary of keys: Filename, SHA256, MD5) to the suspicious entries CSV
    """

    file_exists = os.path.exists(suspicious_file)
    try:
        with open(suspicious_file, 'a', newline='') as csvfile:
            fieldnames = ['Filename', 'SHA256', 'MD5']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)
    except Exception as e:
        print(f"[!] Error writing {suspicious_file}: {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(
        description="File Deviation Checker - Compute SHA256 and MD5 hashes for one or more files, optionally compare against a baseline CSV."
    )
    parser.add_argument('targets', nargs='+', help="File(s) or glob pattern(s) to check e.e (/usr/bin/*)")
    parser.add_argument('--csv', help="Path to output CSV file where results will be saved.")
    parser.add_argument('--baseline', help="Path to baseline CSV file for comparison.")
    args = parser.parse_args()

    # Gather all files from the provided targets
    files_to_process = []
    for target in args.targets:
        # If target contains wildcard characters, treat it as a glob pattern
        if any(char in target for char in ['*', '?', '[']):
            matched_files = glob.glob(target)
            if not matched_files:
                print(f"[-] No files matched pattern: {target}", file=sys.stderr)
            files_to_process.extend(matched_files)
        else:
            if os.path.exists(target) and os.path.isfile(target):
                files_to_process.append(target)
            else:
                print(f"[-] File not found: {target}", file=sys.stderr)

    if not files_to_process:
        print("[-] No valid files to process.", file=sys.stderr)
        sys.exit(1)

    # Process each file and commpute its hash values
    results = []
    for file_path in files_to_process:
        abs_path = os.path.abspath(file_path)
        sha256_val, md5_val = compute_hash(abs_path)
        if sha256_val is None:
            continue # Skip files that could not be processed
        result = {'Filename':abs_path, 'SHA256':sha256_val, 'MD5':md5_val}
        results.append(result)
        # Also output the results to the console if not using --baseline#
        if not args.baseline:
            print(f"\n{abs_path:}")
            print(f"\tSHA256: {sha256_val}")
            print(f"\tMD5: {md5_val}")

    # If a baseline CSV is provided, read it, and compare it to our computed values for anomalies.
    if args.baseline:
        baseline_data = read_baseline_csv(args.baseline)

        # Determine valid base directiories from the user targets
        # For each target, take the directory part and convert to an absolute path
        valid_dirs = set()
        for target in args.targets:
            # For Glob patterns, os.path.dirname gives the base directory
            base_dir = os.path.abspath(os.path.dirname(target))
            valid_dirs.add(base_dir)

        # Check that each entry in the baseline CSV comes from one of these directories
        for baseline_file in baseline_data:
            # baseline_file is stored as an absolute path (see read_baseline_csv)
            if not any(baseline_file.startswith(valid_dir) for valid_dir in valid_dirs):
                print(f"Error: Baseline CSV entry '{baseline_file}' is not under one of the target directories: {valid_dirs}", file=sys.stderr)
                sys.exit(1)

        
        # Compare the computed results with the baseline
        for result in results:
            filename = result['Filename']
            baseline_entry = baseline_data.get(filename)
            if baseline_entry is None:
                print(f"{RED}SUSPICIOUS: File {filename} not found in baseline.{RESET}", file=sys.stderr)
                append_suspicious_entry('suspicious_entries.csv', result)
            else:
                # Compare both hash values
                if result['SHA256'] != baseline_entry['SHA256'] or result['MD5'] != baseline_entry['MD5']:
                    print(f"{RED}SUSPICIOUS: Hash mismatch for {filename}.{RESET}", file=sys.stderr)
                    append_suspicious_entry('suspicious_entries.csv', result)

    # If the user requested CSV output, write all computed results to the given file
    if args.csv:
        write_csv(args.csv, results)

if __name__ == '__main__':
    main()