#!/usrbin/env python3
"""
Author: 0xd33pth0ught
Date: 3 February 2025
Version: 1.0

File Integrity
This script computes hash values (MD5 or SHA-256) of a file to verify its integrity.
"""

import argparse, sys
import hashlib

def compute_hash(file_path, algorithm="sha256", block_size=65536):
    """
    Compute the hash of a file using a specified (sha256) algorithm
    
    :param file_path: Path to the file
    :param algorithm: Hashing algotithm to use. Default is sha256
    :param block_size: Number of bytes to read at a time
    :return: the hexidecimal hash string
    :raises: ValueError: If an unsupported algorithm is provided
    """

    if algorithm not in("md5", "sha256"):
        raise ValueError("[!] Unsupported algorithm::requires 'md5' or 'sha256'.")
    
    hash_func = hashlib.md5() if algorithm == "md5" else hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(block_size), b""):
                hash_func.update(block)
        return hash_func.hexdigest()
    except FileNotFoundError:
        print(f"[!] Error -> File `{file_path}` not found.", file=sys.stderr)
        sys.exit(1)

def main():
    print("--------- File Integrity Check ---------")
    parser = argparse.ArgumentParser(description="File Integrity Checker")
    parser.add_argument("file", help="Path to the file to check")
    parser.add_argument("-a", "--algorithm", choices=["md5", "sha256"], default="sha256", help="Hash Algorithm to use (default: sha256)")
    args = parser.parse_args()

    file_hash = compute_hash(args.file, args.algorithm)
    print(f"{args.algorithm.upper()} hash of {args.file}: {file_hash}")

if __name__ == "__main__":
    main()
