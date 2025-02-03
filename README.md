# File Integrity Checker

- Developer: 0xd33pth0ught
- Init Date: 03 February 2025
- Version: 1.0

A simple Python script to compute and verify file hashes (MD5 and SHA-256) for file integrity checks. This tool is designed to help digital forensic professionals and developers ensure that files have not been altered by comparing their current hash values with known baselines.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Overview

The File Integrity Checker is a command-line utility written in Python. It reads a file in binary mode, computes its hash using either the MD5 or SHA-256 algorithm, and outputs the hash in hexadecimal format. This tool is useful for:
- Verifying file integrity.
- Detecting unauthorized changes to files.
- Supporting forensic investigations.

## Features

- **Hash Computation:** Compute MD5 or SHA-256 hash values.
- **Large File Support:** Processes files in chunks to handle large files without high memory consumption.
- **Command-Line Interface:** Easily specify the file and the desired algorithm.
- **Error Handling:** Gracefully handles missing files and unsupported algorithms.

## Requirements

- Python 3.6 or later
- Standard Python libraries:
  - `argparse`
  - `hashlib`
  - `sys`

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/0xd33pth0ught/fileintegrity.git
   cd fileintegrity
