# File Integrity Checker

- Developer: 0xd33pth0ught
- Init Date: 03 February 2025
- Version: 1.3

A simple Python script to compute hash values for files and optionally output the results to a CSV file. This tool is useful for verifying file integrity in digital forensic investigations and routine system audits.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Single File](#single-file)
  - [Multiple Files](#multiple-files)
  - [Whole Directory](#whole-directory)
  - [CSV Output](#csv-output)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Overview

The File Integrity Checker is a command-line utility written in Python. It computes cryptographic hash values (either SHA256 or MD5) for one or more files, making it easy to verify if files have been modified or tampered with. The script can process a single file, multiple files, or all files in a directory (using shell globbing).

## Features

- **Hash Computation:**  
  Compute either SHA256 (default) or MD5 hashes for files.

- **Flexible Input:**  
  Process a single file, multiple files, or an entire directory (via shell globbing).

- **CSV Output:**  
  Optionally output the results to a CSV file with the columns: `Filename`, `SHA256`, and `MD5`. Depending on the chosen algorithm, one of the hash columns will be filled while the other remains empty.

- **Robust Error Handling:**  
  Skips directories and handles file-not-found errors gracefully.

## Requirements

- Python 3.6 or later

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/0xd33pth0ught/fileintegrity.git
   cd fileintegrity

## Usage

**Checking the integrity of a single file**

```
python3 fileintegrity.py path/to/file.txt
```

**Checking the integrity of multiple files**
```
python3 fileintegrity.py file1.txt file2.txt file3.txt
```

**Checking the intergrit of a directory of files**
```
python3 fileintegrity.py /path/to/directory/*
```

**Outputting to a CSV**
```
python3 fileintegrity.py /path/to/directory/* --csv /path/to/output.csv
```

**Hashing Algorithm Options (default: sha256)**
```
-a/--algorithm md5
```