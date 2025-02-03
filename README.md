# File Deviation Detector

- Developer: 0xd33pth0ught
- Init Date: 03 February 2025
- Version: 2.0

The File Deviation Detector v2.0 is a forensic tool designed to compute cryptographic hashes (SHA256 and MD5) for files and compare them against a provided baseline CSV file. It is useful for detecting unauthorized changes, anomalies, or file deviations in a single file, multiple files, or entire directories (using glob patterns). This tool is especially beneficial for forensic investigations where verifying the integrity of system or application files is critical.

## Table of Contents

- [Overview & Features](#overview--features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Single File](#single-file)
  - [Multiple Files](#multiple-files)
  - [Whole Directory](#whole-directory)
  - [CSV Output](#csv-output)
- [Baseline CSV File](#baseline-csv-file)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Overview & Features

- **Hash Computation:**  
  Computes both SHA256 and MD5 hashes for each file. Although it defaults to SHA256, both hash values are always returned.

- **Flexible File Selection:**  
  Accepts one or more file paths or glob patterns (e.g., `/usr/bin/*`). It automatically resolves wildcards and processes every matching file.

- **CSV Reporting:**  
  If the `--csv` option is provided, results (with headers: `Filename, SHA256, MD5`) are saved to the specified CSV file.

- **Baseline Comparison:**  
  When a baseline CSV is provided via the `--baseline` argument, the script:
  - Validates that each file listed in the baseline belongs to one of the target directories.
  - Compares the computed hash values against the baseline.
  - Flags and logs any discrepancies (missing files or mismatched hashes) as suspicious.
  - Suspicious entries are appended to `suspicious_entries.csv` in the current working directory.
.
## Requirements

- **Python Version:**
  Python 3.8 or later

- **Dependencies:**  
  The script uses only standard Python libraries: `argparse`, `hashlib`, `csv`, `glob`, `os`, and `sys`.

## Installation

1. **Clone or Download the Repository:**
   ```bash
   git clone https://github.com/0xd33pth0ught/file-deviation-detector.git
   cd file-integrity-checker

## Usage

Run the script from the command line using Python. Below are several usage examples:

**Prints the computed SHA256 and MD5 hashes for the file:**
```
python3 file-deviation-detecter.py /path/to/single_file.txt
```

**Computes the hash values for the specified files and writes the results to an output CSV file:**
```
python3 file-deviation-detecter.py /path/to/file1.txt /path/to/file2.txt --csv /path/to/output.csv
```

**Processes all files matching the glob (e.g., all files in /usr/bin)/* and compares them against a provided baseline CSV. Only discrepancies (suspicious entries) will be highlighted in red and logged to suspicious_entries.csv**
```
python3 file-deviation-detecter.py "/usr/bin/*" --baseline /path/to/baseline.csv

```

## Baseline CSV File

**Important:** You must provide your own baseline CSV file because baselines will differ depending on the system and/or environment. The baseline CSV should be generated in a known, trusted state of your file system.

**CSV Format:**
The CSV file must include headers with the following columns:
    Filename: Absolute file path.
    SHA256: SHA256 hash value of the file.
    MD5: MD5 hash value of the file.

Example CSV:
```
Filename,SHA256,MD5
/usr/bin/example1,abcdef1234567890...,12345abcdef67890...
/usr/bin/example2,abcdef0987654321...,09876abcdef54321...
```

**Creating a baseline**
To create a baseline for your system or environment:
1. Run the script without the --baseline option and with the --csv option to output the current state.
2. Verify the output and, once confirmed as the known good state, use the generated CSV as your baseline for future comparisons.

## Troubleshooting

- **No Valid Files Found:**
  Ensure that the file paths or glob patterns provided match files on your system.

- **Baseline Mismatch Error:**
  If a baseline CSV entry does not belong to one of the target directories, the script will exit with an error. Confirm that your baseline CSV file is from the same system/environment as the target files.

- **Permission Issues:**
  Make sure you have the necessary read permissions for the files being processed and write permissions for the directory where the CSV files will be created.

## License
This project is licensed under the MIT License – see the LICENSE file for details.