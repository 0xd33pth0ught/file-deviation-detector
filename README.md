# File Integrity Checker

- Developer: 0xd33pth0ught
- Init Date: 03 February 2025
- Version: 1.2

A simple Python script to compute hash values (MD5 or SHA-256) for files. This tool is designed to help you verify file integrity quickly and efficiently. You can use it to process a single file, multiple files, or even an entire directory (via shell globbing).

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Single File](#single-file)
  - [Multiple Files](#multiple-files)
  - [Whole Directory](#whole-directory)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Overview

The File Integrity Checker is a command-line utility written in Python that computes a hash (either MD5 or SHA-256) for one or more files. It reads files in chunks, making it efficient even for large files.

## Features

- **Hash Computation:** Choose between MD5 and SHA-256 algorithms.
- **Flexible Input:** Process a single file, multiple files, or all files within a directory.
- **Efficient:** Reads files in chunks to handle large files without excessive memory usage.

## Requirements

- Python 3.6 or later

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/0xd33pth0ught/fileintegrity.git
   cd fileintegrity

## Usage

```
python3 fileintegrity.py path/to/file.txt
```

```
python3 fileintegrity.py file1.txt file2.txt file3.txt
```

```
python3 fileintegrity.py /path/to/directory/*
```