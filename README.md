# Introduction

Serpent is a simple but powerful Python-based YARA scanner. It includes tooling to effortlessly fetch community-driven YARA rules, scan files and directories, and dynamically inspect the memory of running processes for matches.

## Features

- **File Scanner (`scan.py`)**: Scan specific files or directories recursively using targeted YARA timeouts. Output results directly to JSON.
- **Process Memory Scanner (`mem_scan.py`)**: Scan running process memory (by individual PID, or scan all processes concurrently). Supports extracting preview strings directly from matched memory regions.
- **Automated Rule Fetching (`scripts/fetch_rules.py`)**: Painlessly download and extract community YARA rules directly from GitHub.

## Running It Locally

Ensure Python is installed and then install the dependencies:

```bash
pip install -r requirements.txt
```

*(Note that `mem_scan.py` will require you to run your terminal as **Administrator** on Windows / `sudo` on Linux to have the necessary permissions to read the memory of other processes).*

Before scanning anything, you will need some YARA rules. You can load your own into any folder, or fetch third party rules.

To download all categories of the community-maintained `Yara-Rules/rules`:
```bash
python scripts/fetch_rules.py
```

To only download specific categories (e.g., malware and mobile_malware):
```bash
python scripts/fetch_rules.py --categories malware mobile_malware
```
You can view all available categories using the `--list-categories` flag. 
*Note: Fetched rules abide by their respective open source licensing (e.g., GPLv2).*

### File Scanning
To scan a specific file or an entire directory, use `scan.py`:

```bash
python scan.py "C:\path\to\scan" --rules "rules/third_party/yara-rules"
```

Optional arguments:
- `--timeout [seconds]` - Set a max timeout for each file scanned (default: 10).
- `--out [file.json]` - Output the scan report to a specific JSON file (default: `results.json`).

### Memory Scanning
To scan the live memory of all running processes against your YARA rules:

```bash
python mem_scan.py --all --rules "rules/third_party/yara-rules"
```

To scan a specific Process ID (PID):

```bash
python mem_scan.py --pid 1234 --rules "rules/third_party/yara-rules"
```

Optional arguments:
- `--timeout [seconds]` - Set a max timeout per process (default: 10).
- `--out [file.json]` - Output the scan report to a specific JSON file (default: `mem_results.json`).