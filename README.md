## Description
A Python utility for malware detection using YARA rules. It leverages the YARA Python library and yarac for in-memory rule handling, optimized binary compilation, and efficient file scanning, offering faster and more reliable results than traditional Bash scripting.

## Requirements
- Python3

## Installation

1. Add ~/bin/ to `PATH`:
```
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc  # Or ~/.zshrc if using Zsh
source ~/.bashrc  # Or ~/.zshrc
```

2. Open Terminal and run:

```
curl -fsSL https://raw.githubusercontent.com/villanovachile/jetpack-local-yara-scanner/main/install_scan.sh -o /tmp/install_scan.sh && bash /tmp/install_scan.sh && rm /tmp/install_scan.sh
```


## Usage

Run the script using the `scan` command. The script supports scanning directories, specific files, or defaults to the current working directory.

1. **Scan the Current Working Directory (Default)**: `scan`

2. **Scan a Specific Directory**: `scan -d /path/to/directory`

3. **Scan Specific Files**: `scan -f file1.php file2.html`

#### Note:
This scans all files in the current working directory or the specified directory/file. To ensure accurate results, limit the scan to binary files.


Example Output:

```
scan
Compiling YARA rules...
Compilation complete.
No flags provided. Scanning current working directory: /Users/user/scan-directory
Total PHP files: 11037
Total HTML/JS files: 3912
Total other files: 235
Total files to scan: 15184
Scanning files:  16%|████████████▊                                                                 | 2489/15184 [00:07<00:43, 289.17it/s]
```