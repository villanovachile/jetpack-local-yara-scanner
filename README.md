## Description
A Python utility for malware detection using YARA rules. It leverages the YARA Python library and yarac for in-memory rule handling, optimized binary compilation, and efficient file scanning, offering faster and more reliable results than traditional Bash scripting.

## Requirements
- Python3
- Yara C Library

## Installation

#### 1. Add ~/bin/ to `PATH`:
```
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc  # Or ~/.zshrc if using Zsh
source ~/.bashrc  # Or ~/.zshrc
```

#### 2. Install Yara C Library

```
brew install yara
```

#### 2. Open Terminal and run:

```
curl -fsSL https://raw.githubusercontent.com/villanovachile/jetpack-local-yara-scanner/main/install_scan.sh -o /tmp/install_scan.sh && bash /tmp/install_scan.sh && rm /tmp/install_scan.sh
```


## Usage

Run the script using the `scan` command. The script supports scanning directories, specific files, or defaults to the current working directory.

### Basic Examples
**Scan the Current Working Directory (Default):** `scan`

**Scan a Specific Directory:** `scan -d /path/to/directory`

**Scan Specific Files:** `scan -f file1.php file2.html`

### Optional Flags

**Include Exploratory Rules:** `scan -d /path/to/directory -e`

**Show Matched String Patterns (string ID and value):** `scan -f suspicious.php -s`

**Combine Exploratory Rules and Matched Strings:** `scan -e -s`





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
Scanning files:  16%|████████████▊            | 2489/15184 [00:07<00:43, 289.17it/s]
```

## Changelog

#### 1.01 -
- Limits scans to files that are 10MB or less
- Calculates memory usage
- Adds --exploratory argument to include signatures that are exploratory. These signatures will be denoted by a * . By default, only production signature matches will be output.
- Adds a `--show-strings` argument to show the matched strings for each signature.

#### 1.00 - 
- Initial release.