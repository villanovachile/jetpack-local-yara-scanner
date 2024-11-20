#!/usr/bin/env python3

import os
import subprocess
import yara
import argparse
import tempfile
from tqdm import tqdm
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_DIR = os.path.expanduser('path/to/yara/repo')
RULES_DIRS = [
    os.path.join(BASE_DIR, 'signatures/YARA/php/'),
    os.path.join(BASE_DIR, 'signatures/YARA/php-with-comments/'),
    os.path.join(BASE_DIR, 'signatures/YARA/html/'),
    os.path.join(BASE_DIR, 'signatures/YARA/raw/'),
]

COMBINED_RULES_FILE = os.path.join(tempfile.gettempdir(), 'combined_yara_rules.yara')
COMPILED_RULES_FILE = os.path.join(tempfile.gettempdir(), 'combined_yara_rules_compiled.yarac')
LOG_FILE = os.path.expanduser('malware_found.log')

def combine_and_compile_rules():
    """Combine YARA rules and compile them."""
    with open(COMBINED_RULES_FILE, 'w') as outfile:
        outfile.write("// Combined YARA Rules\n")
        for rules_dir in RULES_DIRS:
            rule_files = list(Path(rules_dir).glob("*.yara"))
            for rule_file in rule_files:
                with open(rule_file, 'r') as infile:
                    outfile.write(infile.read() + "\n")
    print("Compiling YARA rules...")
    subprocess.run(["yarac", COMBINED_RULES_FILE, COMPILED_RULES_FILE], check=True, stderr=subprocess.DEVNULL)
    print("Compilation complete.")

def categorize_files(files):
    """Categorize files by extension."""
    categories = defaultdict(list)
    for file_path in files:
        ext = file_path.suffix
        if ext == '.php':
            categories['php'].append(file_path)
        elif ext in {'.html', '.htm', '.js'}:
            categories['html_js'].append(file_path)
        else:
            categories['other'].append(file_path)
    return categories

def scan_file(file_path, rules):
    """Scan a single file using YARA rules."""
    try:
        matches = rules.match(str(file_path))
        return file_path, matches
    except yara.Error:
        return file_path, None

def scan_files(rules, files, scan_dir=None):
    """Scan files using YARA rules."""
    results = {}
    with ThreadPoolExecutor() as executor:
        with tqdm(total=len(files), desc="Scanning files") as progress:
            future_to_file = {executor.submit(scan_file, file, rules): file for file in files}
            for future in as_completed(future_to_file):
                file_path, matches = future.result()
                if matches:
                    rel_path = file_path.relative_to(scan_dir) if scan_dir else file_path
                    results[str(rel_path)] = [match.rule for match in matches]
                progress.update(1)

    with open(LOG_FILE, 'w') as log:
        for file, signatures in results.items():
            log.write(f"{file}\n")
            for signature in set(signatures):
                log.write(f"{signature}\n")
            log.write("\n")

    print(f"\nScan results saved to {LOG_FILE}")

def open_log_file(log_file):
    try:
        result = os.system(f"open -a Console {LOG_FILE}")
        if result != 0:
            os.system(f"open {LOG_FILE}")
    except Exception as e:
        os.system(f"open {LOG_FILE}")


def main():
    parser = argparse.ArgumentParser(description="Scan directories or files using YARA rules.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-d", "--directory", type=str, help="Directory to scan")
    group.add_argument("-f", "--file", type=str, nargs='+', help="File(s) to scan")
    args = parser.parse_args()

    combine_and_compile_rules()
    rules = yara.load(filepath=COMPILED_RULES_FILE)

    if args.directory:
        scan_dir = Path(args.directory).expanduser().resolve()
        if not scan_dir.is_dir():
            print(f"Error: Directory not found: {args.directory}")
            return
        files = [f for f in scan_dir.rglob('*') if f.is_file()]
    elif args.file:
        files = [Path(f).expanduser().resolve() for f in args.file]
        missing_files = [str(f) for f in files if not f.is_file()]
        if missing_files:
            print(f"Error: The following file(s) were not found: {', '.join(missing_files)}")
            return
        scan_dir = None
    else:
        scan_dir = Path.cwd()
        files = [f for f in scan_dir.rglob('*') if f.is_file()]
        print(f"No flags provided. Scanning current working directory: {scan_dir}")

    categories = categorize_files(files)
    print(f"Total PHP files: {len(categories['php'])}")
    print(f"Total HTML/JS files: {len(categories['html_js'])}")
    print(f"Total other files: {len(categories['other'])}")
    print(f"Total files to scan: {len(files)}")

    scan_files(rules, files, scan_dir)
    open_log_file(LOG_FILE)

    for temp_file in [COMBINED_RULES_FILE, COMPILED_RULES_FILE]:
        if os.path.exists(temp_file):
            os.remove(temp_file)

if __name__ == "__main__":
    main()
