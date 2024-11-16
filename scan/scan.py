#!/usr/bin/env python3

import os
import subprocess
import yara
import argparse
import tempfile
from tqdm import tqdm
from pathlib import Path

BASE_DIR = os.path.expanduser('path/to/yara/repo')
RULES_DIRS = [
    os.path.join(BASE_DIR, 'signatures/YARA/php/'),
    os.path.join(BASE_DIR, 'signatures/YARA/php-with-comments/'),
    os.path.join(BASE_DIR, 'signatures/YARA/html/'),
    os.path.join(BASE_DIR, 'signatures/YARA/raw/')
]

COMBINED_RULES_FILE = os.path.join(tempfile.gettempdir(), 'combined_yara_rules.yara')
COMPILED_RULES_FILE = os.path.join(tempfile.gettempdir(), 'combined_yara_rules_compiled.yarac')

LOG_FILE = os.path.expanduser('malware_found.log')

def combine_and_compile_rules():
    with open(COMBINED_RULES_FILE, 'w') as outfile:
        outfile.write("// Combined YARA Rules\n")
        for rules_dir in RULES_DIRS:
            for rule_file in Path(os.path.expanduser(rules_dir)).glob("*.yara"):
                with open(rule_file, 'r') as infile:
                    outfile.write(infile.read() + "\n")
    print("Compiling YARA rules...")
    subprocess.run(["yarac", COMBINED_RULES_FILE, COMPILED_RULES_FILE], check=True, stderr=subprocess.DEVNULL)
    print("Compilation complete.")


def scan_files(rules, files, scan_dir=None):
    php_files = []
    html_js_files = []
    other_files = []
    results = {}

    for file_path in files:
        if file_path.suffix == '.php':
            php_files.append(file_path)
        elif file_path.suffix in {'.html', '.htm', '.js'}:
            html_js_files.append(file_path)
        else:
            other_files.append(file_path)

    print(f"Total PHP files: {len(php_files)}")
    print(f"Total HTML/JS files: {len(html_js_files)}")
    print(f"Total other files: {len(other_files)}")
    print(f"Total files to scan: {len(files)}")

    with open(LOG_FILE, 'w') as log:
        for file_path in tqdm(files, desc="Scanning files"):
            try:
                matches = rules.match(str(file_path))
                if matches:
                    rel_path = file_path.relative_to(scan_dir) if scan_dir else file_path
                    results[str(rel_path)] = [match.rule for match in matches]
            except yara.Error:
                print(f"Error scanning file: {file_path}")

        for file, signatures in results.items():
            prefixed_path = f"/srv/htdocs/{file}"
            log.write(f"{prefixed_path}\n")
            for signature in set(signatures):
                log.write(f"{signature}\n")
            log.write("\n")


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
        scan_files(rules, files, scan_dir)
    elif args.file:
        files = [Path(f).expanduser().resolve() for f in args.file]
        missing_files = [str(f) for f in files if not f.is_file()]
        if missing_files:
            print(f"Error: The following file(s) were not found: {', '.join(missing_files)}")
            return
        scan_files(rules, files)
    else:
        scan_dir = Path.cwd()
        files = [f for f in scan_dir.rglob('*') if f.is_file()]
        print(f"No flags provided. Scanning current working directory: {scan_dir}")
        scan_files(rules, files, scan_dir)

    if os.path.exists(COMBINED_RULES_FILE):
        os.remove(COMBINED_RULES_FILE)

    if os.path.exists(COMPILED_RULES_FILE):
        os.remove(COMPILED_RULES_FILE)

    print(f"\nScan complete. Results saved to {LOG_FILE}")
    os.system(f"open -a Console {LOG_FILE}")


if __name__ == "__main__":
    main()
