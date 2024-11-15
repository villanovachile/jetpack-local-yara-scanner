#!/usr/bin/env python3

import os
import subprocess
import yara
from tqdm import tqdm
from pathlib import Path

BASE_DIR = os.path.expanduser('path/to/yara/repo')
RULES_DIRS = [
    os.path.join(BASE_DIR, 'signatures/YARA/php/'),
    os.path.join(BASE_DIR, 'signatures/YARA/php-with-comments/'),
    os.path.join(BASE_DIR, 'signatures/YARA/html/'),
    os.path.join(BASE_DIR, 'signatures/YARA/raw/')
]

COMBINED_RULES_FILE = os.path.join(BASE_DIR, 'combined_yara_rules.yara')
COMPILED_RULES_FILE = os.path.join(BASE_DIR, 'combined_yara_rules_compiled.yarac')

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

def scan_files(rules, scan_dir):
    php_files = []
    html_js_files = []
    other_files = []
    results = {}

    all_files = [f for f in Path(scan_dir).rglob('*') if f.is_file()]
    for file_path in all_files:
        if file_path.suffix == '.php':
            php_files.append(file_path)
        elif file_path.suffix in {'.html', '.htm', '.js'}:
            html_js_files.append(file_path)
        else:
            other_files.append(file_path)

    print(f"Total PHP files: {len(php_files)}")
    print(f"Total HTML/JS files: {len(html_js_files)}")
    print(f"Total other files: {len(other_files)}")
    print(f"Total files to scan: {len(all_files)}")

    with open(LOG_FILE, 'w') as log:
        for file_path in tqdm(all_files, desc="Scanning files"):
            matches = rules.match(str(file_path))
            if matches:
                rel_path = file_path.relative_to(scan_dir)
                results[str(rel_path)] = [match.rule for match in matches]

    with open(LOG_FILE, 'w') as log:
        for file, signatures in results.items():
            prefixed_path = f"/srv/htdocs/{file}"
            log.write(f"{prefixed_path}\n")
            for signature in set(signatures):
                log.write(f"{signature}\n")
            log.write("\n")

def main(scan_dir=None):
    if scan_dir is None:
        scan_dir = Path.cwd()
    else:
        scan_dir = Path(scan_dir).expanduser().resolve()

    combine_and_compile_rules()

    rules = yara.load(filepath=COMPILED_RULES_FILE)

    scan_files(rules, scan_dir)
    print(f"\nScan complete. Results saved to {LOG_FILE}")
    os.system(f"open -a Console {LOG_FILE}")

if __name__ == "__main__":
    import sys
    scan_dir = sys.argv[1] if len(sys.argv) > 1 else None
    main(scan_dir)
