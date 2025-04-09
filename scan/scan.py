#!/usr/bin/env python3
# Title: Jetpack Local YARA Scanner
# Author: Daniel Rodriguez (@villanovachile)
# Version: 1.01

import os
import subprocess
import yara
import argparse
import tempfile
import psutil
from tqdm import tqdm
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings

warnings.filterwarnings("ignore", category=RuntimeWarning)

BASE_DIR = os.path.expanduser('path/to/yara/rules/')
RULES_DIRS = [
    os.path.join(BASE_DIR, 'signatures/YARA/php/'),
    os.path.join(BASE_DIR, 'signatures/YARA/php-with-comments/'),
    os.path.join(BASE_DIR, 'signatures/YARA/html/'),
    os.path.join(BASE_DIR, 'signatures/YARA/raw/'),
]

COMBINED_RULES_FILE = os.path.join(tempfile.gettempdir(), 'combined_yara_rules.yara')
COMPILED_RULES_FILE = os.path.join(tempfile.gettempdir(), 'combined_yara_rules_compiled.yarac')
LOG_FILE = os.path.expanduser('malware_found.log')

FILE_SIZE_LIMIT_MB = 10


def combine_and_compile_rules():
    """Combine YARA rules and compile them."""
    process = psutil.Process(os.getpid())
    print(f"Memory Usage Before Compiling Rules: {process.memory_info().rss / 1024 ** 2:.2f} MB")
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
    print(f"Memory Usage After Compiling Rules: {process.memory_info().rss / 1024 ** 2:.2f} MB")


def filter_files_by_size(files, max_size_mb):
    """Filter files by size, only include files under the max size in MB."""
    max_size_bytes = max_size_mb * 1024 * 1024
    filtered_files = []
    for file in files:
        try:
            if file.stat().st_size <= max_size_bytes:
                filtered_files.append(file)
        except Exception as e:
            print(f"Error accessing file {file}: {e}")
    return filtered_files


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


def scan_file(file_path, rules, include_exploratory=False, show_strings=False):

    """Scan a single file using YARA rules."""
    try:
        matches = rules.match(str(file_path))
    except yara.Error:
        return file_path, None

    labeled_matches = []
    for match in matches:
        if "exploratory" in match.tags and not include_exploratory:
            continue

        matched_strings = []
        if show_strings:
            for s in match.strings:
                try:
                    matched_strings.append(f"{s.identifier}: {repr(s.data)}")
                except Exception as e:
                    matched_strings.append(f"{repr(s)}")  # Fallback


        label = "*exploratory" if "exploratory" in match.tags else "production"
        labeled_matches.append((match.rule, label, matched_strings))
    return file_path, labeled_matches


def scan_files(rules, files, scan_dir=None, include_exploratory=False, show_strings=False):

    """Scan files using YARA rules."""
    results = {}
    process = psutil.Process(os.getpid())

    with ThreadPoolExecutor() as executor:
        with tqdm(total=len(files), desc="Scanning files") as progress:
            future_to_file = {
                executor.submit(scan_file, file, rules, include_exploratory, show_strings): file
                for file in files
            }


            for i, future in enumerate(as_completed(future_to_file)):
                file_path, matches = future.result()

                if matches:
                    rel_path = file_path.relative_to(scan_dir) if scan_dir else file_path
                    results[str(rel_path)] = matches

                if i % 10 == 0:
                    memory_usage = process.memory_info().rss / 1024 ** 2
                    progress.set_description(f"Scanning files (Mem: {memory_usage:.2f} MB)")

                progress.update(1)

    with open(LOG_FILE, 'w') as log:
        for file, signatures in results.items():
            log.write(f"{file}\n")
            for signature, label, strings in signatures:
                line = f"*{signature}" if label == "*exploratory" else signature
                log.write(f"{line}\n")
                if show_strings and strings:
                    for s in strings:
                        log.write(f"    {s}\n")
            log.write("\n")

    print(f"\nScan results saved to {LOG_FILE}")


def open_log_file(log_file):
    """Open the log file after scanning."""
    process = psutil.Process(os.getpid())
    print(f"Memory Usage After scan: {process.memory_info().rss / 1024 ** 2:.2f} MB")
    try:
        result = os.system(f"open -a Console {LOG_FILE}")
        if result != 0:
            os.system(f"open {LOG_FILE}")
    except Exception:
        os.system(f"open {LOG_FILE}")


def main():
    parser = argparse.ArgumentParser(description="Scan directories or files using YARA rules.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-d", "--directory", type=str, help="Directory to scan")
    group.add_argument("-f", "--file", type=str, nargs='+', help="File(s) to scan")
    parser.add_argument("-e", "--exploratory", action="store_true", help="Include exploratory rules in addition to production")
    parser.add_argument("-s", "--show-strings", action="store_true", help="Show matched strings for each signature")
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

    files = filter_files_by_size(files, FILE_SIZE_LIMIT_MB)
    categories = categorize_files(files)

    print(f"Total PHP files under 10MB: {len(categories['php'])}")
    print(f"Total HTML/JS files under 10MB: {len(categories['html_js'])}")
    print(f"Total other files under 10MB: {len(categories['other'])}")
    print(f"Total files under 10MB to scan: {len(files)}")

    if args.exploratory:
        print("Including exploratory rules in scan.")
    scan_files(rules, files, scan_dir, include_exploratory=args.exploratory, show_strings=args.show_strings)
    open_log_file(LOG_FILE)

    for temp_file in [COMBINED_RULES_FILE, COMPILED_RULES_FILE]:
        if os.path.exists(temp_file):
            os.remove(temp_file)


if __name__ == "__main__":
    main()
