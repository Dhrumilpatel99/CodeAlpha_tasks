import os
import re
import argparse
import sys
from pathlib import Path

file_path = Path('/path/to/your/directory')

def scan_code(file_path):
    """
    Scans the given file for common vulnerabilities like SQL Injection, XSS, and hardcoded secrets.
    """
    vulnerabilities = {
        "SQL Injection": re.compile(r"SELECT\s.*FROM\s.*WHERE\s.*(['\"])"),
        "XSS (Cross-Site Scripting)": re.compile(r"<script>.*</script>", re.IGNORECASE),
        "Hardcoded API Keys": re.compile(r"(apikey|token|secret|password)\s*=\s*['\"]?[A-Za-z0-9]{10,}['\"]?")
    }
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()
    except Exception as e:
        print(f"[ERROR] Unable to read file {file_path}: {e}")
        return []
    
    issues = []
    for line_no, line in enumerate(lines, start=1):
        for vuln, pattern in vulnerabilities.items():
            if pattern.search(line):
                issues.append(f"[!] {vuln} detected at line {line_no}: {line.strip()}")
    
    return issues

def scan_directory(directory):
    """
    Scans all Python and JavaScript files in the directory for vulnerabilities.
    """
    if not os.path.isdir(directory):
        print(f"[ERROR] Directory '{directory}' does not exist.")
        return {}
    
    results = {}
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py") or file.endswith(".js"):
                file_path = os.path.join(root, file)
                issues = scan_code(file_path)
                if issues:
                    results[file_path] = issues
    return results

def generate_report(results):
    """
    Generates a report based on detected vulnerabilities.
    """
    report_file = "bug_bounty_report.txt"
    with open(report_file, "w") as report:
        for file, issues in results.items():
            report.write(f"\n[*] File: {file}\n")
            for issue in issues:
                report.write(f"{issue}\n")
    print(f"\n[+] Report generated: {report_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bug Bounty Vulnerability Scanner")
    parser.add_argument("-d", "--directory", help="Directory to scan for vulnerabilities")
    
    args = parser.parse_args()
    
    if not args.directory:
        print("[ERROR] Missing required argument: --directory")
        parser.print_help()
        sys.exit(2)
    
    print("\n[*] Scanning directory for vulnerabilities...")
    scan_results = scan_directory(args.directory)
    
    if scan_results:
        print("[+] Vulnerabilities detected! Generating report...")
        generate_report(scan_results)
    else:
        print("[-] No vulnerabilities found!")
