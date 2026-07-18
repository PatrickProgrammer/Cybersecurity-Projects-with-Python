from pathlib import Path
from pprint import pprint
import json

rules = [
    {
        "name": "Mimikatz Command",
        "pattern": "sekurlsa::logonpasswords",
        "severity": "high",
    },
    {
        "name": "PowerShell Download",
        "pattern": "Invoke-WebRequest",
        "severity": "medium",
    },
    {
        "name": "Encoded PowerShell",
        "pattern": "-EncodedCommand",
        "severity": "high",
    },
]

testfile_path = Path(__file__).parent / "test_files"
output_file_path = Path(__file__).parent / "yara_scanner_results.json"


def read_text_file(file_path):
    try:
        with file_path.open("r", encoding="utf-8") as file:
            return file.read()

    except UnicodeDecodeError:
        print(f"Error decoding file: {file_path}")
        return None

    except PermissionError:
        print(f"Permission denied: {file_path}")
        return None

    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None


def match_rules(content, rules):
    matches = []
    for rule in rules:
        if rule["pattern"].lower() in content.lower():
            match = {
                "rule_name": rule["name"],
                "pattern": rule["pattern"],
                "severity": rule["severity"],
            }
            matches.append(match)
    return matches

def scan_directory(directory_path, rules):
    scan_results = []
    for file_path in directory_path.rglob("*"):
        if file_path.is_file():
            content = read_text_file(file_path)
            if content is None:
                continue
            matches = match_rules(content, rules)
            results = {
                "file_path": str(file_path),
                "matches": matches,
            }
            scan_results.append(results)
    return scan_results

def export_results(scan_results, output_file_path):
    try:
        with output_file_path.open("w", enconding="utf-8") as file:
            json.dump(scan_results, file, indent=4)
            print("Export Success")
    except Exception as e:
        print(f"Error exporting results to {output_file_path}: {e}")
        print("Export failed")

scan_results = scan_directory(testfile_path, rules)
pprint(scan_results)

