from pathlib import Path


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

testfile_path = Path(__file__).parent / "test_files"/ "powershell.txt"


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
        if rule["pattern"].lower() in content:
            match = {
                "rule_name": rule["name"],
                "pattern": rule["pattern"],
                "severity": rule["severity"],
            }
            matches.append(match)
    return matches

content = read_text_file(testfile_path)
content = content.lower()

if content is not None:
    matches = match_rules(content, rules)
    print(matches)
