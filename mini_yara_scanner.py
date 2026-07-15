from pathlib import Path


rules = [
    {
        "name": "Mimikatz Command",
        "pattern": "sekurlsa::logonpasswords",
    },
    {
        "name": "PowerShell Download",
        "pattern": "Invoke-WebRequest",
    },
    {
        "name": "Encoded PowerShell",
        "pattern": "-EncodedCommand",
    },
]

testfile_path = Path(__file__).parent / "test_files"/ "normal.txt"


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


test = read_text_file(testfile_path)
print(test)