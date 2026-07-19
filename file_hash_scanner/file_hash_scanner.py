from pathlib import Path
import hashlib
import json


file_path = Path(__file__).parent / "sample.txt"
ioc_file_path = Path(__file__).parent / "ioc.txt"
directory_path = Path(__file__).parent / "samples"
output_file_path = Path(__file__).parent / "scan_results.json"


def calculate_sha256(file_path):
    hash_object = hashlib.sha256()

    try:
        with file_path.open("rb") as file:
            while True:
                chunk = file.read(4096)

                if not chunk:
                    break

                hash_object.update(chunk)

    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

    except PermissionError:
        print(f"Permission denied: {file_path}")
        return None

    return hash_object.hexdigest()


def load_iocs(ioc_file_path):
    try:
        with ioc_file_path.open("r", encoding="utf-8") as file:
            return {
                line.strip()
                for line in file
                if line.strip()
            }

    except FileNotFoundError:
        print(f"IOC file not found: {ioc_file_path}")
        return set()


def scan_directory(directory_path, malicious_hashes):
    scan_results = []

    if not directory_path.exists():
        print(f"Directory not found: {directory_path}")
        return scan_results

    if not directory_path.is_dir():
        print(f"Path is not a directory: {directory_path}")
        return scan_results

    for file_path in directory_path.rglob("*"):
        if not file_path.is_file():
            continue

        file_hash = calculate_sha256(file_path)

        if file_hash is None:
            print(f"Could not scan file: {file_path}")

            scan_result = {
                "file_path": str(file_path),
                "sha256": None,
                "ioc_match": False,
                "error": "Hash calculation failed",
            }

            scan_results.append(scan_result)
            continue

        ioc_match = file_hash in malicious_hashes

        scan_result = {
            "file_path": str(file_path),
            "sha256": file_hash,
            "ioc_match": ioc_match,
        }

        scan_results.append(scan_result)

        if ioc_match:
            print(
                f"ALERT: Malicious hash detected: "
                f"{file_hash} in file {file_path}"
            )
        else:
            print(
                f"No IOC match: {file_hash} in file {file_path}"
            )

    return scan_results

def export_results(scan_results, output_file_path):
    try:
        with output_file_path.open("w", encoding="utf-8") as file:
            json.dump(scan_results, file, indent=4)
            print(f" Export Success")
    except Exception as e:
        print(f"Error exporting results to {output_file_path}: {e}")
        print("Export failed")

def main():
    malicious_hashes = load_iocs(ioc_file_path)

    scan_results = scan_directory(directory_path, malicious_hashes)

    export_results(scan_results, output_file_path)


if __name__ == "__main__":
    main()