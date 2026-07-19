from pathlib import Path

log_path = Path(__file__).parent / "auth.log"

with log_path.open("r", encoding="utf-8") as log_file:
    for line in log_file:
        if "Failed password" in line:
            print(line.strip())