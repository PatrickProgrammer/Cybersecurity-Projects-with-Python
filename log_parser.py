from pathlib import Path

log_path = Path(__file__).parent / "security.log"

with log_path.open("r", encoding="utf-8") as log_file:
    for i in log_file:
        parts = i.strip().split()
        print(parts)