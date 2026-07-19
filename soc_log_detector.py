from pathlib import Path
from pprint import pprint


file_path = Path(__file__).parent / "logs"/"auth.log"
log_directory = Path(__file__).parent / "logs"

def load_log_file(file_path):

    try:
        with file_path.open("r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip()]
        
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except PermissionError:
        print(f"Permission Denied: {file_path}")
        return None
    except UnicodeDecodeError:
        print(f"Error decoding (Not valid UTF-8): {file_path}")
        return None
    

def load_all_logs(logs_directory):
    events = []

    for file_path in logs_directory.rglob("*.log"):
        if not file_path.is_file():
            continue

        content = load_log_file(file_path)

        if content is None:
            continue

        for line in content:
            result = {
                "source_file": file_path.name,
                "raw_log": line,
            }

            events.append(result)

    return events


def parse_auth_log(raw_log):
    parts = raw_log.split()
    if len(parts) < 7:
        return None
    
    event = {
        "timestamp": f"{parts[0]} {parts[1]}",
        "severity": parts[2],
        "user": parts[3].split("=", 1)[1],
        "action": f"{parts[4]} {parts[5]}",
        "source_ip": parts[6].split("=", 1)[1],
        }
    return event


def parse_events(events):
    parsed_events = []

    for event in events:
        if event["source_file"] == "auth.log":
            parsed_event = parse_auth_log(event["raw_log"])

            if parsed_events is None:
                continue

            parsed_event["source_file"] = event["source_file"] 
            parsed_event["raw_log"] = event["raw_log"]

            parsed_events.append(parsed_event)

    return parsed_events
    
events = load_all_logs(log_directory)

parsed_events = parse_events(events)

print(parsed_events)