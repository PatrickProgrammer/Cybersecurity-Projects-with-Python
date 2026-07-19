from pathlib import Path
from pprint import pprint
from soc_detector.rules import DETECTION_RULES


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
        "event_type": "auth",
        }
    return event


def parse_events(events):
    parsed_events = []

    for event in events:
        if event["source_file"] == "auth.log":
            parsed_event = parse_auth_log(event["raw_log"])
        
        elif event["source_file"] == "powershell.log":
            parsed_event = parse_powershell_log(event["raw_log"])
        
        elif event["source_file"] == "process.log":
            parsed_event = parse_process_log(event["raw_log"])
        
        else:
            continue

        if parsed_event is None:
            continue

        parsed_event["source_file"] = event["source_file"] 
        parsed_event["raw_log"] = event["raw_log"]

        parsed_events.append(parsed_event)

    return parsed_events

def parse_powershell_log(raw_log):
        result = {
            "command": raw_log,
            "event_type": "powershell",
        }

        return result
    

def parse_process_log(raw_log):

    result = {
        "process_name": raw_log,
        "event_type" : "process",
    }
    return result

def apply_rules(parsed_events, rules):
    alerts = []
    for event in parsed_events:
        for rule in rules:
            if event["event_type"] != rule["event_type"]:
                continue
                
            field_value = event.get(rule["field"])
            
            if field_value is None:
                continue

            if rule["pattern"].lower() in field_value.lower():
                alert = {
                    "rule_name" : rule["name"],
                    "severity": rule["severity"],
                    "source_file": event["source_file"],
                    "matched_filed": rule["field"],
                    "matched_pattern": rule["pattern"],
                    "raw_low": event["raw_log"],
                }
                alerts.append(alert)

    return alerts

events = load_all_logs(log_directory)
parsed_events = parse_events(events)
alerts = apply_rules(parsed_events, DETECTION_RULES)
pprint(alerts)


