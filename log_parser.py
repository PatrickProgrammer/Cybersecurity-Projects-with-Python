from pathlib import Path

events = []

log_path = Path(__file__).parent / "security.log"

with log_path.open("r", encoding="utf-8") as log_file:
    for line in log_file:
        parts = line.strip().split()

        event = {
            "date": parts[0],
            "time": parts[1],
            "severity": parts[2],
            "user": parts[3].split("=")[1],
            "action": parts[4].split("=")[1],
            "src_ip": parts[5].split("=")[1]
        }
        events.append(event)  
          
severity_counts = {}
  
for event in events:
    severity = event["severity"]

    if severity in severity_counts:
        severity_counts[severity] += 1
    else:
        severity_counts[severity] = 1


ip_count = {}

for event in events:
    src_ip = event["src_ip"]

    if src_ip in ip_count:
        ip_count[src_ip] += 1
    else:
        ip_count[src_ip] = 1

for ip, count in ip_count.items():
    if count >= 0:
        print(f"IP:{ip} Count: {count}")

        