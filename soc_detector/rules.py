DETECTION_RULES = [
    {
        "name": "PowerShell Download",
        "event_type": "powershell",
        "field": "command",
        "pattern": "Invoke-WebRequest",
        "severity": "medium",
    },
    {
        "name": "Encoded PowerShell",
        "event_type": "powershell",
        "field": "command",
        "pattern": "-EncodedCommand",
        "severity": "high",
    },
    {
        "name": "Suspicious PowerShell Process",
        "event_type": "process",
        "field": "process_name",
        "pattern": "powershell.exe",
        "severity": "medium",
    },
    {
        "name": "Failed Login",
        "event_type": "auth",
        "field": "action",
        "pattern": "Failed Login",
        "severity": "low",
    },
]