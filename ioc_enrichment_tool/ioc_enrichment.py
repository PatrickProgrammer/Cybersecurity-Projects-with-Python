from pathlib import Path
import ipaddress
import string


indicators_file_path = Path(__file__).parent/ "indicators.txt"

def load_indicator(file_path):
    try: 
        with file_path.open("r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print("File Error")
        return []
    except PermissionError:
        print("Permission Denied")
        return []


def identify_ioc_type(indicator):
    try:
        ip = ipaddress.ip_address(indicator)

        if ip.version == 4:
            return "ipv4"
        
    except ValueError:
        pass
    if (len(indicator) in (32,40,64) and all(character in string.hexdigits for character in indicator)):
        return "hash"
    
    if "." in indicator:
        return "domain"
    return "unknown"

def build_ioc(indicator):

    ioc_type = identify_ioc_type(indicator)

    structure = {
    "indicator": indicator,
    "type": ioc_type,
    }
    return structure  

def validate_ioc(ioc):
    indicator = ioc["indicator"]
    ioc_type = ioc["type"]

    if ioc_type == "ipv4":
            try:
                ip = ipaddress.ip_address(indicator)
                return ip.version == 4
            except ValueError:
                return False
        

    elif ioc_type == "hash":
        if (len(indicator) in (32,40,64)) and all(character in string.hexdigits for character in indicator):
            return True
        

    elif ioc_type == "domain":
        return ( "." in indicator and " " not in indicator and not indicator.startswith(".") and not indicator.endswith(".")
            )
    
    return False

def filter_valid_iocs(iocs):
    valid_iocs = []
    for ioc in iocs:
        if ioc["valid"]:
            valid_iocs.append(ioc)
    return valid_iocs


def enrich_ioc(ioc):
    ioc["source"] = None
    ioc["malicious"] = None
    ioc["suspicious"] = None
    ioc["harmless"] = None
    ioc["reputation"] = None
    ioc["last_analysis"] = None

    return ioc



# Load indicators
indicators = load_indicator(indicators_file_path)

# Build IOC objects
iocs = []
enriched_iocs = []

for indicator in indicators:
    iocs.append(build_ioc(indicator))

# Validate
for ioc in iocs:
    ioc["valid"] = validate_ioc(ioc)

# Filter
valid_iocs = filter_valid_iocs(iocs)

for ioc in valid_iocs:
    enriched_ioc = enrich_ioc(ioc)
    enriched_iocs.append(enriched_ioc)
# Output
print(indicator)
print(enriched_iocs)
# print(valid_iocs)


