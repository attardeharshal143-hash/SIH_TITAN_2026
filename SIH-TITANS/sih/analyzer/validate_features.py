import json
import sys
from pathlib import Path

def validate_features_data(features):
    """
    Production-safe structural feature validator.
    Validates data integrity without hardcoding specific IP addresses or requiring 100% ESP traffic.
    """
    if not isinstance(features, list):
        return False, "Features data must be a list"

    if len(features) == 0:
        return False, "Feature list is empty (no packets found in PCAP)"

    required_keys = {
        "packet_number",
        "packet_length",
        "ip_version",
        "ip_protocol_number",
        "src_ip",
        "dst_ip",
        "transport_protocol",
        "src_port",
        "dst_port",
        "ike_candidate",
        "esp",
        "ah",
        "icmp",
        "dns"
    }

    for idx, feat in enumerate(features):
        if not isinstance(feat, dict):
            return False, f"Packet {idx + 1} entry is not a valid object"

        missing = required_keys - set(feat.keys())
        if missing:
            return False, f"Packet {idx + 1} missing required keys: {missing}"

        if not isinstance(feat["packet_length"], (int, float)) or feat["packet_length"] <= 0:
            return False, f"Packet {idx + 1} has invalid packet_length"

    return True, f"Validation successful: {len(features)} packets structurally verified."

if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("dataset/ipsec_features.json")
    if not target.exists():
        print(f"Error: {target} does not exist.")
        sys.exit(1)

    with open(target, "r", encoding="utf-8") as f:
        data = json.load(f)

    valid, msg = validate_features_data(data)
    print("================================")
    print("     FEATURE VALIDATION")
    print("================================")
    print(msg)
    if not valid:
        sys.exit(1)
