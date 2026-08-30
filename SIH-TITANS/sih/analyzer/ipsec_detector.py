import json
import sys
from pathlib import Path

def detect_ipsec_stats(features):
    stats = {
        "total_packets": len(features),
        "esp_packets": sum(1 for f in features if f.get("esp")),
        "ah_packets": sum(1 for f in features if f.get("ah")),
        "ike_packets": sum(1 for f in features if f.get("ike_candidate")),
        "tcp_packets": sum(1 for f in features if f.get("transport_protocol") == "TCP"),
        "udp_packets": sum(1 for f in features if f.get("transport_protocol") == "UDP"),
        "icmp_packets": sum(1 for f in features if f.get("icmp")),
        "dns_packets": sum(1 for f in features if f.get("dns")),
        "other_packets": 0,
        "is_ipsec_detected": False
    }

    known = stats["esp_packets"] + stats["ah_packets"] + stats["ike_packets"] + stats["tcp_packets"] + stats["udp_packets"] + stats["icmp_packets"] + stats["dns_packets"]
    stats["other_packets"] = max(0, stats["total_packets"] - known)
    stats["is_ipsec_detected"] = (stats["esp_packets"] > 0 or stats["ah_packets"] > 0 or stats["ike_packets"] > 0)
    return stats

if __name__ == "__main__":
    feature_file = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("dataset/ipsec_features.json")
    if not feature_file.exists():
        print(f"Error: {feature_file} not found")
        sys.exit(1)

    with open(feature_file, "r", encoding="utf-8") as f:
        features = json.load(f)

    stats = detect_ipsec_stats(features)
    print("================================")
    print("       IPSEC DETECTOR")
    print("================================")
    for k, v in stats.items():
        print(f"{k}: {v}")
    print("================================")
