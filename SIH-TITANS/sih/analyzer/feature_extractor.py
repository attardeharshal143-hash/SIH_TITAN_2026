import json
import sys
from pathlib import Path
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS
from scapy.layers.ipsec import ESP, AH

def extract_packet_features(packet, packet_number, base_time=None):
    time_offset = 0.0
    if hasattr(packet, "time"):
        if base_time is not None:
            time_offset = round(float(packet.time) - float(base_time), 4)
        else:
            time_offset = round(float(packet.time), 4)

    features = {
        "packet_number": packet_number,
        "time_offset": max(0.0, time_offset),
        "packet_length": len(packet),
        "ip_version": None,
        "ip_protocol_number": None,
        "src_ip": None,
        "dst_ip": None,
        "transport_protocol": "OTHER",
        "src_port": None,
        "dst_port": None,
        "ike_candidate": False,
        "esp": False,
        "ah": False,
        "icmp": False,
        "dns": False,
        "info": ""
    }

    # IP Layer
    if packet.haslayer(IP):
        ip = packet[IP]
        features["ip_version"] = 4
        features["ip_protocol_number"] = int(ip.proto)
        features["src_ip"] = str(ip.src)
        features["dst_ip"] = str(ip.dst)
    elif packet.haslayer(IPv6):
        ip = packet[IPv6]
        features["ip_version"] = 6
        features["ip_protocol_number"] = int(ip.nh)
        features["src_ip"] = str(ip.src)
        features["dst_ip"] = str(ip.dst)

    # Transport / IPsec Layer Checks
    if packet.haslayer(ESP) or features["ip_protocol_number"] == 50:
        features["esp"] = True
        features["transport_protocol"] = "ESP"
        features["info"] = "Encrypted Security Payload (ESP)"
        if packet.haslayer(ESP) and hasattr(packet[ESP], "spi"):
            features["info"] += f" SPI={hex(packet[ESP].spi)}"
    elif packet.haslayer(AH) or features["ip_protocol_number"] == 51:
        features["ah"] = True
        features["transport_protocol"] = "AH"
        features["info"] = "Authentication Header (AH)"
        if packet.haslayer(AH) and hasattr(packet[AH], "spi"):
            features["info"] += f" SPI={hex(packet[AH].spi)}"
    elif packet.haslayer(TCP):
        tcp = packet[TCP]
        features["transport_protocol"] = "TCP"
        features["src_port"] = int(tcp.sport)
        features["dst_port"] = int(tcp.dport)
        features["info"] = f"TCP {tcp.sport} -> {tcp.dport}"
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        features["transport_protocol"] = "UDP"
        features["src_port"] = int(udp.sport)
        features["dst_port"] = int(udp.dport)

        if udp.sport in (500, 4500) or udp.dport in (500, 4500):
            features["ike_candidate"] = True
            features["transport_protocol"] = "IKE"
            if udp.sport == 4500 or udp.dport == 4500:
                features["info"] = f"IKE NAT-T (UDP {udp.sport} -> {udp.dport})"
            else:
                features["info"] = f"IKE ISAKMP (UDP {udp.sport} -> {udp.dport})"
        elif packet.haslayer(DNS) or udp.sport == 53 or udp.dport == 53:
            features["dns"] = True
            features["transport_protocol"] = "DNS"
            features["info"] = "DNS Query/Response"
        else:
            features["info"] = f"UDP {udp.sport} -> {udp.dport}"
    elif packet.haslayer(ICMP):
        features["transport_protocol"] = "ICMP"
        features["icmp"] = True
        features["info"] = "ICMP Control Message"

    return features

def extract_pcap_features(pcap_path):
    packets = rdpcap(str(pcap_path))
    if len(packets) == 0:
        return []

    base_time = float(packets[0].time) if hasattr(packets[0], "time") else 0.0
    packet_features = []

    for idx, packet in enumerate(packets, start=1):
        feat = extract_packet_features(packet, idx, base_time=base_time)
        packet_features.append(feat)

    return packet_features

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python feature_extractor.py <path_to_pcap> [output_json]")
        sys.exit(1)

    pcap_file = Path(sys.argv[1])
    if not pcap_file.exists():
        print(f"Error: File not found {pcap_file}")
        sys.exit(1)

    features = extract_pcap_features(pcap_file)
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("dataset/ipsec_features.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(features, f, indent=2)

    print(f"Features successfully extracted: {len(features)} packets -> {output_path}")
