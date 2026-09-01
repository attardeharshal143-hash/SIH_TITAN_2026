import json
import sys
import math
import struct
from pathlib import Path
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, Raw
from scapy.layers.ipsec import ESP, AH

def calculate_shannon_entropy(data_bytes):
    if not data_bytes or len(data_bytes) == 0:
        return 0.0
    counts = {}
    for b in data_bytes:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    total = len(data_bytes)
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(float(entropy), 3)

def extract_packet_features(packet, packet_number, base_time=None):
    time_offset = 0.0
    if hasattr(packet, "time"):
        if base_time is not None:
            time_offset = round(float(packet.time) - float(base_time), 4)
        else:
            time_offset = round(float(packet.time), 4)

    raw_bytes = bytes(packet)
    payload_bytes = b""
    if packet.haslayer(Raw):
        payload_bytes = bytes(packet[Raw].load)
    elif len(raw_bytes) > 20:
        payload_bytes = raw_bytes[20:]

    entropy = calculate_shannon_entropy(payload_bytes if payload_bytes else raw_bytes)

    features = {
        "packet_number": packet_number,
        "time_offset": max(0.0, time_offset),
        "packet_length": len(packet),
        "payload_length": len(payload_bytes),
        "shannon_entropy": entropy,
        "ip_version": None,
        "ip_protocol_number": None,
        "src_ip": None,
        "dst_ip": None,
        "transport_protocol": "OTHER",
        "app_protocol": "UNKNOWN",
        "src_port": 0,
        "dst_port": 0,
        "spi": None,
        "seq_num": None,
        "ike_candidate": False,
        "esp": False,
        "ah": False,
        "http": False,
        "tls": False,
        "ssh": False,
        "icmp": False,
        "dns": False,
        "info": ""
    }

    # IP Layer
    ip_payload = b""
    if packet.haslayer(IP):
        ip = packet[IP]
        features["ip_version"] = 4
        features["ip_protocol_number"] = int(ip.proto)
        features["src_ip"] = str(ip.src)
        features["dst_ip"] = str(ip.dst)
        ip_payload = bytes(ip.payload)
    elif packet.haslayer(IPv6):
        ip = packet[IPv6]
        features["ip_version"] = 6
        features["ip_protocol_number"] = int(ip.nh)
        features["src_ip"] = str(ip.src)
        features["dst_ip"] = str(ip.dst)
        ip_payload = bytes(ip.payload)

    # 1. IPsec ESP (Protocol 50)
    if packet.haslayer(ESP) or features["ip_protocol_number"] == 50:
        features["esp"] = True
        features["transport_protocol"] = "ESP"
        features["app_protocol"] = "IPsec ESP"
        
        # Extract SPI & Sequence Number directly from bytes or layer
        if packet.haslayer(ESP):
            esp_layer = packet[ESP]
            if hasattr(esp_layer, "spi"):
                features["spi"] = f"0x{esp_layer.spi:08x}"
            if hasattr(esp_layer, "seq"):
                features["seq_num"] = int(esp_layer.seq)
        elif len(ip_payload) >= 8:
            try:
                spi_val, seq_val = struct.unpack("!II", ip_payload[:8])
                features["spi"] = f"0x{spi_val:08x}"
                features["seq_num"] = int(seq_val)
            except Exception:
                pass

        spi_str = f" SPI={features['spi']}" if features["spi"] else ""
        seq_str = f" Seq={features['seq_num']}" if features["seq_num"] is not None else ""
        features["info"] = f"Encrypted Security Payload (ESP){spi_str}{seq_str} (H={entropy:.2f} b/B)"

    # 2. IPsec AH (Protocol 51)
    elif packet.haslayer(AH) or features["ip_protocol_number"] == 51:
        features["ah"] = True
        features["transport_protocol"] = "AH"
        features["app_protocol"] = "IPsec AH"
        if packet.haslayer(AH):
            ah_layer = packet[AH]
            if hasattr(ah_layer, "spi"):
                features["spi"] = f"0x{ah_layer.spi:08x}"
            if hasattr(ah_layer, "seq"):
                features["seq_num"] = int(ah_layer.seq)
        elif len(ip_payload) >= 8:
            try:
                _, _, spi_val, seq_val = struct.unpack("!BBHI", ip_payload[:8])
                features["spi"] = f"0x{spi_val:08x}"
                features["seq_num"] = int(seq_val)
            except Exception:
                pass
        spi_str = f" SPI={features['spi']}" if features["spi"] else ""
        features["info"] = f"Authentication Header (AH){spi_str} (Unencrypted Integrity Only)"

    # 3. TCP & Layer 7 Protocols
    elif packet.haslayer(TCP):
        tcp = packet[TCP]
        features["transport_protocol"] = "TCP"
        features["src_port"] = int(tcp.sport)
        features["dst_port"] = int(tcp.dport)
        
        # Check HTTP
        is_http = False
        if tcp.sport in (80, 8080, 8000) or tcp.dport in (80, 8080, 8000):
            is_http = True
        elif payload_bytes and any(payload_bytes.startswith(v) for v in (b"GET ", b"POST ", b"HTTP/", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ")):
            is_http = True

        if is_http:
            features["http"] = True
            features["app_protocol"] = "HTTP"
            if payload_bytes:
                try:
                    first_line = payload_bytes.split(b"\r\n")[0].decode("utf-8", errors="ignore")
                    features["info"] = first_line[:60]
                except Exception:
                    features["info"] = f"HTTP (Port {tcp.sport} -> {tcp.dport})"
            else:
                features["info"] = f"HTTP (Port {tcp.sport} -> {tcp.dport})"

        elif tcp.sport == 443 or tcp.dport == 443 or (payload_bytes and payload_bytes[:1] == b"\x16" and payload_bytes[1:3] in (b"\x03\x01", b"\x03\x02", b"\x03\x03")):
            features["tls"] = True
            features["app_protocol"] = "TLS/HTTPS"
            features["info"] = f"TLS/HTTPS (Port {tcp.sport} -> {tcp.dport})"

        elif tcp.sport == 22 or tcp.dport == 22 or (payload_bytes and payload_bytes.startswith(b"SSH-")):
            features["ssh"] = True
            features["app_protocol"] = "SSH"
            features["info"] = f"SSH Remote Session (Port {tcp.sport} -> {tcp.dport})"
        else:
            features["app_protocol"] = "TCP"
            features["info"] = f"TCP {tcp.sport} -> {tcp.dport}"

    # 4. UDP & IKEv2 / DNS
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        features["transport_protocol"] = "UDP"
        features["src_port"] = int(udp.sport)
        features["dst_port"] = int(udp.dport)

        if udp.sport in (500, 4500) or udp.dport in (500, 4500):
            features["ike_candidate"] = True
            features["transport_protocol"] = "IKE"
            features["app_protocol"] = "IKEv2"
            if udp.sport == 4500 or udp.dport == 4500:
                features["info"] = f"IKE NAT-T (UDP {udp.sport} -> {udp.dport})"
            else:
                features["info"] = f"IKE ISAKMP (UDP {udp.sport} -> {udp.dport})"
        elif packet.haslayer(DNS) or udp.sport == 53 or udp.dport == 53:
            features["dns"] = True
            features["transport_protocol"] = "DNS"
            features["app_protocol"] = "DNS"
            features["info"] = f"DNS Query/Response (UDP {udp.sport} -> {udp.dport})"
        else:
            features["app_protocol"] = "UDP"
            features["info"] = f"UDP {udp.sport} -> {udp.dport}"

    # 5. ICMP
    elif packet.haslayer(ICMP):
        features["transport_protocol"] = "ICMP"
        features["app_protocol"] = "ICMP"
        features["icmp"] = True
        features["info"] = "ICMP Control / Ping Message"

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
