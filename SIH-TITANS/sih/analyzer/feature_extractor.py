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

    features = {
        "packet_number": packet_number,
        "time_offset": max(0.0, time_offset),
        "packet_length": len(packet),
        "payload_length": 0,
        "shannon_entropy": 0.0,
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

    # 1. IPsec ESP (Protocol 50) - Native L3 Encapsulation
    if packet.haslayer(ESP) or features["ip_protocol_number"] == 50:
        features["esp"] = True
        features["transport_protocol"] = "ESP"
        features["app_protocol"] = "IPsec ESP"
        
        esp_payload_data = b""
        if packet.haslayer(ESP):
            esp_layer = packet[ESP]
            if hasattr(esp_layer, "spi"):
                features["spi"] = f"0x{esp_layer.spi:08x}"
            if hasattr(esp_layer, "seq"):
                features["seq_num"] = int(esp_layer.seq)
            
            # Extract isolated ciphertext payload (excluding 8-byte SPI and Seq headers)
            if hasattr(esp_layer, "data") and esp_layer.data:
                esp_payload_data = bytes(esp_layer.data)
            elif len(bytes(esp_layer)) > 8:
                esp_payload_data = bytes(esp_layer)[8:]
        elif len(ip_payload) >= 8:
            try:
                spi_val, seq_val = struct.unpack("!II", ip_payload[:8])
                features["spi"] = f"0x{spi_val:08x}"
                features["seq_num"] = int(seq_val)
                esp_payload_data = ip_payload[8:]
            except Exception:
                pass

        features["payload_length"] = len(esp_payload_data)
        features["shannon_entropy"] = calculate_shannon_entropy(esp_payload_data)
        features["info"] = f"ESP Encapsulated Payload (SPI: {features['spi']}, Seq: {features['seq_num']})"
        return features

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
        elif len(ip_payload) >= 12:
            try:
                spi_val, seq_val = struct.unpack("!II", ip_payload[4:12])
                features["spi"] = f"0x{spi_val:08x}"
                features["seq_num"] = int(seq_val)
            except Exception:
                pass

        features["payload_length"] = len(ip_payload)
        features["shannon_entropy"] = calculate_shannon_entropy(ip_payload)
        features["info"] = f"AH Header (SPI: {features['spi']}, Seq: {features['seq_num']}) - Integrity Only"
        return features

    # 3. Transport Layers (TCP / UDP / ICMP)
    payload_bytes = b""
    if packet.haslayer(UDP):
        payload_bytes = bytes(packet[UDP].payload) if hasattr(packet[UDP], "payload") else b""
    elif packet.haslayer(TCP):
        payload_bytes = bytes(packet[TCP].payload) if hasattr(packet[TCP], "payload") else b""
    elif packet.haslayer(Raw):
        payload_bytes = bytes(packet[Raw].load)
    elif len(raw_bytes) > 20:
        payload_bytes = raw_bytes[20:]

    features["payload_length"] = len(payload_bytes)
    features["shannon_entropy"] = calculate_shannon_entropy(payload_bytes)

    if packet.haslayer(UDP):
        features["transport_protocol"] = "UDP"
        features["src_port"] = int(packet[UDP].sport)
        features["dst_port"] = int(packet[UDP].dport)

        # RFC 3948: NAT-T UDP 4500 Disambiguation (IKE vs Encapsulated ESP)
        if (features["src_port"] == 4500 or features["dst_port"] == 4500) and len(payload_bytes) >= 8:
            if payload_bytes.startswith(b"\x00\x00\x00\x00"):
                # Non-ESP Marker present -> IKE negotiation over NAT-T
                features["ike_candidate"] = True
                features["app_protocol"] = "IKEv2 / NAT-T"
                features["info"] = "IKE Key Exchange over UDP 4500 (Non-ESP Marker)"
            else:
                # Non-ESP Marker absent -> First 4 bytes are SPI (RFC 3948 ESP in UDP)
                try:
                    spi_val, seq_val = struct.unpack("!II", payload_bytes[:8])
                    features["esp"] = True
                    features["transport_protocol"] = "ESP"
                    features["app_protocol"] = "IPsec ESP (NAT-T / UDP 4500)"
                    features["spi"] = f"0x{spi_val:08x}"
                    features["seq_num"] = int(seq_val)
                    esp_ciphertext = payload_bytes[8:]
                    features["payload_length"] = len(esp_ciphertext)
                    features["shannon_entropy"] = calculate_shannon_entropy(esp_ciphertext)
                    features["info"] = f"NAT-T ESP Payload (SPI: {features['spi']}, Seq: {features['seq_num']})"
                    return features
                except Exception:
                    features["ike_candidate"] = True
                    features["app_protocol"] = "IKE / NAT-T"
        elif features["src_port"] == 500 or features["dst_port"] == 500:
            features["ike_candidate"] = True
            features["app_protocol"] = "IKE Key Exchange (UDP 500)"
            features["info"] = f"IKE Key Exchange (Port {features['dst_port']})"
        elif features["src_port"] == 53 or features["dst_port"] == 53 or packet.haslayer(DNS):
            features["dns"] = True
            features["app_protocol"] = "DNS"
            features["info"] = "DNS Resolution Query/Response"
        else:
            features["app_protocol"] = f"UDP/{features['dst_port']}"
            features["info"] = f"UDP Datagram {features['src_port']} -> {features['dst_port']}"

    elif packet.haslayer(TCP):
        features["transport_protocol"] = "TCP"
        features["src_port"] = int(packet[TCP].sport)
        features["dst_port"] = int(packet[TCP].dport)

        if features["src_port"] == 80 or features["dst_port"] == 80:
            features["http"] = True
            features["app_protocol"] = "HTTP"
            features["info"] = "HTTP Plaintext Web Communication"
        elif features["src_port"] == 443 or features["dst_port"] == 443:
            features["tls"] = True
            features["app_protocol"] = "TLS/HTTPS"
            features["info"] = "TLS Encrypted Transport"
        elif features["src_port"] == 22 or features["dst_port"] == 22:
            features["ssh"] = True
            features["app_protocol"] = "SSH"
            features["info"] = "SSH Remote Session"
        else:
            features["app_protocol"] = f"TCP/{features['dst_port']}"
            features["info"] = f"TCP Stream {features['src_port']} -> {features['dst_port']}"

    elif packet.haslayer(ICMP):
        features["transport_protocol"] = "ICMP"
        features["icmp"] = True
        features["app_protocol"] = "ICMP"
        features["info"] = "ICMP Diagnostic Message"

    return features

def extract_pcap_features(pcap_path):
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        return []
    
    try:
        packets = rdpcap(str(pcap_path))
    except Exception:
        return []

    if not packets:
        return []

    base_time = float(packets[0].time) if hasattr(packets[0], "time") else 0.0
    features_list = []
    for idx, pkt in enumerate(packets):
        feat = extract_packet_features(pkt, idx + 1, base_time=base_time)
        features_list.append(feat)

    return features_list
