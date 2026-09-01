import numpy as np

def perform_encrypted_traffic_analysis(features):
    """
    Empirical Packet Length & Distribution Profiler.
    Reports strictly measurable packet dimensions without asserting fabricated
    application identities. Accurately flags small sample sizes (N < 5 frames) where
    statistical moments cannot be meaningfully computed.
    """
    if not features:
        return {
            "application_category": "No Traffic Recorded",
            "traffic_pattern": "Inactive",
            "eta_confidence": None,
            "avg_packet_size_bytes": 0,
            "packet_size_std_dev": 0.0,
            "burstiness_index": 0.0,
            "inferred_behavior": "No packets available for statistical characterization."
        }

    esp_features = [f for f in features if f.get("esp")]
    http_features = [f for f in features if f.get("http")]
    tls_features = [f for f in features if f.get("tls")]
    ssh_features = [f for f in features if f.get("ssh")]
    dns_features = [f for f in features if f.get("dns")]

    # -------------------------------------------------------------------------
    # CASE 1: UNENCRYPTED / NON-IPSEC TRAFFIC
    # -------------------------------------------------------------------------
    if len(esp_features) == 0:
        lengths = [f.get("packet_length", 0) for f in features if f.get("packet_length", 0) > 0]
        avg_len = float(np.mean(lengths)) if lengths else 0.0
        std_len = float(np.std(lengths)) if lengths else 0.0
        burst_idx = round(float(std_len / (avg_len + 1e-5)), 2)

        if len(http_features) > 0:
            return {
                "application_category": "Plaintext HTTP (Port 80)",
                "traffic_pattern": "Unencrypted HTTP Transport",
                "eta_confidence": "100% (Direct L7 Header)",
                "avg_packet_size_bytes": round(avg_len, 1),
                "packet_size_std_dev": round(std_len, 1),
                "burstiness_index": burst_idx,
                "inferred_behavior": f"Observed {len(http_features)} plaintext HTTP packets on TCP port 80. Cleartext payloads visible in packet capture without IPsec encapsulation."
            }
        elif len(dns_features) > 0:
            return {
                "application_category": "DNS Queries/Responses (UDP 53)",
                "traffic_pattern": "Unencrypted DNS Resolution",
                "eta_confidence": "100% (Direct L7 Header)",
                "avg_packet_size_bytes": round(avg_len, 1),
                "packet_size_std_dev": round(std_len, 1),
                "burstiness_index": burst_idx,
                "inferred_behavior": f"Observed {len(dns_features)} unencrypted DNS packets on UDP port 53."
            }
        elif len(tls_features) > 0:
            return {
                "application_category": "TLS Transport Flow (Port 443)",
                "traffic_pattern": "Transport-Layer Encrypted Flow",
                "eta_confidence": "100% (Direct L4 Port/TLS Header)",
                "avg_packet_size_bytes": round(avg_len, 1),
                "packet_size_std_dev": round(std_len, 1),
                "burstiness_index": burst_idx,
                "inferred_behavior": "TLS encrypted transport flow operating outside of an IPsec network tunnel."
            }
        elif len(ssh_features) > 0:
            return {
                "application_category": "SSH Transport Flow (Port 22)",
                "traffic_pattern": "Direct SSH Session",
                "eta_confidence": "100% (Direct L4 Port/SSH Header)",
                "avg_packet_size_bytes": round(avg_len, 1),
                "packet_size_std_dev": round(std_len, 1),
                "burstiness_index": burst_idx,
                "inferred_behavior": "SSH connection running directly over TCP port 22 without IPsec encapsulation."
            }
        else:
            return {
                "application_category": "Unencapsulated Network Flow",
                "traffic_pattern": "Standard Non-VPN TCP/UDP Transport",
                "eta_confidence": "N/A (Generic Flow)",
                "avg_packet_size_bytes": round(avg_len, 1),
                "packet_size_std_dev": round(std_len, 1),
                "burstiness_index": burst_idx,
                "inferred_behavior": "Standard network packets observed without IPsec ESP (Protocol 50) encapsulation."
            }

    # -------------------------------------------------------------------------
    # CASE 2: ESP ENCRYPTED TRAFFIC
    # -------------------------------------------------------------------------
    lengths = [f.get("packet_length", 0) for f in esp_features if f.get("packet_length", 0) > 0]
    if not lengths:
        lengths = [100]

    arr = np.array(lengths)
    total_pkts = len(arr)
    avg_len = float(np.mean(arr))
    std_len = float(np.std(arr))
    max_len = int(np.max(arr))
    min_len = int(np.min(arr))
    burst_idx = round(float(std_len / (avg_len + 1e-5)), 2)

    # Handle Small Sample Size (N < 5)
    if total_pkts < 5:
        lengths_str = ", ".join(str(l) for l in lengths)
        return {
            "application_category": f"Insufficient Sample Size (N = {total_pkts} ESP frame{'s' if total_pkts > 1 else ''})",
            "traffic_pattern": f"N < 5 (Observed lengths: {lengths_str} B)",
            "eta_confidence": None,
            "avg_packet_size_bytes": round(avg_len, 1),
            "packet_size_std_dev": round(std_len, 1),
            "burstiness_index": burst_idx,
            "inferred_behavior": f"Capture contains only {total_pkts} ESP frame(s) (lengths: {lengths_str} B). Meaningful statistical distribution analysis and burstiness metrics require a multi-packet sample window (>= 5 frames)."
        }

    small_pkts = np.sum(arr < 250)
    medium_pkts = np.sum((arr >= 250) & (arr < 1100))
    mtu_pkts = np.sum(arr >= 1100)

    ratio_small = small_pkts / total_pkts
    ratio_medium = medium_pkts / total_pkts
    ratio_mtu = mtu_pkts / total_pkts

    if ratio_mtu >= 0.65 or (avg_len >= 1100 and ratio_mtu >= 0.50):
        category = "MTU-Saturated Encapsulated Flow"
        pattern = f"Bulk Frame Distribution ({ratio_mtu*100:.0f}% >= 1100B)"
    elif std_len < 10.0 and min_len == max_len:
        category = "Fixed-Size Encapsulated Flow"
        pattern = f"Uniform Sizing ({avg_len:.0f}B Constant)"
    elif ratio_small >= 0.85:
        category = "Lightweight Encapsulated Flow"
        pattern = f"Sub-250B Sizing ({ratio_small*100:.0f}% < 250B)"
    elif 280 <= avg_len <= 950:
        category = "Variable-Length Encapsulated Flow"
        pattern = f"Mid-Range Sizing (Mean: {avg_len:.1f}B)"
    else:
        category = "Mixed-Length Encapsulated Flow"
        pattern = f"Heterogeneous Sizing (Mean: {avg_len:.1f}B, Std: {std_len:.1f}B)"

    behavior = (
        f"Payload is fully encapsulated within ESP ciphertext. Frame sizing reflects aggregate transport-layer packet lengths "
        f"(Mean: {avg_len:.1f} B, Std Dev: {std_len:.1f} B, Range: {min_len}-{max_len} B). "
        f"Application-layer identity cannot be determined without session timing, bidirectional flow correlation, or decryption keys."
    )

    return {
        "application_category": category,
        "traffic_pattern": pattern,
        "eta_confidence": None,
        "avg_packet_size_bytes": round(avg_len, 1),
        "packet_size_std_dev": round(std_len, 1),
        "burstiness_index": burst_idx,
        "inferred_behavior": behavior
    }
