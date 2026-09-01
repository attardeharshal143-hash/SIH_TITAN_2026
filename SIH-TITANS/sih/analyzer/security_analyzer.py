import json
import sys
from pathlib import Path

def assess_security(features, ike_map=None):
    total = len(features)
    if total == 0:
        return {
            "packets_analyzed": 0,
            "security_grade": "N/A",
            "compliance_status": "NO TRAFFIC (Empty Capture)",
            "risk_score": 0,
            "risk_level": "INFO",
            "ipsec_tunnel_detected": False,
            "cryptographic_posture": {
                "encryption_enforced": False,
                "authentication_only_ah": False,
                "ike_negotiation_captured": False,
                "distinct_spis": [],
                "spi_count": 0,
                "status_text": "No network packets found in capture file."
            },
            "leakage_assessment": {
                "is_vpn_leak": False,
                "cleartext_packets": 0,
                "leakage_percentage": 0.0,
                "leaked_protocols": []
            },
            "anti_replay_audit": {
                "sequence_integrity": "N/A",
                "replay_risk": "NONE"
            },
            "mtu_fragmentation_audit": {
                "avg_packet_size": 0,
                "max_packet_size": 0,
                "fragmentation_risk": "LOW"
            },
            "findings": ["No network packets found in capture file."],
            "remediations": ["Verify network capture file integrity and re-upload."]
        }

    esp_packets = [f for f in features if f.get("esp")]
    ah_packets = [f for f in features if f.get("ah")]
    ike_packets = [f for f in features if f.get("ike_candidate")]
    
    http_packets = [f for f in features if f.get("http")]
    tls_packets = [f for f in features if f.get("tls")]
    ssh_packets = [f for f in features if f.get("ssh")]
    dns_packets = [f for f in features if f.get("dns")]
    icmp_packets = [f for f in features if f.get("icmp")]
    other_tcp = [f for f in features if f.get("transport_protocol") == "TCP" and not f.get("http") and not f.get("tls") and not f.get("ssh")]
    other_udp = [f for f in features if f.get("transport_protocol") == "UDP" and not f.get("ike_candidate") and not f.get("dns")]

    esp_count = len(esp_packets)
    ah_count = len(ah_packets)
    ike_count = len(ike_packets)
    
    ipsec_detected = (esp_count > 0 or ah_count > 0 or ike_count > 0)
    non_ipsec_count = total - esp_count - ah_count - ike_count

    # 1. Real SPI Discovery
    distinct_spis = sorted(list(set(f["spi"] for f in features if f.get("spi"))))

    # 2. Real Anti-Replay Sequence Validation (Grouped per Security Association / SPI)
    spis_seq_map = {}
    for f in esp_packets:
        spi_key = f.get("spi", "default")
        if f.get("seq_num") is not None:
            spis_seq_map.setdefault(spi_key, []).append(f["seq_num"])

    duplicates = 0
    is_monotonic = True
    total_tracked_seqs = 0
    for spi_key, seqs in spis_seq_map.items():
        total_tracked_seqs += len(seqs)
        dup_count = len(seqs) - len(set(seqs))
        duplicates += dup_count
        if len(seqs) > 1:
            if not all(seqs[i] < seqs[i+1] for i in range(len(seqs) - 1)):
                is_monotonic = False

    if duplicates > 0:
        anti_replay_status = f"VULNERABLE ({duplicates} Duplicate Sequence Numbers Detected across SAs)"
        replay_risk = "HIGH"
    elif is_monotonic and total_tracked_seqs > 0:
        anti_replay_status = f"SYNCHRONIZED (Strictly Monotonic Sequence 1..{total_tracked_seqs} verified across {len(spis_seq_map)} SAs, 0 replays)"
        replay_risk = "LOW"
    elif total_tracked_seqs > 0:
        anti_replay_status = f"VALID (Packets within window across {len(spis_seq_map)} SAs)"
        replay_risk = "LOW"
    else:
        anti_replay_status = "N/A (No ESP Sequence Headers)"
        replay_risk = "NONE"

    # 3. Real Shannon Entropy Averages
    esp_entropies = [f.get("shannon_entropy", 0.0) for f in esp_packets]
    avg_esp_entropy = round(sum(esp_entropies) / len(esp_entropies), 2) if esp_entropies else 0.0

    # Summarize observed application protocols
    observed_protocols = []
    if esp_count > 0: observed_protocols.append(f"IPsec ESP ({esp_count})")
    if ah_count > 0: observed_protocols.append(f"IPsec AH ({ah_count})")
    if ike_count > 0: observed_protocols.append(f"IKEv2/NAT-T ({ike_count})")
    if len(http_packets) > 0: observed_protocols.append(f"HTTP Plaintext ({len(http_packets)})")
    if len(tls_packets) > 0: observed_protocols.append(f"TLS/HTTPS ({len(tls_packets)})")
    if len(ssh_packets) > 0: observed_protocols.append(f"SSH ({len(ssh_packets)})")
    if len(dns_packets) > 0: observed_protocols.append(f"DNS ({len(dns_packets)})")
    if len(icmp_packets) > 0: observed_protocols.append(f"ICMP ({len(icmp_packets)})")
    if len(other_tcp) > 0: observed_protocols.append(f"Generic TCP ({len(other_tcp)})")
    if len(other_udp) > 0: observed_protocols.append(f"Generic UDP ({len(other_udp)})")

    findings = []
    remediations = []

    # =========================================================================
    # CASE 1: NON-IPSEC / STANDARD NETWORK TRAFFIC (Zero VPN protocols)
    # =========================================================================
    if not ipsec_detected:
        risk_score = 15 if len(http_packets) > 0 else 10
        security_grade = "B"
        compliance_status = "NON-IPSEC TRAFFIC (Standard Application Stream)"
        risk_level = "LOW (Standard Non-VPN Traffic)"

        findings.append(f"Standard non-VPN network traffic evaluated ({total} frames analyzed).")
        findings.append(f"Observed Application Protocols: {', '.join(observed_protocols)}.")
        findings.append("No IPsec ESP (Protocol 50), AH (Protocol 51), or IKE key exchanges were observed in this capture stream.")
        
        if len(http_packets) > 0:
            findings.append(f"Cleartext Web Communication: {len(http_packets)} plain HTTP packets detected (Port 80 / Unencrypted GET/POST).")
            remediations.append("Migrate plain HTTP web endpoints to TLS/HTTPS (Port 443) or encapsulate across a site-to-site IPsec VPN tunnel.")
        else:
            remediations.append("If this traffic was intended to transit a secure IPsec tunnel, configure gateway firewall policies to enforce ESP encapsulation.")

        return {
            "packets_analyzed": total,
            "security_grade": security_grade,
            "compliance_status": compliance_status,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "ipsec_tunnel_detected": False,
            "cryptographic_posture": {
                "encryption_enforced": False,
                "authentication_only_ah": False,
                "ike_negotiation_captured": False,
                "distinct_spis": [],
                "spi_count": 0,
                "avg_entropy_bits": 0.0,
                "status_text": "No IPsec VPN tunnel detected in capture stream."
            },
            "leakage_assessment": {
                "is_vpn_leak": False,
                "cleartext_packets": non_ipsec_count,
                "leakage_percentage": 0.0,
                "leaked_protocols": observed_protocols,
                "details": "Traffic consists of standard unencapsulated application flows (not a VPN tunnel leak)."
            },
            "anti_replay_audit": {
                "sequence_integrity": "N/A (Non-IPsec)",
                "replay_risk": "NONE"
            },
            "mtu_fragmentation_audit": {
                "avg_packet_size": round(sum(f.get("packet_length", 0) for f in features) / total, 1),
                "max_packet_size": max(f.get("packet_length", 0) for f in features),
                "fragmentation_risk": "LOW"
            },
            "findings": findings,
            "remediations": remediations
        }

    # =========================================================================
    # CASE 2: IPSEC TRAFFIC DETECTED (Pure VPN or Mixed Split-Tunnel)
    # =========================================================================
    risk_score = 10
    
    if esp_count > 0:
        findings.append(f"ESP Payload Encryption Verified: {esp_count} encrypted frames ({round(esp_count/total*100, 1)}% of capture, Mean Entropy: {avg_esp_entropy} bits/byte).")
        if non_ipsec_count == 0:
            findings.append("Full Encapsulation: 100% of captured traffic is encapsulated within secure IPsec tunnel.")
    
    if distinct_spis:
        findings.append(f"Active Security Association SPIs: {', '.join(distinct_spis)}.")

    if ike_count > 0:
        findings.append(f"IKE Handshake Observed: {ike_count} key exchange negotiation packets detected on UDP 500/4500.")
    elif esp_count > 0:
        findings.append("Established Tunnel Trace: Initial IKE negotiation was completed prior to this capture window.")

    if ah_count > 0:
        risk_score += 30
        findings.append(f"Authentication Header (AH) Active: {ah_count} packets use Protocol 51. (Note: AH provides integrity but NO data encryption).")
        remediations.append("Migrate from AH (Protocol 51) to ESP (Protocol 50) with AES-GCM-256 for full confidentiality.")

    if duplicates > 0:
        risk_score += 35
        findings.append(f"CRITICAL: Anti-Replay Alert - {duplicates} duplicate ESP sequence numbers detected.")
        remediations.append("Verify Anti-Replay window synchronization on gateway to prevent packet injection attacks.")

    # Check for any weak cipher / DH group negotiation across all parsed IKE proposals
    has_crypto_downgrade = False
    if ike_map:
        for k, prop in ike_map.items():
            if isinstance(prop, dict) and prop.get("has_real_proposals"):
                encr = prop.get("encryption_algorithm") or ""
                dh = prop.get("dh_group") or ""
                dh_bits = prop.get("dh_bits") or 2048
                key_bits = prop.get("key_length") or 256
                if "DES" in encr or "3DES" in encr or key_bits < 128 or (dh_bits < 2048 and "Curve" not in dh and "ML-KEM" not in dh and "Kyber" not in dh):
                    has_crypto_downgrade = True
                    findings.append(f"CRITICAL: Cryptographic Downgrade Attack Detected: IKE handshake negotiated weak suite {encr} ({key_bits}b) / {dh}.")
                    remediations.append("Upgrade Phase 1 and Phase 2 proposals to AES-256-GCM and Diffie-Hellman Group 14+ or Curve25519.")

    if has_crypto_downgrade:
        risk_score = max(risk_score + 65, 75)

    # True Leakage Check
    leak_pct = round((non_ipsec_count / total) * 100, 1) if ipsec_detected else 0.0
    leaked_protos = [p for p in observed_protocols if "IPsec" not in p and "IKE" not in p]

    if non_ipsec_count > 0:
        risk_score += min(50, int(leak_pct * 0.5))
        findings.append(f"Split-Tunneling / Plaintext Leakage: {non_ipsec_count} unencrypted packets ({leak_pct}%) observed outside the active IPsec tunnel.")
        remediations.append("Enforce strict split-tunnel prevention policies so all enterprise traffic is routed through the IPsec ESP tunnel.")

    if has_crypto_downgrade:
        security_grade = "C" if risk_score <= 75 else "F"
        compliance_status = "NON-COMPLIANT (Cryptographic Downgrade Detected)"
        risk_level = "HIGH" if risk_score <= 75 else "CRITICAL"
    elif risk_score <= 15:
        security_grade = "A+"
        compliance_status = "COMPLIANT (NIST SP 800-77 & NSA CNSA 2.0)"
        risk_level = "LOW"
    elif risk_score <= 30:
        security_grade = "A"
        compliance_status = "COMPLIANT WITH MINOR WARNINGS"
        risk_level = "LOW"
    elif risk_score <= 50:
        security_grade = "B"
        compliance_status = "PARTIALLY COMPLIANT"
        risk_level = "MEDIUM"
    elif risk_score <= 75:
        security_grade = "C"
        compliance_status = "NON-COMPLIANT (Vulnerabilities Detected)"
        risk_level = "HIGH"
    else:
        security_grade = "F"
        compliance_status = "CRITICAL NON-COMPLIANCE"
        risk_level = "CRITICAL"

    return {
        "packets_analyzed": total,
        "security_grade": security_grade,
        "compliance_status": compliance_status,
        "risk_score": min(100, risk_score),
        "risk_level": risk_level,
        "ipsec_tunnel_detected": True,
        "cryptographic_posture": {
            "encryption_enforced": esp_count > 0,
            "authentication_only_ah": (ah_count > 0 and esp_count == 0),
            "ike_negotiation_captured": ike_count > 0,
            "distinct_spis": distinct_spis,
            "spi_count": len(distinct_spis),
            "avg_entropy_bits": avg_esp_entropy,
            "status_text": "IPsec Encapsulation Active"
        },
        "leakage_assessment": {
            "is_vpn_leak": non_ipsec_count > 0,
            "cleartext_packets": non_ipsec_count,
            "leakage_percentage": leak_pct,
            "leaked_protocols": leaked_protos
        },
        "anti_replay_audit": {
            "sequence_integrity": anti_replay_status,
            "replay_risk": replay_risk,
            "duplicate_sequences": duplicates
        },
        "mtu_fragmentation_audit": {
            "avg_packet_size": round(sum(f.get("packet_length", 0) for f in features) / total, 1),
            "max_packet_size": max(f.get("packet_length", 0) for f in features),
            "fragmentation_risk": "LOW"
        },
        "findings": findings,
        "remediations": remediations
    }
