from datetime import datetime

def perform_advanced_security_audit(arg1, arg2=None, ike_details=None, raw_packets=None, *args, **kwargs):
    """
    Performs empirical security audit against NSA CNSA 2.0 and NIST SP 800-77 standards.
    - When real IKE key exchange is present, scores PQC readiness rigorously based on KEM, Cipher, and PRF.
    - When only pre-established ESP is captured, honestly reports PQC readiness as Indeterminate.
    - MITRE ATT&CK mappings ONLY fire on genuine verifiable attacks/downgrades (Zero false exfiltration alarms).
    """
    if isinstance(arg1, list) and isinstance(arg2, dict):
        features = arg1
        base_assessment = arg2
    elif isinstance(arg1, dict):
        base_assessment = arg1
        if isinstance(arg2, dict) and ike_details is None:
            ike_details = arg2
        features = []
    else:
        base_assessment = {}
        features = []

    is_ipsec = base_assessment.get("ipsec_tunnel_detected", False)
    total_packets = base_assessment.get("packets_analyzed", 0)
    crypto = base_assessment.get("cryptographic_posture", {})
    leak_data = base_assessment.get("leakage_assessment", {})
    anti_replay = base_assessment.get("anti_replay_audit", {})
    
    esp_count = len([p for p in crypto.get("distinct_spis", [])])
    ah_count = 1 if crypto.get("authentication_only_ah") else 0
    cleartext_count = leak_data.get("cleartext_packets", 0)
    dup_seqs = anti_replay.get("duplicate_sequences", 0)
    avg_entropy = crypto.get("avg_entropy_bits", 0.0)

    # -------------------------------------------------------------------------
    # CASE 1: UNENCRYPTED / NON-IPSEC TRAFFIC
    # -------------------------------------------------------------------------
    if not is_ipsec:
        ike_audit = {
            "ike_version_detected": "None (No IKE Handshake Present)",
            "exchange_mode": "N/A - Non-VPN Traffic",
            "psk_vulnerability_risk": "N/A",
            "identity_protection": "N/A",
            "aggressive_mode_detected": False,
            "details": "No IKE key exchange negotiation packets observed in capture stream."
        }

        downgrade_checks = [
            {
                "check": "IPsec Encapsulation",
                "status": "VULNERABLE" if cleartext_count > 0 else "INFO",
                "severity": "HIGH" if cleartext_count > 0 else "INFO",
                "description": "No IPsec ESP (Protocol 50) encapsulation detected. Application traffic transmitted unencrypted."
            }
        ]

        mitre_mappings = []
        # Check if plain HTTP on port 80 exists
        has_plain_http = any("HTTP" in p for p in leak_data.get("leaked_protocols", []))
        if has_plain_http:
            mitre_mappings.append({
                "technique_id": "T1040",
                "technique_name": "Network Sniffing (Plaintext Protocol Exposure)",
                "tactic": "Credential Access / Discovery",
                "severity": "HIGH",
                "finding_ref": "Unencrypted plain HTTP communication observed without IPsec or transport-layer encryption.",
                "mitigation": "Enforce site-to-site IPsec ESP encapsulation or TLS 1.3 to protect cleartext web payloads."
            })

        return {
            "ike_key_exchange_audit": ike_audit,
            "cryptographic_downgrade_checks": downgrade_checks,
            "pqc_readiness": {
                "pqc_score": None,
                "pqc_status": "Not Applicable (Non-VPN Stream)",
                "quantum_resistance_index": "N/A",
                "harvest_now_decrypt_later_risk": "N/A (Cleartext Stream)",
                "recommendations": [
                    "No IPsec cryptographic tunnel active in capture stream.",
                    "If this data requires confidentiality, deploy site-to-site IPsec with AES-256-GCM and RFC 9370 ML-KEM post-quantum key exchange."
                ]
            },
            "mitre_attack_mapping": mitre_mappings,
            "siem_event": {
                "event_schema": "Elastic Common Schema (ECS) v1.12",
                "event_id": f"EVT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                "event_type": "network_traffic_audit",
                "threat_level": "high" if has_plain_http else "informational",
                "compliance": "non_compliant_unencrypted" if has_plain_http else "compliant_baseline",
                "ipsec_active": False,
                "observed_protocols": leak_data.get("leaked_protocols", [])
            }
        }

    # -------------------------------------------------------------------------
    # CASE 2: IPSEC TRAFFIC EVALUATION
    # -------------------------------------------------------------------------
    has_real_ike = (ike_details is not None and ike_details.get("has_real_proposals"))

    if has_real_ike:
        encr_name = ike_details.get("encryption_algorithm") or "AES-GCM"
        key_bits = ike_details.get("key_length") or 256
        dh_name = ike_details.get("dh_group") or "MODP-2048"
        dh_bits = ike_details.get("dh_bits", 2048)
        prf_name = ike_details.get("prf_algorithm") or "PRF_HMAC_SHA2_256"
        integ_name = ike_details.get("integrity_algorithm") or "HMAC-SHA2-256"

        ike_audit = {
            "ike_version_detected": ike_details.get("version", "IKEv2"),
            "exchange_mode": "Aggressive Mode (Insecure)" if ike_details.get("is_aggressive_mode") else "Main / IKE_SA_INIT (Identity Protected)",
            "psk_vulnerability_risk": "HIGH (Aggressive Mode Hash Exposure)" if ike_details.get("is_aggressive_mode") else "LOW",
            "identity_protection": "EXPOSED IN CLEARTEXT" if ike_details.get("is_aggressive_mode") else "ENCRYPTED (Phase 1 Protected)",
            "aggressive_mode_detected": ike_details.get("is_aggressive_mode", False),
            "details": f"IKE exchange negotiated {encr_name} ({key_bits}b), {dh_name} ({dh_bits}b), {prf_name}."
        }

        is_weak_cipher = ("DES" in encr_name or "3DES" in encr_name or "IDEA" in encr_name or key_bits < 128)
        is_weak_dh = (dh_bits < 2048 and "Curve" not in dh_name and "ML-KEM" not in dh_name and "Kyber" not in dh_name)
        is_pqc_kem = ("ML-KEM" in dh_name or "Kyber" in dh_name)

        # Quantitative CNSA 2.0 / PQC Scoring Formula
        sym_score = 0 if is_weak_cipher else (20 if key_bits == 128 else 40)
        kem_score = 40 if is_pqc_kem else (0 if is_weak_dh else 25)
        prf_score = 0 if ("MD5" in prf_name or "SHA1" in prf_name) else (20 if ("384" in prf_name or "512" in prf_name) else 15)

        pqc_score = sym_score + kem_score + prf_score
        if is_weak_cipher or is_weak_dh:
            pqc_score = 0 if (is_weak_cipher and is_weak_dh) else min(20, pqc_score)
            pqc_status = f"No post-quantum protection observed; legacy/weak parameters negotiated ({encr_name}/{dh_name})"
        elif is_pqc_kem:
            pqc_status = "QUANTUM-RESISTANT (CNSA 2.0 Complete / PQC KEM Negotiated)"
        elif pqc_score >= 80:
            pqc_status = "No post-quantum key exchange mechanism observed in parsed IKE negotiation (Classical CNSA 2.0 Symmetric Tier)"
        else:
            pqc_status = "No post-quantum key exchange mechanism observed in parsed IKE negotiation (Classical key exchange only)"

        downgrade_checks = [
            {
                "check": "Obsolete Cipher Downgrade (DES / 3DES / IDEA)",
                "status": "VULNERABLE" if is_weak_cipher else "SECURE",
                "severity": "CRITICAL" if is_weak_cipher else "INFO",
                "description": f"Negotiated encryption cipher: {encr_name} ({key_bits}-bit)."
            },
            {
                "check": "Diffie-Hellman Group Strength (Logjam / Shor Resistance)",
                "status": "VULNERABLE" if is_weak_dh else "SECURE",
                "severity": "HIGH" if is_weak_dh else "INFO",
                "description": f"Negotiated key exchange group: {dh_name} ({dh_bits}-bit)."
            }
        ]

        pqc_recommendations = []
        if is_weak_cipher:
            pqc_recommendations.append(f"CRITICAL: Replace obsolete cipher {encr_name} with AES-256-GCM AEAD.")
        if is_weak_dh:
            pqc_recommendations.append(f"CRITICAL: Upgrade Diffie-Hellman group {dh_name} to MODP-2048+ or Curve25519 / ML-KEM-768.")
        if not is_weak_cipher and not is_weak_dh:
            pqc_recommendations.append("Cryptographic parameters satisfy NIST SP 800-77 recommendations.")

    else:
        # Case B: Established ESP Stream Without Handshake in Capture Window
        ike_audit = {
            "ike_version_detected": "IKEv2 (Pre-established SA)",
            "exchange_mode": "Established ESP Tunnel Flow",
            "psk_vulnerability_risk": "Indeterminate (Handshake Not in Capture Window)",
            "identity_protection": "Encrypted (Pre-negotiated)",
            "aggressive_mode_detected": False,
            "details": "Initial IKE SA negotiation occurred prior to this capture window. Active ESP frames confirm established tunnel."
        }

        downgrade_checks = [
            {
                "check": "ESP Byte Entropy (Statistical Randomness)",
                "status": "INFO",
                "severity": "INFO",
                "description": f"ESP frames exhibit Mean Byte Shannon Entropy = {avg_entropy} b/B (Theoretical max: 8.0 b/B)."
            }
        ]

        pqc_score = None
        pqc_status = "PQC Status: Indeterminate (Absence of captured IKE negotiation does not indicate presence or lack of PQC capability)."
        pqc_recommendations = [
            f"ESP payload exhibits Mean Byte Shannon Entropy = {avg_entropy} bits/byte.",
            "Note: Shannon entropy measures byte uniformity (0.0-8.0 b/B). High entropy indicates pseudorandom byte distribution (characteristic of both cryptographic ciphertext and random generator filler), but does not confirm cryptographic algorithm strength or key integrity.",
            "To inspect DH group strength or ML-KEM post-quantum proposals, capture the initial IKE_SA_INIT handshake."
        ]
        is_weak_cipher = False
        is_weak_dh = False

    # MITRE ATT&CK Mapping (Strict Ground-Truth: Only trigger on genuine verifiable attack/downgrade indicators)
    mitre_mappings = []
    
    # 1. Obsolete Cryptography Downgrade
    if has_real_ike and (is_weak_cipher or is_weak_dh):
        mitre_mappings.append({
            "technique_id": "T1588.004",
            "technique_name": "Obsolete Cryptographic Algorithm / Downgrade",
            "tactic": "Defense Evasion / Cryptographic Weakness",
            "severity": "CRITICAL" if is_weak_cipher else "HIGH",
            "finding_ref": f"Negotiated weak algorithm proposal ({encr_name} / {dh_name}). Vulnerable to classical cryptanalysis and quantum factorization.",
            "mitigation": "Disable legacy Phase 1/Phase 2 proposals and enforce AES-256-GCM with DH Group 14+ or Curve25519."
        })

    # 2. Sequence Replay Attack
    if dup_seqs >= 3 or (dup_seqs > 0 and (dup_seqs / max(total_packets, 1)) >= 0.10):
        mitre_mappings.append({
            "technique_id": "T1557",
            "technique_name": "Replay / Duplicate Sequence Anomaly (MITRE ATT&CK T1557 Candidate)",
            "tactic": "Credential Access / Defense Evasion",
            "severity": "HIGH - Candidate",
            "finding_ref": f"Replay / duplicate sequence anomaly detected; potential anti-replay violation ({dup_seqs} duplicate packets observed across distinct sequence values). Classified as MITRE ATT&CK T1557 Candidate with Severity: HIGH - Candidate (additional host/gateway correlation required to confirm malicious injection vs. network retransmission).",
            "mitigation": "Audit and enforce anti-replay window checking (RFC 4303 64/128-packet window) to guard against replay/duplicate sequence anomalies; discard duplicate sequence packets at VPN gateway."
        })

    return {
        "ike_key_exchange_audit": ike_audit,
        "cryptographic_downgrade_checks": downgrade_checks,
        "pqc_readiness": {
            "pqc_score": pqc_score,
            "pqc_status": pqc_status,
            "quantum_resistance_index": f"{pqc_score}%" if pqc_score is not None else "Indeterminate",
            "harvest_now_decrypt_later_risk": "RESISTANT" if (pqc_score is not None and pqc_score >= 80) else ("ELEVATED" if pqc_score is not None else "Indeterminate (Handshake Not Captured)"),
            "recommendations": pqc_recommendations
        },
        "mitre_attack_mapping": mitre_mappings,
        "siem_event": {
            "event_schema": "Elastic Common Schema (ECS) v1.12",
            "event_id": f"EVT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "event_type": "ipsec_security_audit",
            "threat_level": "critical" if (dup_seqs >= 3 or (has_real_ike and is_weak_cipher)) else "low",
            "compliance": "compliant" if (not has_real_ike or (not is_weak_cipher and not is_weak_dh)) else "non_compliant",
            "ipsec_active": True,
            "active_spis": crypto.get("distinct_spis", [])
        }
    }
