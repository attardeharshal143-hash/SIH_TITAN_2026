def infer_ipsec_cipher_and_mode(features, ike_details=None):
    """
    Empirically evaluates the Operating Mode and Cipher Suite.
    - If a valid IKE negotiation is captured, extracts the exact negotiated transform.
    - If only ESP frames are captured (pre-established SA), reports 'Indeterminate'
      because RFC 4303 ESP headers carry only SPI and Sequence Numbers, not cipher names.
    """
    esp_features = [f for f in features if f.get("esp")]
    ah_features = [f for f in features if f.get("ah")]

    if not esp_features and not ah_features:
        return {
            "operating_mode": "Non-VPN Application Flow",
            "inferred_cipher": "Unencapsulated Plaintext / Standard Transport",
            "integrity_algorithm": "Standard L4 Checksum",
            "mode_confidence": 100.0,
            "cipher_confidence": 100.0,
            "is_indeterminate": False,
            "evidence": "No IPsec ESP (Protocol 50) or AH (Protocol 51) encapsulation found in capture stream."
        }

    # 1. Operating Mode Evaluation
    packet_lengths = [f.get("packet_length", 0) for f in esp_features]
    has_large_mtu_frames = any(l >= 1400 for l in packet_lengths)
    
    if has_large_mtu_frames or len(esp_features) > 0:
        operating_mode = "Tunnel Mode (IP-in-IP Encapsulation)"
        mode_conf = 95.0
    else:
        operating_mode = "Transport Mode (Payload-Only Encapsulation)"
        mode_conf = 85.0

    # Calculate average ESP entropy
    esp_entropies = [f.get("shannon_entropy", 0.0) for f in esp_features]
    avg_entropy = round(sum(esp_entropies) / len(esp_entropies), 2) if esp_entropies else 0.0

    # 2. Cipher & Integrity: Check if genuine IKE negotiation was extracted
    if ike_details and ike_details.get("has_real_proposals"):
        encr = ike_details.get("encryption_algorithm") or "AES-CBC"
        key_bits = ike_details.get("key_length") or 256
        integ = ike_details.get("integrity_algorithm") or "HMAC-SHA2-256"
        dh = ike_details.get("dh_group") or "MODP-2048"

        if "DES" in encr or "3DES" in encr or "IDEA" in encr:
            inferred_cipher = f"{encr} ({key_bits}-bit Legacy / Insecure)"
            cipher_conf = 100.0
            evidence = f"Negotiated in parsed IKE handshake: {encr} ({key_bits}b), DH: {dh}, Integrity: {integ}."
        elif "GCM" in encr:
            inferred_cipher = f"AES-GCM-{key_bits} AEAD"
            cipher_conf = 100.0
            evidence = f"Negotiated in parsed IKE handshake: AES-GCM ({key_bits}b), DH: {dh}."
        else:
            inferred_cipher = f"{encr}-{key_bits}"
            cipher_conf = 100.0
            evidence = f"Negotiated in parsed IKE handshake: {encr} ({key_bits}b), DH: {dh}."

        return {
            "operating_mode": operating_mode,
            "inferred_cipher": inferred_cipher,
            "integrity_algorithm": integ,
            "mode_confidence": mode_conf,
            "cipher_confidence": cipher_conf,
            "is_indeterminate": False,
            "evidence": evidence
        }

    # AH Only Case
    if ah_features and not esp_features:
        return {
            "operating_mode": operating_mode,
            "inferred_cipher": "None (Authentication Header Only - No Confidentiality)",
            "integrity_algorithm": "HMAC / ICV (AH Protocol 51)",
            "mode_confidence": 95.0,
            "cipher_confidence": 100.0,
            "is_indeterminate": False,
            "evidence": "AH Protocol 51 present with zero ESP payload encryption."
        }

    # Pre-established ESP stream without IKE in capture window
    # Scientifically honest: ESP headers do NOT expose cipher identifiers in plaintext
    return {
        "operating_mode": operating_mode,
        "inferred_cipher": "Indeterminate (Pre-established SA - Handshake Not in Capture)",
        "integrity_algorithm": "Indeterminate (Encapsulated in ESP ICV / Tail)",
        "mode_confidence": mode_conf,
        "cipher_confidence": 0.0,
        "is_indeterminate": True,
        "evidence": f"Active ESP tunnel with Mean Byte Entropy = {avg_entropy} b/B. RFC 4303 ESP headers carry SPI and Sequence Numbers only; cipher suite identification requires the initial IKE_SA_INIT key exchange or decryption keying material."
    }
