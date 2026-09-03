import struct
from scapy.all import IP, IPv6, UDP, Raw

# IKEv2 & IKEv1 (ISAKMP) Transform & Cipher Mappings
ENCR_TRANSFORMS = {
    1: {"name": "DES-CBC", "key_bits": 56, "security": "BROKEN", "quantum": "BROKEN"},
    2: {"name": "IDEA-CBC", "key_bits": 128, "security": "WEAK", "quantum": "VULNERABLE"},
    3: {"name": "Blowfish-CBC", "key_bits": 128, "security": "MEDIUM", "quantum": "VULNERABLE"},
    4: {"name": "RC5-R16-B64", "key_bits": 128, "security": "WEAK", "quantum": "VULNERABLE"},
    5: {"name": "3DES-CBC", "key_bits": 168, "security": "BROKEN", "quantum": "BROKEN"},
    6: {"name": "CAST-CBC", "key_bits": 128, "security": "WEAK", "quantum": "VULNERABLE"},
    7: {"name": "AES-CBC", "key_bits": 128, "security": "SECURE", "quantum": "PARTIAL"},
    12: {"name": "AES-CBC", "key_bits": 128, "security": "SECURE", "quantum": "PARTIAL"},
    14: {"name": "AES-CTR", "key_bits": 128, "security": "SECURE", "quantum": "PARTIAL"},
    18: {"name": "AES-CCM-8", "key_bits": 128, "security": "SECURE", "quantum": "PARTIAL"},
    19: {"name": "AES-CCM-12", "key_bits": 128, "security": "SECURE", "quantum": "PARTIAL"},
    20: {"name": "AES-CCM-16", "key_bits": 128, "security": "SECURE", "quantum": "PARTIAL"},
    28: {"name": "AES-GCM-16", "key_bits": 256, "security": "CNSA_2", "quantum": "GROVER_SAFE"},
    29: {"name": "ChaCha20-Poly1305", "key_bits": 256, "security": "CNSA_2", "quantum": "GROVER_SAFE"}
}

DH_TRANSFORMS = {
    1: {"name": "MODP-768 (Group 1)", "bits": 768, "security": "BROKEN", "quantum": "BROKEN"},
    2: {"name": "MODP-1024 (Group 2)", "bits": 1024, "security": "BROKEN", "quantum": "BROKEN"},
    5: {"name": "MODP-1536 (Group 5)", "bits": 1536, "security": "WEAK", "quantum": "BROKEN"},
    14: {"name": "MODP-2048 (Group 14)", "bits": 2048, "security": "SECURE", "quantum": "SHOR_VULNERABLE"},
    15: {"name": "MODP-3072 (Group 15)", "bits": 3072, "security": "SECURE", "quantum": "SHOR_VULNERABLE"},
    16: {"name": "MODP-4096 (Group 16)", "bits": 4096, "security": "SECURE", "quantum": "SHOR_VULNERABLE"},
    19: {"name": "Curve25519 (Group 19)", "bits": 256, "security": "SECURE", "quantum": "SHOR_VULNERABLE"},
    20: {"name": "Curve384 (Group 20)", "bits": 384, "security": "CNSA_2", "quantum": "SHOR_VULNERABLE"},
    31: {"name": "ML-KEM-768 / Kyber-768 (Group 31)", "bits": 768, "security": "POST_QUANTUM", "quantum": "PQC_COMPLETE"},
    32: {"name": "ML-KEM-1024 / Kyber-1024 (Group 32)", "bits": 1024, "security": "POST_QUANTUM", "quantum": "PQC_COMPLETE"}
}

PRF_TRANSFORMS = {
    1: {"name": "PRF_HMAC_MD5", "security": "BROKEN"},
    2: {"name": "PRF_HMAC_SHA1", "security": "WEAK"},
    4: {"name": "PRF_HMAC_SHA2_256", "security": "SECURE"},
    5: {"name": "PRF_HMAC_SHA2_256", "security": "SECURE"},
    6: {"name": "PRF_HMAC_SHA2_384", "security": "CNSA_2"},
    7: {"name": "PRF_HMAC_SHA2_512", "security": "CNSA_2"}
}

INTEG_TRANSFORMS = {
    1: {"name": "AUTH_HMAC_MD5_96", "security": "BROKEN"},
    2: {"name": "AUTH_HMAC_SHA1_96", "security": "WEAK"},
    12: {"name": "AUTH_HMAC_SHA2_256_128", "security": "SECURE"},
    13: {"name": "AUTH_HMAC_SHA2_384_192", "security": "CNSA_2"},
    14: {"name": "AUTH_HMAC_SHA2_512_256", "security": "CNSA_2"}
}

def parse_ike_payload(raw_bytes, pkt_label="Packet"):
    """
    Performs deep binary dissection of both IKEv1 (ISAKMP RFC 2408/2409)
    and IKEv2 (RFC 7296) SA negotiation payloads and transform attributes.
    """
    if not raw_bytes or len(raw_bytes) < 28:
        return None

    try:
        init_spi, resp_spi, next_payload, version, exch_type, flags, msg_id, length = struct.unpack("!8s8sBBBBII", raw_bytes[:28])
        major_ver = (version >> 4) & 0x0F
        minor_ver = version & 0x0F
        is_ikev2 = (major_ver == 2)
        is_aggressive = (exch_type == 4)

        result = {
            "version": f"IKEv{major_ver}.{minor_ver}",
            "exchange_type": exch_type,
            "next_payload": next_payload,
            "is_aggressive_mode": is_aggressive,
            "initiator_spi": f"0x{init_spi.hex()}",
            "responder_spi": f"0x{resp_spi.hex()}",
            "child_spis": [],
            "encryption_algorithm": None,
            "key_length": None,
            "dh_group": None,
            "dh_bits": None,
            "prf_algorithm": None,
            "integrity_algorithm": None,
            "has_real_proposals": False,
            "payload_chain": []
        }

        offset = 28
        curr_payload = next_payload

        # Walk generic payload chain
        while curr_payload != 0 and offset < len(raw_bytes) - 4:
            np, res_crit, p_len = struct.unpack("!BBH", raw_bytes[offset:offset+4])
            result["payload_chain"].append((curr_payload, p_len))
            if p_len < 4 or offset + p_len > len(raw_bytes):
                break

            payload_data = raw_bytes[offset+4 : offset+p_len]
            
            # SA Payload: Type 33 in IKEv2 or Type 1 in IKEv1
            if (is_ikev2 and curr_payload == 33) or (not is_ikev2 and curr_payload == 1):
                result["has_real_proposals"] = True
                
                # IKEv1 SA payload has a 4-byte DOI + 4-byte Situation header before proposals
                p_offset = 0
                if not is_ikev2 and len(payload_data) >= 8:
                    doi = struct.unpack("!I", payload_data[:4])[0]
                    if doi == 1:  # IPsec DOI
                        p_offset = 8
                
                while p_offset < len(payload_data) - 8:
                    last_sub, _, sub_len, prop_num, proto_id, spi_sz, num_transforms = struct.unpack("!BBHBBBB", payload_data[p_offset:p_offset+8])
                    if sub_len < 8 or p_offset + sub_len > len(payload_data):
                        break
                    
                    if spi_sz == 4 and len(payload_data) >= p_offset + 12:
                        child_spi_int = struct.unpack("!I", payload_data[p_offset+8 : p_offset+12])[0]
                        result["child_spis"].append(f"0x{child_spi_int:08x}")

                    t_offset = p_offset + 8 + spi_sz
                    for _ in range(num_transforms):
                        if t_offset + 8 > p_offset + sub_len:
                            break
                        
                        if is_ikev2:
                            # IKEv2 Transform Substructure
                            _, _, t_len, t_type, _, t_id = struct.unpack("!BBHBBH", payload_data[t_offset:t_offset+8])
                            key_len = None
                            if t_len > 8:
                                attr_bytes = payload_data[t_offset+8 : t_offset+t_len]
                                if len(attr_bytes) >= 4:
                                    af_type, val = struct.unpack("!HH", attr_bytes[:4])
                                    if (af_type & 0x7FFF) == 14:
                                        key_len = val

                            if t_type == 1:
                                encr_info = ENCR_TRANSFORMS.get(t_id, {"name": f"ENCR_{t_id}", "key_bits": 128, "security": "UNKNOWN", "quantum": "UNKNOWN"})
                                result["encryption_algorithm"] = encr_info["name"]
                                result["key_length"] = key_len or encr_info["key_bits"]
                            elif t_type == 2:
                                result["prf_algorithm"] = PRF_TRANSFORMS.get(t_id, {}).get("name", f"PRF_{t_id}")
                            elif t_type == 3:
                                result["integrity_algorithm"] = INTEG_TRANSFORMS.get(t_id, {}).get("name", f"AUTH_{t_id}")
                            elif t_type == 4:
                                dh_info = DH_TRANSFORMS.get(t_id, {"name": f"DH_Group_{t_id}", "bits": 1024, "security": "UNKNOWN", "quantum": "UNKNOWN"})
                                result["dh_group"] = dh_info["name"]
                                result["dh_bits"] = dh_info["bits"]

                            t_offset += t_len
                        else:
                            # IKEv1 (ISAKMP) Transform Substructure
                            _, _, t_len, t_num, t_id, _ = struct.unpack("!BBHBBH", payload_data[t_offset:t_offset+8])
                            
                            # Parse IKEv1 Attributes
                            attr_offset = t_offset + 8
                            while attr_offset < t_offset + t_len and attr_offset <= len(payload_data) - 4:
                                af_type, val = struct.unpack("!HH", payload_data[attr_offset:attr_offset+4])
                                is_basic = bool(af_type & 0x8000)
                                attr_type = af_type & 0x7FFF
                                
                                if is_basic:
                                    if attr_type == 1:  # Encryption Algorithm
                                        encr_info = ENCR_TRANSFORMS.get(val, {"name": f"ENCR_{val}", "key_bits": 128, "security": "UNKNOWN", "quantum": "UNKNOWN"})
                                        result["encryption_algorithm"] = encr_info["name"]
                                        result["key_length"] = encr_info["key_bits"]
                                    elif attr_type == 2:  # Hash Algorithm / PRF
                                        result["prf_algorithm"] = PRF_TRANSFORMS.get(val, {}).get("name", f"HASH_{val}")
                                        result["integrity_algorithm"] = PRF_TRANSFORMS.get(val, {}).get("name", f"HASH_{val}")
                                    elif attr_type == 4:  # Group Description (DH Group)
                                        dh_info = DH_TRANSFORMS.get(val, {"name": f"DH_Group_{val}", "bits": 1024, "security": "UNKNOWN", "quantum": "UNKNOWN"})
                                        result["dh_group"] = dh_info["name"]
                                        result["dh_bits"] = dh_info["bits"]
                                    elif attr_type == 14:  # Key Length
                                        result["key_length"] = val
                                    attr_offset += 4
                                else:
                                    # Variable length attribute
                                    v_len = val
                                    attr_offset += 4 + v_len

                            t_offset += t_len

                    p_offset += sub_len
                    if last_sub == 0:
                        break

            offset += p_len
            curr_payload = np

        return result
    except Exception as parse_err:
        return None

def extract_all_ike_negotiations(pcap_packets):
    """
    Extracts all IKE negotiations indexed by:
    1. Exact endpoint pair (ip_src, ip_dst) - bidirectional sorted tuple
    2. Single IP endpoints (both IPv4 and IPv6 normalized)
    3. Child SA SPI (if present in proposal)
    Strictly conforms to RFC 3948: Non-ESP Marker is ONLY checked/stripped on UDP port 4500.
    """
    ike_map = {}
    proposal_list = []

    print(f"[IKE_DISSECTOR] Inspecting {len(pcap_packets)} total frames for IKEv1/IKEv2 proposals...")

    for idx, pkt in enumerate(pcap_packets):
        try:
            if pkt.haslayer(UDP) and (pkt[UDP].sport in (500, 4500) or pkt[UDP].dport in (500, 4500)):
                raw_bytes = bytes(pkt[UDP].payload) if hasattr(pkt[UDP], "payload") else b""
                is_natt_port = (pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500)
                
                # RFC 3948 Section 2.1:
                # The Non-ESP Marker (0x00000000) MUST NOT be checked or stripped on UDP port 500!
                # On port 500, 4 leading zeros can be a valid 64-bit IKE Initiator SPI.
                if is_natt_port:
                    has_natt_marker = raw_bytes.startswith(b"\x00\x00\x00\x00")
                    if has_natt_marker:
                        raw_bytes = raw_bytes[4:]
                    elif len(raw_bytes) >= 4:
                        # Non-ESP marker absent on UDP 4500 -> It is NAT-T ESP encapsulated ciphertext, skip IKE parse
                        continue

                parsed = parse_ike_payload(raw_bytes, pkt_label=f"Pkt #{idx+1}")
                
                ip_src = "0.0.0.0"
                ip_dst = "0.0.0.0"
                if pkt.haslayer(IP):
                    ip_src = str(pkt[IP].src).strip().lower()
                    ip_dst = str(pkt[IP].dst).strip().lower()
                elif pkt.haslayer(IPv6):
                    ip_src = str(pkt[IPv6].src).strip().lower()
                    ip_dst = str(pkt[IPv6].dst).strip().lower()

                if parsed and parsed.get("has_real_proposals"):
                    pair_key = tuple(sorted([ip_src, ip_dst]))
                    ike_map[pair_key] = parsed
                    ike_map[ip_src] = parsed
                    ike_map[ip_dst] = parsed

                    for c_spi in parsed.get("child_spis", []):
                        ike_map[c_spi.lower()] = parsed

                    proposal_list.append(parsed)
                    print(f"[IKE_DISSECTOR] [Pkt #{idx+1}] Extracted IKE proposal for {ip_src} <-> {ip_dst} (Pair: {pair_key}) => {parsed.get('encryption_algorithm')} / {parsed.get('dh_group')}")
                else:
                    if parsed:
                        chain_str = str(parsed.get('payload_chain', []))
                        print(f"[IKE_DISSECTOR] [Pkt #{idx+1}] UDP {pkt[UDP].sport}->{pkt[UDP].dport} ({ip_src} -> {ip_dst}) | {parsed.get('version')} Exch={parsed.get('exchange_type')} NextPayload={parsed.get('next_payload')} | Chain: {chain_str} (No SA Type 33/1)")
                    else:
                        hex_preview = raw_bytes[:16].hex() if raw_bytes else 'EMPTY'
                        print(f"[IKE_DISSECTOR] [Pkt #{idx+1}] UDP {pkt[UDP].sport}->{pkt[UDP].dport} ({ip_src} -> {ip_dst}): Invalid IKE header/payload bytes (len={len(raw_bytes)}, hex={hex_preview})")
        except Exception as pkt_err:
            print(f"[IKE_DISSECTOR] [WARNING] Skipped malformed packet #{idx+1}: {pkt_err}")
            continue

    if proposal_list:
        ike_map["global_first"] = proposal_list[0]
        ike_map["all_proposals"] = proposal_list
        print(f"[IKE_DISSECTOR] Successfully extracted {len(proposal_list)} valid IKE proposals across capture.")
    else:
        print("[IKE_DISSECTOR] Zero valid IKE proposals found in capture window (all SAs will default to Pre-established).")

    return ike_map

def extract_ike_negotiation_details(pcap_packets):
    ike_map = extract_all_ike_negotiations(pcap_packets)
    return ike_map.get("global_first")
