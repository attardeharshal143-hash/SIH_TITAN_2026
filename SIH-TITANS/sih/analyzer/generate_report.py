import json
import uuid
from pathlib import Path
from datetime import datetime
from analyzer.cipher_mode_infer import infer_ipsec_cipher_and_mode
from analyzer.eta_fingerprint import perform_encrypted_traffic_analysis
from analyzer.advanced_security_auditor import perform_advanced_security_audit
from analyzer.remediation_generator import generate_remediation_scripts
from analyzer.tunnel_partitioner import partition_and_audit_tunnels
from analyzer.ike_dissector import extract_all_ike_negotiations

def build_full_report(features, assessment, ml_result, pcap_name="traffic.pcap", reports_dir=None, raw_packets=None, ike_map=None):
    now = datetime.utcnow()
    report_id = f"REP-{now.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    
    unique_src_ips = sorted(list(set(x["src_ip"] for x in features if x.get("src_ip"))))
    unique_dst_ips = sorted(list(set(x["dst_ip"] for x in features if x.get("dst_ip"))))
    unique_protocols = sorted(list(set(x["transport_protocol"] for x in features if x.get("transport_protocol"))))

    # Mutually Exclusive Protocol Partitioning (Every frame counted exactly once - Zero Double Counting)
    esp_count = 0
    ah_count = 0
    ike_count = 0
    dns_count = 0
    other_udp_count = 0
    tcp_count = 0
    icmp_count = 0
    other_count = 0

    for x in features:
        if x.get("esp"):
            esp_count += 1
        elif x.get("ah"):
            ah_count += 1
        elif x.get("ike_candidate") or (x.get("transport_protocol") == "UDP" and (x.get("src_port") in (500, 4500) or x.get("dst_port") in (500, 4500))):
            ike_count += 1
        elif x.get("dns") or (x.get("transport_protocol") == "UDP" and (x.get("src_port") == 53 or x.get("dst_port") == 53)):
            dns_count += 1
        elif x.get("transport_protocol") == "UDP":
            other_udp_count += 1
        elif x.get("transport_protocol") == "TCP":
            tcp_count += 1
        elif x.get("icmp") or x.get("transport_protocol") == "ICMP":
            icmp_count += 1
        else:
            other_count += 1

    # 1. Global ETA Fingerprinting
    eta_result = perform_encrypted_traffic_analysis(features)
    
    # 2. Advanced Security Audit (IKE SA Dissection, PQC, Downgrade detection)
    adv_audit = perform_advanced_security_audit(features, assessment, raw_packets=raw_packets)
    
    # 3. Global Cipher & Mode Inference (IKE-first precedence)
    first_ike = ike_map.get("global_first") if ike_map else None
    cipher_inference = infer_ipsec_cipher_and_mode(features, ike_details=first_ike)

    # 4. Per-Tunnel / Per-SA Partitioned Analysis
    sa_audits = partition_and_audit_tunnels(features, ike_map)

    # 5. Worst-Case Aggregation: If any SA is weak or has crypto downgrade, enforce strict non-compliance
    sec_grade = assessment.get("security_grade", "A")
    comp_status = assessment.get("compliance_status", "COMPLIANT")
    r_score = assessment.get("risk_score", 10)
    r_level = assessment.get("risk_level", "LOW")

    if sa_audits:
        weak_sas = [sa for sa in sa_audits if sa.get("pqc_score") == 0 or "Legacy" in str(sa.get("inferred_cipher", "")) or "DES" in str(sa.get("inferred_cipher", "")) or "VULNERABLE" in str(sa.get("pqc_status", ""))]
        if weak_sas:
            weak_spis = [sa.get("spi", "") for sa in weak_sas if sa.get("spi")]
            if len(weak_spis) == 1:
                downgrade_desc = f"SA {weak_spis[0]}"
            else:
                downgrade_desc = f"SAs {', '.join(weak_spis)}"

            weak_sa = weak_sas[0]
            cipher_inference["inferred_cipher"] = weak_sa.get("inferred_cipher")
            adv_audit["pqc_readiness"]["pqc_score"] = 0
            adv_audit["pqc_readiness"]["pqc_status"] = f"QUANTUM-VULNERABLE (Downgrade in {downgrade_desc})"
            sec_grade = "C" if r_score <= 75 else "F"
            comp_status = f"NON-COMPLIANT (Cryptographic Downgrade in {downgrade_desc})"
            r_score = max(r_score, 75)
            r_level = "HIGH"

    report = {
        "report_id": report_id,
        "report_type": "Enterprise IPsec Security Audit & Compliance Report",
        "report_name": f"Audit Analysis - {pcap_name}",
        "pcap_file": pcap_name,
        "generated_at": now.isoformat() + "Z",
        "generated_date_str": now.strftime("%b %d, %Y, %H:%M UTC"),
        "status": "Completed",
        "executive_summary": {
            "security_grade": sec_grade,
            "compliance_status": comp_status,
            "risk_score": r_score,
            "risk_level": r_level,
            "summary_text": f"Traffic trace {pcap_name} was evaluated by the TITAN Inspection Engine. Security posture rated Grade {sec_grade} with a normalized risk index of {r_score}/100."
        },
        "traffic_summary": {
            "packets_analyzed": len(features),
            "esp_packets": esp_count,
            "ah_packets": ah_count,
            "ike_candidates": ike_count,
            "dns_packets": dns_count,
            "udp_packets": other_udp_count,
            "other_udp_packets": other_udp_count,
            "total_udp_all": ike_count + dns_count + other_udp_count,
            "tcp_packets": tcp_count,
            "icmp_packets": icmp_count,
            "other_packets": other_count,
            "active_security_associations": len(sa_audits)
        },
        "cryptographic_analysis": assessment.get("cryptographic_posture", {}),
        "leakage_assessment": assessment.get("leakage_assessment", {}),
        "anti_replay_audit": assessment.get("anti_replay_audit", {}),
        "mtu_fragmentation_audit": assessment.get("mtu_fragmentation_audit", {}),
        "encrypted_traffic_analysis": eta_result,
        "advanced_security_audit": adv_audit,
        "cipher_mode_inference": cipher_inference,
        "pqc_readiness": adv_audit.get("pqc_readiness", {}),
        "mitre_attack_mapping": adv_audit.get("mitre_attack_mapping", []),
        "siem_event": adv_audit.get("siem_event", {}),
        "security_associations": sa_audits,
        "endpoints": {
            "source_ips": unique_src_ips,
            "destination_ips": unique_dst_ips
        },
        "protocols": unique_protocols,
        "ml_analysis": ml_result,
        "security_assessment": {
            "security_grade": sec_grade,
            "risk_score": r_score,
            "risk_level": r_level,
            "findings": assessment.get("findings", []),
            "remediations": assessment.get("remediations", []),
            "remediation_guidance": assessment.get("remediations", []),
            "risk_score_breakdown": assessment.get("risk_score_breakdown", [])
        }
    }

    # Generate automated hardening remediation scripts
    report["remediation_scripts"] = generate_remediation_scripts(report)

    if reports_dir:
        reports_dir = Path(reports_dir)
        reports_dir.mkdir(parents=True, exist_ok=True)
        rep_file = reports_dir / f"{report_id}.json"
        with open(rep_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    return report
