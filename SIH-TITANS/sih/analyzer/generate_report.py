import json
import sys
import uuid
from datetime import datetime
from pathlib import Path

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from analyzer.eta_fingerprint import perform_encrypted_traffic_analysis
from analyzer.advanced_security_auditor import perform_advanced_security_audit

def build_full_report(features, assessment, ml_result, pcap_name="traffic.pcap", reports_dir=None):
    now = datetime.utcnow()
    report_id = f"REP-{now.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    
    unique_src_ips = sorted(list(set(x["src_ip"] for x in features if x.get("src_ip"))))
    unique_dst_ips = sorted(list(set(x["dst_ip"] for x in features if x.get("dst_ip"))))
    unique_protocols = sorted(list(set(x["transport_protocol"] for x in features if x.get("transport_protocol"))))

    esp_count = sum(1 for x in features if x.get("esp"))
    ah_count = sum(1 for x in features if x.get("ah"))
    ike_count = sum(1 for x in features if x.get("ike_candidate"))
    tcp_count = sum(1 for x in features if x.get("transport_protocol") == "TCP")
    udp_count = sum(1 for x in features if x.get("transport_protocol") == "UDP")
    icmp_count = sum(1 for x in features if x.get("icmp"))
    dns_count = sum(1 for x in features if x.get("dns"))

    # Run ETA Fingerprinting and Advanced Cybersecurity Audits
    eta_result = perform_encrypted_traffic_analysis(features)
    adv_audit = perform_advanced_security_audit(features, assessment)

    report = {
        "report_id": report_id,
        "report_type": "Enterprise IPsec Security Audit & Compliance Report",
        "report_name": f"Audit Analysis - {pcap_name}",
        "pcap_file": pcap_name,
        "generated_at": now.isoformat() + "Z",
        "generated_date_str": now.strftime("%b %d, %Y, %H:%M UTC"),
        "status": "Completed",
        "executive_summary": {
            "security_grade": assessment.get("security_grade", "A"),
            "compliance_status": assessment.get("compliance_status", "COMPLIANT"),
            "risk_score": assessment.get("risk_score", 10),
            "risk_level": assessment.get("risk_level", "LOW"),
            "summary_text": f"Traffic trace {pcap_name} was evaluated by the TITAN Inspection Engine. Security posture rated Grade {assessment.get('security_grade', 'A')} with a normalized risk index of {assessment.get('risk_score', 10)}/100."
        },
        "traffic_summary": {
            "packets_analyzed": len(features),
            "esp_packets": esp_count,
            "ah_packets": ah_count,
            "ike_candidates": ike_count,
            "tcp_packets": tcp_count,
            "udp_packets": udp_count,
            "icmp_packets": icmp_count,
            "dns_packets": dns_count
        },
        "cryptographic_analysis": assessment.get("cryptographic_posture", {}),
        "leakage_assessment": assessment.get("leakage_assessment", {}),
        "anti_replay_audit": assessment.get("anti_replay_audit", {}),
        "mtu_fragmentation_audit": assessment.get("mtu_fragmentation_audit", {}),
        "encrypted_traffic_analysis": eta_result,
        "advanced_security_audit": adv_audit,
        "pqc_readiness": adv_audit.get("pqc_readiness", {}),
        "mitre_attack_mapping": adv_audit.get("mitre_attack_mapping", []),
        "siem_event": adv_audit.get("siem_event", {}),
        "endpoints": {
            "source_ips": unique_src_ips,
            "destination_ips": unique_dst_ips
        },
        "protocols": unique_protocols,
        "ml_analysis": ml_result,
        "security_assessment": {
            "security_grade": assessment.get("security_grade", "A"),
            "risk_score": assessment.get("risk_score", 0),
            "risk_level": assessment.get("risk_level", "UNKNOWN"),
            "findings": assessment.get("findings", []),
            "remediations": assessment.get("remediations", []),
            "remediation_guidance": assessment.get("remediations", [])
        }
    }

    if reports_dir is not None:
        reports_dir = Path(reports_dir)
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_path = reports_dir / f"{report_id}.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    return report

if __name__ == "__main__":
    feat_file = BASE_DIR / "dataset" / "ipsec_features.json"
    sec_file = BASE_DIR / "dataset" / "security_assessment.json"
    rep_dir = BASE_DIR / "reports"

    if not feat_file.exists() or not sec_file.exists():
        print("Required intermediate files missing.")
        sys.exit(1)

    with open(feat_file, "r", encoding="utf-8") as f:
        features = json.load(f)

    with open(sec_file, "r", encoding="utf-8") as f:
        assessment = json.load(f)

    from analyzer.ml_predict import run_ml_inference
    ml_result = run_ml_inference(features)

    report = build_full_report(features, assessment, ml_result, reports_dir=rep_dir)
    print("Report generated successfully:")
    print(f"Report ID: {report['report_id']}")
    print(f"Security Grade: {report['executive_summary']['security_grade']}")
