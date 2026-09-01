import json
import sys
from pathlib import Path

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from analyzer.feature_extractor import extract_pcap_features
from analyzer.validate_features import validate_features_data
from analyzer.security_analyzer import assess_security
from analyzer.ml_predict import run_ml_inference
from analyzer.generate_report import build_full_report

def run_complete_pipeline(pcap_path, reports_dir=None, dataset_dir=None):
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        return False, None, [], f"PCAP file not found: {pcap_path.name}"

    try:
        # 1. Feature extraction
        features = extract_pcap_features(pcap_path)
        if not features or len(features) == 0:
            return False, None, [], "PCAP file contains no valid network packets"

        # 2. Structural Validation
        is_valid, val_msg = validate_features_data(features)
        if not is_valid:
            return False, None, [], f"Feature validation failed: {val_msg}"

        # Load raw packets for deep IKE proposal dissection
        raw_pkts = None
        ike_map = {}
        try:
            from scapy.all import rdpcap
            from analyzer.ike_dissector import extract_all_ike_negotiations
            raw_pkts = rdpcap(str(pcap_path))
            ike_map = extract_all_ike_negotiations(raw_pkts)
        except Exception:
            raw_pkts = None
            ike_map = {}

        # 3. Security Assessment with IKE Proposal Gating
        assessment = assess_security(features, ike_map=ike_map)

        # 4. ML Inference
        ml_result = run_ml_inference(features)

        # 5. Build Final Report with per-tunnel breakdown
        report = build_full_report(
            features=features,
            assessment=assessment,
            ml_result=ml_result,
            pcap_name=pcap_path.name,
            reports_dir=reports_dir,
            raw_packets=raw_pkts,
            ike_map=ike_map
        )

        # Intermediate files are not written to dataset to ensure clean environment

        return True, report, features, None

    except Exception as e:
        return False, None, [], f"Analysis pipeline encountered an error: {str(e)}"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_pipeline.py <pcap_file>")
        sys.exit(1)

    pcap_target = Path(sys.argv[1])
    base_dir = Path(__file__).resolve().parent.parent
    success, report, feats, err = run_complete_pipeline(
        pcap_target,
        reports_dir=base_dir / "reports",
        dataset_dir=base_dir / "dataset"
    )

    if not success:
        print(f"[ERROR] {err}")
        sys.exit(1)

    print("================================")
    print("       PIPELINE COMPLETE")
    print("================================")
    print(f"Packets Analyzed: {len(feats)}")
    print(f"Risk Score:       {report['security_assessment']['risk_score']}/100")
    print(f"Risk Level:       {report['security_assessment']['risk_level']}")
    print(f"Report ID:        {report['report_id']}")
    print("================================")
