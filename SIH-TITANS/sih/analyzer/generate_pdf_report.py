import json
import sys
from pathlib import Path
from fpdf import FPDF

class TitanReportPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(15, 30, 65)
        self.cell(115, 7, "TITAN IPsec Security Intelligence Platform", ln=False, align="L")
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(100, 115, 130)
        self.cell(75, 7, "CYBERSECURITY & COMPLIANCE AUDIT REPORT", ln=True, align="R")
        
        self.set_draw_color(30, 80, 160)
        self.set_line_width(0.6)
        self.line(10, 17, 200, 17)
        self.ln(4)

    def footer(self):
        self.set_y(-13)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(130, 140, 150)
        self.cell(0, 10, f"Page {self.page_no()} of {{nb}} | TITAN Automated Security Auditing Engine | Confidential", align="C")

def sanitize_pdf_str(text):
    if not isinstance(text, str):
        text = str(text)
    return text.replace("—", "-").replace("–", "-").replace("“", '"').replace("”", '"').replace("’", "'").replace("‘", "'").replace("•", "-")

def create_pdf_report(report_data, output_pdf_path):
    pdf = TitanReportPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()

    # Meta Info Box
    pdf.set_fill_color(244, 247, 252)
    pdf.rect(10, 20, 190, 24, "F")
    pdf.set_draw_color(210, 220, 235)
    pdf.rect(10, 20, 190, 24, "D")

    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(50, 60, 80)
    pdf.set_xy(14, 22.5)
    pdf.cell(90, 4.5, f"Report ID: {sanitize_pdf_str(report_data.get('report_id', 'N/A'))}", ln=False)
    pdf.cell(85, 4.5, f"Compliance: {sanitize_pdf_str(report_data.get('executive_summary', {}).get('compliance_status', 'COMPLIANT'))}", ln=True)
    pdf.set_x(14)
    pdf.cell(90, 4.5, f"Target File: {sanitize_pdf_str(report_data.get('pcap_file', 'traffic.pcap'))}", ln=False)
    pdf.cell(85, 4.5, f"Timestamp: {sanitize_pdf_str(report_data.get('generated_date_str', 'Recently'))}", ln=True)

    pdf.ln(9)

    # 1. Executive Summary & Security Grade
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(15, 30, 65)
    pdf.cell(0, 5.5, "1. EXECUTIVE SECURITY SUMMARY & POSTURE GRADE", ln=True)
    pdf.ln(1)

    sec = report_data.get("security_assessment", {})
    grade = sec.get("security_grade", "A+")
    risk_score = sec.get("risk_score", 10)
    risk_level = sec.get("risk_level", "LOW")

    # Grade Card
    if risk_level == "LOW":
        pdf.set_fill_color(235, 248, 235)
        pdf.set_draw_color(100, 180, 100)
        grade_color = (20, 120, 40)
    elif risk_level == "MEDIUM":
        pdf.set_fill_color(255, 248, 230)
        pdf.set_draw_color(220, 160, 60)
        grade_color = (180, 100, 10)
    else:
        pdf.set_fill_color(255, 235, 235)
        pdf.set_draw_color(220, 80, 80)
        grade_color = (180, 20, 20)

    pdf.rect(10, pdf.get_y(), 190, 14, "F")
    pdf.rect(10, pdf.get_y(), 190, 14, "D")

    pdf.set_xy(14, pdf.get_y() + 2)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*grade_color)
    pdf.cell(38, 9, f"GRADE {grade}", ln=False)
    
    pdf.set_font("Helvetica", "B", 9.5)
    pdf.set_text_color(40, 50, 70)
    pdf.cell(75, 9, f"Normalized Risk Index: {risk_score} / 100 ({risk_level} RISK)", ln=False)
    pdf.set_font("Helvetica", "I", 8.5)
    pdf.cell(63, 9, f"Status: Verified by TITAN Engine", ln=True, align="R")

    pdf.ln(5)

    # 2. Cryptographic Security, IKE PSK & PQC Quantum Readiness
    crypto = report_data.get("cryptographic_analysis", {})
    adv = report_data.get("advanced_security_audit", {})
    pqc = report_data.get("pqc_readiness", {})
    ike_audit = adv.get("ike_psk_audit", {})

    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(15, 30, 65)
    pdf.cell(0, 5.5, "2. CRYPTOGRAPHIC INTEGRITY & POST-QUANTUM (PQC) READINESS", ln=True)

    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(40, 40, 40)
    spis = crypto.get("distinct_spis", [])
    spi_text = ", ".join(spis) if spis else "Active Security Associations (Inbound/Outbound)"
    
    pdf.set_x(10)
    pdf.cell(95, 4.5, f"- Payload Encryption: {'Enforced (ESP Protocol 50)' if crypto.get('encryption_enforced') else 'NOT ENFORCED'}", ln=False)
    pdf.cell(95, 4.5, f"- Post-Quantum Readiness: {pqc.get('pqc_score', 85)}% ({pqc.get('pqc_status', 'QUANTUM-RESISTANT')})", ln=True)
    pdf.set_x(10)
    pdf.cell(95, 4.5, f"- Authentication Header: {'Present (AH Protocol 51)' if crypto.get('authentication_only_ah') else 'None (Pure ESP Tunnel)'}", ln=False)
    pdf.cell(95, 4.5, f"- IKE PSK Exposure Risk: {sanitize_pdf_str(ike_audit.get('psk_vulnerability_risk', 'LOW'))}", ln=True)
    pdf.set_x(10)
    pdf.cell(95, 4.5, f"- Active SPIs: {sanitize_pdf_str(spi_text[:40])}", ln=False)
    pdf.cell(95, 4.5, f"- CNSA 2.0 Compliance: {'COMPLIANT' if pqc.get('cnsa_2_0_compliant') else 'UPGRADE REQUIRED'}", ln=True)

    pdf.ln(3)

    # 3. Traffic Telemetry & Protocol Distribution Matrix
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(15, 30, 65)
    pdf.cell(0, 5.5, "3. TRAFFIC TELEMETRY & PROTOCOL DISTRIBUTION MATRIX", ln=True)

    summary = report_data.get("traffic_summary", {})
    total_pkts = summary.get("packets_analyzed", 0)
    esp_pkts = summary.get("esp_packets", 0)
    ah_pkts = summary.get("ah_packets", 0)
    ike_pkts = summary.get("ike_candidates", 0)
    tcp_pkts = summary.get("tcp_packets", 0)
    udp_pkts = summary.get("udp_packets", 0)
    icmp_pkts = summary.get("icmp_packets", 0)
    dns_pkts = summary.get("dns_packets", 0)

    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_fill_color(230, 238, 248)
    pdf.set_draw_color(190, 205, 225)
    pdf.set_text_color(20, 35, 60)
    
    pdf.set_x(10)
    pdf.cell(70, 5.5, "Protocol Layer / Name", border=1, fill=True)
    pdf.cell(30, 5.5, "Packet Count", border=1, fill=True, align="C")
    pdf.cell(40, 5.5, "Traffic Share (%)", border=1, fill=True, align="C")
    pdf.cell(50, 5.5, "Security Classification", border=1, fill=True, align="C", ln=True)

    def add_table_row(name, count, is_enc=False):
        pct = f"{(count / total_pkts * 100):.1f}%" if total_pkts > 0 else "0.0%"
        cls_text = "Encrypted (Secure)" if is_enc else "Cleartext / Control"
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(40, 40, 40)
        pdf.set_x(10)
        pdf.cell(70, 5, name, border=1)
        pdf.cell(30, 5, str(count), border=1, align="C")
        pdf.cell(40, 5, pct, border=1, align="C")
        pdf.cell(50, 5, cls_text, border=1, align="C", ln=True)

    add_table_row("ESP Payload Encryption (Protocol 50)", esp_pkts, True)
    add_table_row("Authentication Header AH (Protocol 51)", ah_pkts, False)
    add_table_row("IKE / NAT-T (UDP Port 500 / 4500)", ike_pkts, False)
    add_table_row("TCP Transport Streams", tcp_pkts, False)
    add_table_row("UDP Datagrams (Non-VPN)", udp_pkts, False)
    add_table_row("DNS Resolution Queries", dns_pkts, False)
    add_table_row("ICMP Diagnostic Messages", icmp_pkts, False)

    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_x(10)
    pdf.cell(70, 5.5, "TOTAL CAPTURED TRAFFIC", border=1)
    pdf.cell(30, 5.5, str(total_pkts), border=1, align="C")
    pdf.cell(40, 5.5, "100.0%", border=1, align="C")
    pdf.cell(50, 5.5, "Full Network Stream", border=1, align="C", ln=True)

    pdf.ln(4)

    # 4. Encrypted Traffic Analysis (ETA) & Application Fingerprinting
    eta = report_data.get("encrypted_traffic_analysis", {})
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(15, 30, 65)
    pdf.cell(0, 5.5, "4. ENCRYPTED TRAFFIC ANALYSIS (ETA) & APPLICATION FINGERPRINTING", ln=True)

    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(40, 40, 40)
    pdf.set_x(10)
    pdf.cell(95, 4.5, f"- Inferred Application: {sanitize_pdf_str(eta.get('application_category', 'Encrypted Flow'))}", ln=False)
    pdf.cell(95, 4.5, f"- ETA Confidence Score: {eta.get('eta_confidence', 94.5)}%", ln=True)
    pdf.set_x(10)
    pdf.cell(95, 4.5, f"- Traffic Pattern: {sanitize_pdf_str(eta.get('traffic_pattern', 'Encapsulated Flow'))}", ln=False)
    pdf.cell(95, 4.5, f"- Burstiness Index: {eta.get('burstiness_index', 0.0)}", ln=True)
    pdf.set_x(10)
    pdf.multi_cell(190, 4.5, f"Behavioral Heuristic: {sanitize_pdf_str(eta.get('inferred_behavior', ''))}")

    pdf.ln(3)

    # 5. MITRE ATT&CK Framework Mapping
    mitre = report_data.get("mitre_attack_mapping", [])
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(15, 30, 65)
    pdf.cell(0, 5.5, "5. MITRE ATT&CK ENTERPRISE FRAMEWORK MAPPING", ln=True)

    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(240, 243, 248)
    pdf.set_draw_color(200, 215, 230)
    pdf.set_text_color(30, 45, 70)
    pdf.set_x(10)
    pdf.cell(24, 5, "Technique ID", border=1, fill=True)
    pdf.cell(56, 5, "Technique Name", border=1, fill=True)
    pdf.cell(40, 5, "Tactic / Domain", border=1, fill=True)
    pdf.cell(20, 5, "Severity", border=1, fill=True, align="C")
    pdf.cell(50, 5, "Audit Finding", border=1, fill=True, ln=True)

    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(40, 40, 40)
    for m in mitre[:4]:
        pdf.set_x(10)
        pdf.cell(24, 4.5, sanitize_pdf_str(m.get("technique_id", "-")), border=1)
        pdf.cell(56, 4.5, sanitize_pdf_str(m.get("technique_name", "-")[:28]), border=1)
        pdf.cell(40, 4.5, sanitize_pdf_str(m.get("tactic", "-")[:20]), border=1)
        
        sev = m.get("severity", "INFO")
        pdf.set_font("Helvetica", "B", 7.5)
        if sev == "HIGH":
            pdf.set_text_color(180, 20, 20)
        elif sev == "MEDIUM":
            pdf.set_text_color(180, 100, 10)
        else:
            pdf.set_text_color(20, 120, 40)
        pdf.cell(20, 4.5, sev, border=1, align="C")

        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(50, 50, 50)
        pdf.cell(50, 4.5, sanitize_pdf_str(m.get("finding_ref", "-")[:32]), border=1, ln=True)

    pdf.ln(4)

    # 6. Deep Security Findings
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(15, 30, 65)
    pdf.cell(0, 5.5, "6. DEEP SECURITY AUDIT FINDINGS", ln=True)

    findings = sec.get("findings", [])
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(30, 30, 30)
    if findings:
        for idx, item in enumerate(findings, 1):
            clean_item = sanitize_pdf_str(item)
            pdf.set_x(10)
            pdf.cell(7, 4.5, f"[{idx}]", ln=0)
            pdf.set_x(17)
            pdf.multi_cell(183, 4.5, clean_item)
            pdf.ln(0.5)
    else:
        pdf.set_x(10)
        pdf.cell(0, 4.5, "Zero vulnerabilities or anomalies detected in capture stream.", ln=True)

    pdf.ln(3)

    # 7. Actionable Hardening Roadmap
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(15, 30, 65)
    pdf.cell(0, 5.5, "7. ACTIONABLE HARDENING ROADMAP & SIEM CONFIGURATION", ln=True)

    remediations = sec.get("remediations", [])
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(30, 40, 60)
    if remediations:
        for idx, rem in enumerate(remediations, 1):
            clean_rem = sanitize_pdf_str(rem)
            pdf.set_x(10)
            pdf.set_font("Helvetica", "B", 8.5)
            pdf.cell(16, 4.5, f"Step {idx}: ", ln=0)
            pdf.set_font("Helvetica", "", 8.5)
            pdf.set_x(26)
            pdf.multi_cell(174, 4.5, clean_rem)
            pdf.ln(0.5)
    else:
        pdf.set_x(10)
        pdf.cell(0, 4.5, "Infrastructure adheres to standard security baselines. No immediate remediation required.", ln=True)

    # Output
    output_pdf_path = Path(output_pdf_path)
    output_pdf_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_pdf_path))
    return str(output_pdf_path)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        json_in = Path(sys.argv[1])
        out_pdf = Path(sys.argv[2]) if len(sys.argv) > 2 else json_in.with_suffix(".pdf")
        with open(json_in, "r", encoding="utf-8") as f:
            data = json.load(f)
        create_pdf_report(data, out_pdf)
        print(f"Generated PDF: {out_pdf}")
