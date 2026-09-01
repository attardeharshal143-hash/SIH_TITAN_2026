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

    sec = report_data.get("security_assessment", {})
    crypto = report_data.get("cryptographic_analysis", {})
    adv = report_data.get("advanced_security_audit", {})
    pqc = report_data.get("pqc_readiness", {})
    c_infer = report_data.get("cipher_mode_inference", {})
    summary = report_data.get("traffic_summary", {})
    eta = report_data.get("encrypted_traffic_analysis", {})
    mitre = report_data.get("mitre_attack_mapping", [])
    anti_replay = report_data.get("anti_replay_audit", {})
    remediations = report_data.get("remediation_scripts", {})

    total_pkts = summary.get("packets_analyzed", 0)
    esp_pkts = summary.get("esp_packets", 0)
    ah_pkts = summary.get("ah_packets", 0)
    ike_pkts = summary.get("ike_candidates", 0)
    tcp_pkts = summary.get("tcp_packets", 0)
    udp_pkts = summary.get("udp_packets", 0)
    icmp_pkts = summary.get("icmp_packets", 0)
    dns_pkts = summary.get("dns_packets", 0)

    is_ipsec = (esp_pkts > 0 or ah_pkts > 0 or ike_pkts > 0)

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

    grade = sec.get("security_grade", "A+")
    risk_score = sec.get("risk_score", 10)
    risk_level = sec.get("risk_level", "LOW")

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
    pdf.cell(75, 9, f"Risk Index: {risk_score} / 100 ({risk_level})", ln=False)
    pdf.set_font("Helvetica", "I", 8.5)
    pdf.cell(63, 9, f"Traffic: {'IPsec Encapsulated' if is_ipsec else 'Standard Non-VPN'}", ln=True, align="R")

    pdf.ln(5)

    # 2. Cryptographic Security & Posture
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(15, 30, 65)
    pdf.cell(0, 5.5, "2. CRYPTOGRAPHIC INTEGRITY & POST-QUANTUM (PQC) POSTURE AUDIT", ln=True)

    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(40, 40, 40)
    spis = crypto.get("distinct_spis", [])
    spi_text = ", ".join(spis) if spis else ("Active SPIs" if is_ipsec else "None (Non-IPsec)")
    
    op_mode = c_infer.get("operating_mode", "Tunnel Mode" if is_ipsec else "N/A (Non-VPN)")
    cipher_name = c_infer.get("inferred_cipher", "AES-GCM-256 AEAD" if is_ipsec else "Plaintext HTTP/TCP")
    icv_tag = c_infer.get("integrity_algorithm", "128-bit GHASH GMAC" if is_ipsec else "TCP/IP Checksum")

    pdf.set_x(10)
    pdf.cell(95, 4.5, f"- Operating Mode: {sanitize_pdf_str(op_mode[:45])}", ln=False)
    pdf.cell(95, 4.5, f"- Inferred Cipher: {sanitize_pdf_str(cipher_name[:45])}", ln=True)
    
    pdf.set_x(10)
    pdf.cell(95, 4.5, f"- Payload Encryption: {'Enforced (ESP Protocol 50)' if esp_pkts > 0 else 'None (Unencrypted / Plaintext)'}", ln=False)
    pdf.cell(95, 4.5, f"- PQC Readiness: {pqc.get('pqc_score', 0)}% ({pqc.get('pqc_status', 'N/A')})", ln=True)
    
    pdf.set_x(10)
    pdf.cell(95, 4.5, f"- Auth / ICV Tag: {sanitize_pdf_str(icv_tag[:45])}", ln=False)
    pdf.cell(95, 4.5, f"- Anti-Replay: {sanitize_pdf_str(anti_replay.get('sequence_integrity', 'N/A')[:45])}", ln=True)

    pdf.set_x(10)
    pdf.cell(190, 4.5, f"- Active SPIs: {sanitize_pdf_str(spi_text[:80])}", ln=True)

    # Render Per-SA Partitioned Multi-Tunnel Table in PDF if multiple SAs
    sas = report_data.get("security_associations", [])
    if len(sas) > 1:
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_fill_color(230, 238, 248)
        pdf.set_text_color(20, 35, 60)
        pdf.set_x(10)
        pdf.cell(26, 4.5, "SPI (SA)", border=1, fill=True)
        pdf.cell(44, 4.5, "Endpoints", border=1, fill=True)
        pdf.cell(42, 4.5, "Inferred Cipher", border=1, fill=True)
        pdf.cell(20, 4.5, "PQC Grade", border=1, fill=True, align="C")
        pdf.cell(58, 4.5, "ETA Application Classification", border=1, fill=True, ln=True)

        for sa in sas:
            pdf.set_font("Helvetica", "", 7.5)
            pdf.set_text_color(40, 40, 40)
            pdf.set_x(10)
            pdf.cell(26, 4, sanitize_pdf_str(sa.get("spi", "")[:12]), border=1)
            pdf.cell(44, 4, sanitize_pdf_str(sa.get("endpoints", "")[:24]), border=1)
            pdf.cell(42, 4, sanitize_pdf_str(sa.get("inferred_cipher", "")[:22]), border=1)
            pdf.cell(20, 4, f"{sa.get('pqc_score', 0)}%", border=1, align="C")
            eta_name = sa.get("eta_profile", {}).get("application_category", "Standard Flow")
            pdf.cell(58, 4, sanitize_pdf_str(eta_name[:34]), border=1, ln=True)
        pdf.ln(2)
    else:
        pdf.ln(3)

    # 3. Traffic Telemetry & Protocol Matrix
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(15, 30, 65)
    pdf.cell(0, 5.5, "3. TRAFFIC TELEMETRY & PROTOCOL DISTRIBUTION MATRIX", ln=True)

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

    # 4. ETA & Application Fingerprinting
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(15, 30, 65)
    pdf.cell(0, 5.5, "4. APPLICATION FINGERPRINTING & ENCRYPTED TRAFFIC ANALYSIS", ln=True)

    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(40, 40, 40)
    pdf.set_x(10)
    pdf.cell(95, 4.5, f"- Inferred Application: {sanitize_pdf_str(eta.get('application_category', 'Standard Network Flow'))}", ln=False)
    pdf.cell(95, 4.5, f"- Identification Confidence: {eta.get('eta_confidence', 95.0)}%", ln=True)
    pdf.set_x(10)
    pdf.cell(95, 4.5, f"- Traffic Pattern: {sanitize_pdf_str(eta.get('traffic_pattern', 'Standard Flow'))}", ln=False)
    pdf.cell(95, 4.5, f"- Burstiness Index: {eta.get('burstiness_index', 0.0)}", ln=True)
    pdf.set_x(10)
    pdf.multi_cell(190, 4.5, f"Analysis: {sanitize_pdf_str(eta.get('inferred_behavior', ''))}")

    pdf.ln(3)

    # 5. MITRE ATT&CK Framework Mapping
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(15, 30, 65)
    pdf.cell(0, 5.5, "5. MITRE ATT&CK ENTERPRISE FRAMEWORK MAPPING", ln=True)

    if not mitre:
        pdf.set_font("Helvetica", "I", 8.5)
        pdf.set_text_color(60, 60, 60)
        pdf.set_x(10)
        pdf.cell(0, 5, "No adversary tactics or active tunnel exfiltration techniques detected in this capture stream.", ln=True)
    else:
        for m in mitre:
            pdf.set_font("Helvetica", "B", 8.5)
            pdf.set_text_color(180, 20, 20)
            pdf.set_x(10)
            pdf.cell(0, 4.5, f"[{m.get('technique_id')}] {sanitize_pdf_str(m.get('technique_name'))} ({m.get('tactic')}) - Severity: {m.get('severity')}", ln=True)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(40, 40, 40)
            pdf.set_x(14)
            pdf.multi_cell(186, 4, f"Observation: {sanitize_pdf_str(m.get('finding_ref', ''))} | Mitigation: {sanitize_pdf_str(m.get('mitigation', ''))}")

    pdf.ln(3)

    # 6. Deep Forensic Findings & Remediations
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(15, 30, 65)
    pdf.cell(0, 5.5, "6. FORENSIC FINDINGS & ACTIONABLE REMEDIATIONS", ln=True)

    findings = sec.get("findings", [])
    remed_guidance = sec.get("remediations", [])

    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(20, 35, 60)
    pdf.set_x(10)
    pdf.cell(0, 4.5, "Audited Observations:", ln=True)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(40, 40, 40)
    for f in findings:
        pdf.set_x(14)
        pdf.multi_cell(186, 4, f"- {sanitize_pdf_str(f)}")

    if remed_guidance:
        pdf.ln(1)
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(20, 35, 60)
        pdf.set_x(10)
        pdf.cell(0, 4.5, "Recommended Actions:", ln=True)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(40, 40, 40)
        for r in remed_guidance:
            pdf.set_x(14)
            pdf.multi_cell(186, 4, f"- {sanitize_pdf_str(r)}")

    # 7. Automated Remediation Configuration Snippet
    if remediations and (remediations.get("strongswan_swanctl_conf") or remediations.get("cisco_ios_xe_cli")):
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 10.5)
        pdf.set_text_color(15, 30, 65)
        pdf.cell(0, 5.5, "7. HARDENED CONFIGURATION REMEDIATION (STRONGSWAN / CISCO)", ln=True)
        
        pdf.set_font("Courier", "", 7.5)
        pdf.set_fill_color(240, 244, 250)
        pdf.set_text_color(25, 45, 75)
        
        conf_snippet = remediations.get("strongswan_swanctl_conf", "")
        if conf_snippet:
            lines = conf_snippet.split("\n")[:18]
            clean_snippet = "\n".join(lines)
            pdf.set_x(10)
            pdf.multi_cell(190, 3.5, sanitize_pdf_str(clean_snippet), fill=True)

    pdf.output(str(output_pdf_path))
    return output_pdf_path
