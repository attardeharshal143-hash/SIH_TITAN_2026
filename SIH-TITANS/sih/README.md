# 🛡️ TITAN: IPsec Security Intelligence & Automated Audit Platform
> **AI-Driven Deep Packet Inspection, Cryptographic Vulnerability Auditing, Encrypted Traffic Analysis (ETA), Post-Quantum Readiness Scoring & MITRE ATT&CK Mapping for IPsec VPNs.**

---

## 🌟 Executive Summary & Problem Statement

Modern enterprise, banking, and defense infrastructures rely heavily on **IPsec Virtual Private Networks (VPNs)** to secure sensitive site-to-site and remote-access communications. However, security teams and SOC analysts face major challenges:

1. **The "Encrypted Black Box" Blindspot**: Standard network monitoring tools treat IPsec ESP (Protocol 50) traffic as opaque blobs, creating zero visibility into tunnel health or configuration flaws.
2. **Silent Cleartext Leakage**: Misconfigurations (such as split-tunneling bypasses) often allow unencrypted DNS queries or HTTP/TCP streams to escape the tunnel unnoticed.
3. **Cryptographic Weaknesses & Downgrades**: Legacy proposals (e.g., IKEv1 Aggressive Mode hash exposures, 3DES ciphers, MD5 hashes, weak Diffie-Hellman groups) expose organizations to interception.
4. **Post-Quantum Vulnerability**: Most legacy tunnels lack assessment against upcoming quantum threats ("Harvest Now, Decrypt Later").
5. **Manual Analysis Overhead**: Manually analyzing packet traces in Wireshark takes hours of senior engineer time.

**TITAN** solves these challenges by providing an **automated, instant cybersecurity auditing engine** that ingests any network capture (`.pcap`, `.pcapng`) or sniffs live network adapters, evaluates cryptographic posture in seconds, assigns a **Security Grade (A+ to F)**, and generates **Certified PDF Audit Reports** and **SIEM Telemetry Events**.

---

## 🚀 Key Platform Capabilities

```text
               ┌──────────────────────────────────────────────────────────┐
               │          INPUT: PCAP File Upload OR Live Wire Feed       │
               └────────────────────────────┬─────────────────────────────┘
                                            │
                                            ▼
               ┌──────────────────────────────────────────────────────────┐
               │                TITAN CORE INSPECTION ENGINE              │
               │                                                          │
               │  1. Deep Packet Inspection (ESP Proto 50, AH Proto 51)   │
               │  2. Key Exchange Auditing (IKEv2 / NAT-T UDP 500/4500)   │
               │  3. Encrypted Traffic Analysis (ETA) Fingerprinting      │
               │  4. Cryptographic Downgrade & Weakness Detector          │
               │  5. Post-Quantum Cryptography (PQC) Readiness Scoring    │
               │  6. MITRE ATT&CK Matrix Mapping (T1048, T1572, M1037)    │
               │  7. Random Forest Machine Learning Traffic Classifier    │
               │  8. Anti-Replay & Sequence Integrity Verification        │
               │  9. MTU Overhead & Fragmentation Risk Assessment         │
               └────────────────────────────┬─────────────────────────────┘
                                            │
                                            ▼
               ┌──────────────────────────────────────────────────────────┐
               │                       OUTPUTS                            │
               │  • Interactive Glassmorphic Web Dashboard                │
               │  • Certified Multi-Section PDF Security Audit Report     │
               │  • Standardized SIEM JSON Event Stream (Splunk / Elastic)│
               └──────────────────────────────────────────────────────────┘
```

### 1. 🔍 Deep Cryptographic Packet Inspection
- Parses IPv4/IPv6 headers and isolates **ESP (Protocol 50)**, **AH (Protocol 51)**, and **IKE/ISAKMP (UDP 500/4500)** frames.
- Dissects active **Security Parameters Index (SPI)** values, tracks directional flows (Inbound vs Outbound SAs), and verifies sequence number monotonicity for **Anti-Replay protection**.

### 2. 🕵️ Encrypted Traffic Analysis (ETA) & Application Fingerprinting
- Statistically profiles packet size distributions, burstiness indices, and temporal intervals to infer application behavior inside the encrypted tunnel **without decrypting payloads**:
  - *Interactive Shell / VoIP / Command Streams* (Low latency, fixed small frames)
  - *Bulk Encrypted Data Transfer / Database Sync* (MSS-saturated frames)
  - *HTTPS / API Web Services over IPsec* (Bimodal request-response flow)

### 3. 📉 Cryptographic Weakness & Downgrade Attack Detection
- Audits active proposals against obsolete standards:
  - ❌ **Legacy Ciphers**: Flags DES, 3DES, Blowfish, RC4.
  - ❌ **Weak Hashes**: Flags MD5, SHA-1 truncated MACs.
  - ❌ **Weak Diffie-Hellman Groups**: Flags DH Group 1 (768-bit), Group 2 (1024-bit), Group 5 (1536-bit).
  - ❌ **IKE PSK Exposure**: Audits IKE handshakes for unencrypted hash exposure in IKEv1 Aggressive Mode.

### 4. ⚛️ Post-Quantum Cryptography (PQC) Readiness Score
- Evaluates tunnel resistance against quantum computing threats based on **NSA CNSA 2.0 & NIST** recommendations.
- Generates a **Quantum Resistance Index** (e.g., `85% Quantum-Resistant (CNSA 2.0 Symmetric Tier)`).

### 5. 🗺️ MITRE ATT&CK Matrix Mapping & SIEM Integration
- Automatically correlates security findings to formal MITRE ATT&CK techniques:
  - `T1048`: Exfiltration Over Alternative Protocol (Cleartext leak detection)
  - `T1572`: Protocol Tunneling (Uncontrolled bypass transport streams)
  - `T1040`: Network Sniffing (AH unencrypted payload exposure)
  - `M1037`: Filter Network Traffic (Defensive encapsulation baseline)
- Exposes structured SIEM JSON telemetry at `/api/report/siem` for direct ingestion into **Splunk**, **Wazuh**, or **Elasticsearch**.

### 6. 📡 Real-Time Live Sniffing & One-Click Live Audit
- Auto-discovers physical and virtual network adapters (Wi-Fi, Ethernet, VPN virtual NICs).
- Sniffs wire traffic in real time, computes live Ingress/Egress throughput (Mbps), and provides an instant **"Analyze Live Feed & Generate Report"** action.

### 7. 📄 Multi-Section Certified PDF Audit Reports
- Generates professional, multi-section PDF audit reports containing Executive Summaries, Security Grades, Protocol Distribution Matrices, ETA Fingerprints, MITRE ATT&CK Tables, and Actionable Hardening Checklists.

---

## 🏗️ Technical Architecture & Project Structure

```text
sih/
├── frontend/                     # Interactive Web Dashboard
│   ├── index.html                # Home Landing Page & Engine Health Pill
│   ├── analyzer.html             # Drag & Drop PCAP Analyzer & ETA/MITRE Panels
│   ├── reports.html              # Historical Audit Archive & PDF Downloads
│   ├── live_monitor.html         # Real-time Packet Sniffer & Live Audit Engine
│   ├── about.html                # Protocol Specifications & Architecture
│   ├── settings.html             # Dynamic Cloud API URL Configuration
│   └── js/
│       └── api.js                # Universal API Gateway Resolver
├── backend/
│   ├── app.py                    # Unified Flask REST API & Static Asset Server
│   └── __init__.py
├── analyzer/                     # Core Security Engine Modules
│   ├── feature_extractor.py      # Scapy Packet Feature Extractor
│   ├── validate_features.py      # Structural Data Integrity Validator
│   ├── ipsec_detector.py         # Protocol Classifier & Counter
│   ├── security_analyzer.py      # Deep Risk Assessor & Grade Calculator
│   ├── eta_fingerprint.py        # Encrypted Traffic Analysis & Fingerprinting
│   ├── advanced_security_auditor.py # MITRE Mapping, PQC Scoring, IKE PSK Audit
│   ├── ml_predict.py             # Random Forest Inference Pipeline
│   ├── train_ml_model.py         # Model Training Pipeline
│   ├── generate_report.py        # Comprehensive JSON Report Builder
│   ├── generate_pdf_report.py    # Multi-Section PDF Report Generator (fpdf2)
│   ├── run_pipeline.py           # In-Process End-to-End Orchestrator
│   └── __init__.py
├── dataset/                      # Reference Models & Test Captures
│   ├── ipsec_ml_model.joblib     # Pre-Trained Random Forest Classifier
│   ├── ml_training_dataset.json  # Reference Feature Training Set
│   ├── final_ipsec.pcap          # Verified 100% Encrypted ESP Test Capture
│   └── varied_ipsec.pcap         # Multi-Protocol Traffic Capture
├── reports/                      # Runtime Generated Audit Reports (.json & .pdf)
├── requirements.txt              # Production Dependencies
├── .env.example                  # Environment Configuration Template
├── .gitignore                    # Git Ignore Rules
└── README.md                     # Master Documentation
```

---

## 🛠️ Quick Start Guide

### 1. Prerequisites
- **Python 3.9+** (Windows, Linux, or macOS)
- Standard `pip` package manager

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/your-username/sih-ipsec-analyzer.git
cd sih-ipsec-analyzer/sih

# Install dependencies
pip install -r requirements.txt
```

### 3. Launching the Unified Application
```bash
python backend/app.py
```
*The backend API and static frontend web interface will start together at **`http://localhost:5000`**.*

### 4. Exploring the Interface
- **Home**: `http://localhost:5000/`
- **PCAP Analyzer**: `http://localhost:5000/analyzer.html` (Upload any `.pcap` to see ETA, PQC, ML, and MITRE findings)
- **Live Monitor**: `http://localhost:5000/live_monitor.html` (Sniff live NICs and run one-click audits)
- **Reports Archive**: `http://localhost:5000/reports.html` (Download formatted PDF audit reports)

---

## 🔌 Complete REST API Reference

| Endpoint | Method | Description | Data Returned |
|---|---|---|---|
| `/api/health` | `GET` | System health check and engine status | Service status, engine version |
| `/api/analyze` | `POST` | Upload `.pcap` / `.pcapng` for instant deep analysis | Full report JSON, features, PDF link |
| `/api/report` | `GET` | Retrieve latest report or query by `?id=...` | Report JSON |
| `/api/reports` | `GET` | List all historical reports in database | Array of report summaries |
| `/api/reports/<id>/pdf` | `GET` | Download official formatted PDF audit report | Binary `application/pdf` |
| `/api/report/pdf` | `GET` | Download latest audit report as PDF | Binary `application/pdf` |
| `/api/reports/<id>/download` | `GET` | Download raw report data as JSON | JSON file attachment |
| `/api/report/siem` | `GET` | Export latest telemetry formatted for SIEM | SIEM JSON alert event |
| `/api/reports/<id>/siem` | `GET` | Export specific report for SIEM | SIEM JSON alert event |
| `/api/features` | `GET` | Retrieve extracted packet feature vectors | Array of feature dictionaries |
| `/api/live/interfaces` | `GET` | List all available physical/virtual NICs | Array of network adapters |
| `/api/live/start` | `POST` | Start real-time packet sniffing | Status, active adapter name |
| `/api/live/stop` | `POST` | Pause live packet capture | Status confirmation |
| `/api/live/packets` | `GET` | Poll live packet stream & throughput | Throughput (Mbps), packet telemetry |
| `/api/live/analyze` | `POST` | Analyze live captured packets & generate PDF | Live audit report & PDF download URL |

---

## 👥 Use Cases Across Cybersecurity Roles

| Role | Primary Workflow | Key Benefit |
|---|---|---|
| **🛡️ SOC Analyst / Blue Team** | Monitors live packet telemetry to detect cleartext leaks, split-tunneling anomalies, or unencrypted DNS queries escaping the VPN. | Instant real-time alerts on VPN tunnel failures. |
| **⚔️ Security Auditor / Red Team** | Ingests packet captures to verify IKE exchange modes, detect weak PSK exposure, and test compliance with modern cipher baselines. | Passive, non-intrusive auditing with zero network disruption. |
| **📋 CISO & Compliance Officer** | Generates certified multi-section PDF audit reports to satisfy compliance audits (**ISO 27001**, **NIST SP 800-77**, **PCI-DSS**). | One-click certified PDF evidence of encryption compliance. |
| **🌐 Network Engineer** | Analyzes MTU overhead telemetry to prevent PMTU blackholes and packet fragmentation slowdowns. | Optimizes VPN throughput and eliminates packet loss. |

---

## 🔒 Security & Deployment Notes

- **Zero VM / Localhost Dependency**: 100% self-contained pure Python architecture. Does not depend on VirtualBox, Kali Linux, root namespaces, or hardcoded paths.
- **Production Independence**: Ready for single-click deployment to **Render**, **Railway**, **AWS**, or **Docker**.
- **Privacy & Safety**: Processes captures in-memory or in isolated temporary buffers, with automatic buffer cleanup upon completion.

---

## 📄 License & Attribution

Developed for the **Smart India Hackathon (SIH)**. Distributed under the MIT License.
