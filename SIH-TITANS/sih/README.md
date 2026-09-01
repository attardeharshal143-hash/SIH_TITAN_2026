# 🛡️ TITAN: IPsec Security Intelligence & Automated Audit Platform
> **AI-Driven Deep Packet Inspection, Cryptographic Vulnerability Auditing, Multi-Moment Encrypted Traffic Analysis (ETA), Post-Quantum Readiness Scoring & MITRE ATT&CK Mapping for IPsec VPNs.**

---

## 🌟 Executive Summary & Problem Statement

Modern enterprise, banking, and defense infrastructures rely heavily on **IPsec Virtual Private Networks (VPNs)** to secure sensitive site-to-site and remote-access communications. However, security teams and SOC analysts face critical operational blindspots:

1. **The "Encrypted Black Box" Blindspot**: Standard network monitoring tools treat IPsec ESP (Protocol 50) traffic as opaque blobs, creating zero visibility into tunnel health, anti-replay synchronization, or cryptographic downgrade risks.
2. **Context Misclassification**: Conventional static audit tools falsely assume every network capture contains an IPsec VPN, mislabeling benign plaintext HTTP or DNS traffic as "tunnel leaks" or "VoIP".
3. **Silent Cleartext Leakage**: Misconfigurations (such as split-tunneling bypasses) often allow unencrypted enterprise traffic to escape the VPN tunnel unnoticed.
4. **Cryptographic Weaknesses & Downgrades**: Legacy proposals (e.g., IKEv1 Aggressive Mode hash exposures, 3DES ciphers, MD5 hashes, weak Diffie-Hellman groups) expose organizations to active adversary interception.
5. **Post-Quantum Vulnerability**: Most legacy tunnels lack quantitative assessment against upcoming quantum computing decryption threats ("Harvest Now, Decrypt Later").

**TITAN** solves these challenges by providing an **automated, context-aware cybersecurity auditing engine** that ingests any network capture (.pcap, .pcapng) or sniffs live network adapters, evaluates cryptographic posture in seconds, assigns a **Security Grade (A+ to F)**, and generates **Certified PDF Audit Reports**, **Hardened Remediation Scripts**, and **SIEM Telemetry Events**.

---

## 🚀 Key Platform Capabilities

`	ext
               ┌──────────────────────────────────────────────────────────┐
               │          INPUT: PCAP File Upload OR Live Wire Feed       │
               └────────────────────────────┬─────────────────────────────┘
                                            │
                                            ▼
               ┌──────────────────────────────────────────────────────────┐
               │                TITAN CORE INSPECTION ENGINE              │
               │                                                          │
               │  1. Deep Packet Inspection (ESP Proto 50, AH Proto 51)   │
               │  2. RFC 4301 Per-SA Anti-Replay Sequence Validation      │
               │  3. Exact Byte-Level Shannon Entropy Calculation         │
               │  4. Multi-Moment Encrypted Traffic Analysis (ETA)        │
               │  5. Operating Mode & AES-GCM-256 Cipher Auto-Inference   │
               │  6. Multi-Tier Post-Quantum (PQC) Readiness Scoring      │
               │  7. MITRE ATT&CK Matrix Mapping (T1048, T1572, T1040)    │
               │  8. 1,600-Sample Random Forest Machine Learning Model    │
               │  9. Automated Multi-Vendor Hardening Script Generator    │
               └────────────────────────────┬─────────────────────────────┘
                                            │
                                            ▼
               ┌──────────────────────────────────────────────────────────┐
               │                       OUTPUTS                            │
               │  • Interactive 7-Section Glassmorphic Web Dashboard      │
               │  • StrongSwan, Cisco IOS-XE & Fortinet Remediation CLI   │
               │  • Certified Multi-Section PDF Security Audit Report     │
               │  • Standardized SIEM JSON Event Stream (Splunk / Elastic)│
               └──────────────────────────────────────────────────────────┘
`

---

## 🔬 Core Engineering Innovations & Enhancements

### 1. 🌐 Context-Aware Protocol Reality & Zero-Mock Analysis
- **Strict Non-IPsec vs. IPsec Context Separation**:
  - For **Non-IPsec Captures** (*e.g., plain HTTP, DNS, TLS, ICMP*): Identifies the Layer-7 application flow directly (HTTP GET /index.html), assigns baseline Grade B (15/100 risk), with **0 fake SPIs, 0 fake IKE narratives, and 0 fake split-tunnel leaks**.
  - For **Genuine IPsec Captures**: Evaluates ESP encapsulation, extracts real 32-bit SPIs, tracks per-SA sequence numbers, and audits true split-tunnel leakage.

### 2. 🧮 Mathematical Shannon Entropy & Per-SA Anti-Replay
- **Byte-Level Shannon Entropy ($)**:
  H = -\sum_{i=0}^{255} p_i \log_2(p_i)
  - Encrypted ESP frames:  \approx 6.58\text{ to }7.98\text{ bits/byte}$ (Cryptographic pseudorandomness confirmed).
  - Cleartext ASCII/HTTP frames:  \approx 3.2\text{ to }4.8\text{ bits/byte}$ (Flags unencrypted transport).
- **RFC 4301 / 4303 Per-SA Sequence Monotonicity**:
  - Groups sequence numbers strictly per Security Association (per-SPI) to verify monotonic ordering ({i+1} > s_i$) and eliminate false cross-SA duplicate sequence collisions.

### 3. 🎙️ Multi-Moment Encrypted Traffic Analysis (ETA) Discrimination
Statistically profiles packet lengths, variances, burstiness indices ( = \sigma_L / \mu_L$), and quantiles to discriminate application classes inside encrypted ESP tunnels without decryption:

| Traffic Class | Typical Packet Profile | Statistical Moments | Real-World Application |
| :--- | :---: | :---: | :---: |
| **VoIP / Real-Time Voice** | \text{–}260\text{B}$ fixed audio frames | $\mu_L \approx 180\text{B}, \sigma_L < 45\text{B}, B < 0.10$ | RTP / Opus / G.711 voice calls |
| **Adaptive Video Stream** | Bursty I/P frame cadence | $\mu_L \approx 685\text{B}, \sigma_L > 220\text{B}, B > 0.35$ | H.264 / H.265 video teleconferencing |
| **Bulk Data Transfer** | MSS MTU saturating ($\\ge 1350\text{B}$) | $\mu_L > 1200\text{B}, \ge 65\% \text{ MTU packets}$ | Database replication, cloud backup |
| **Interactive Shell** | Lightweight keystroke frames | $\mu_L < 150\text{B}, 100\% < 200\text{B}$ | SSH remote management / CLI |
| **Web API / REST** | Request-response transactions | $\mu_L \approx 300\text{–}900\text{B}$, bimodal | HTTPS / REST microservices |

### 4. ⚛️ Multi-Tier Post-Quantum Cryptography (PQC) Calculation
Quantitatively measures resistance against quantum adversaries (Shor\'s and Grover\'s algorithms) based on **NSA CNSA 2.0 & NIST SP 800-77**:
\text{PQC Score} = \text{Symmetric Tier (Max 40)} + \text{KEM Tier (Max 40)} + \text{Integrity Tier (Max 20)}
- **AES-GCM-256 + Curve25519 + SHA-384**:  + 25 + 20 = \mathbf{85\% \text{ (Quantum-Resistant)}}$.
- **AH Protocol 51 (No Encryption)**:  + 10 + 10 = \mathbf{20\% \text{ (Vulnerable)}}$.
- **Non-IPsec / Plaintext**: $\mathbf{0\% \text{ (N/A)}}$.

### 5. 🔬 Precise Operating Mode & Cipher Auto-Inference (cipher_mode_infer.py)
- Dissects packet encapsulation overhead to determine:
  - **Tunnel Mode**: \text{ to }64\text{ bytes}$ overhead (Gateway-to-Gateway IP-in-IP Encapsulation).
  - **Transport Mode**: \text{ to }44\text{ bytes}$ overhead (Host-to-Host).
- Identifies symmetric ciphers via Integrity Check Value (ICV) tag length and entropy:
  - 16-byte ICV + High Entropy $\rightarrow$ **AES-GCM-256 AEAD (Galois/Counter Mode)** with 128-bit GHASH GMAC tag.

### 6. ⚡ Automated Multi-Vendor Hardening Script Generator (
emediation_generator.py)
Dynamically creates ready-to-deploy, copy-pasteable configuration files tailored to the specific audit findings:
- 🌐 **Linux StrongSwan**: swanctl.conf enforcing es256gcm16-prfsha384-ecp384-modp2048!.
- 🏢 **Cisco IOS-XE / ASA**: crypto ipsec transform-set esp-gcm 256 CLI commands with PFS Group 19.
- 🛡️ **Fortinet FortiGate**: Phase-1/Phase-2 es256gcm CLI configuration with ASIC hardware offloading.

---

## 🤖 Machine Learning Model Architecture

| Parameter | Specification |
| :--- | :--- |
| **Model Algorithm** | **Random Forest Classifier** (
_estimators = 200, max_depth = 12) |
| **Model Artifact** | sih/dataset/ipsec_ml_model.joblib |
| **Training Dataset** | sih/dataset/ml_training_dataset.json (**1,600 labeled packet feature samples**) |
| **Validation Accuracy** | **100.00%** (5-Fold Stratified Cross-Validation) |
| **Feature Vector (10D)** | packet_length, ip_version, ip_proto, src_port, dst_port, ike_candidate, esp, h, icmp, dns |

---

## 🏗️ Project Directory Structure

`	ext
sih/
├── frontend/                     # Interactive Web Dashboard (HTML5 / Tailwind CSS / JS)
│   ├── index.html                # Home Landing Page & Quick Output Audit Links
│   ├── analyzer.html             # Drag & Drop PCAP Ingestion & Progress Tracker
│   ├── report_viewer.html        # 7-Section Comprehensive Audit Report Viewer
│   ├── reports.html              # Dynamic Historical Reports Archive & Bento Grid
│   ├── live_monitor.html         # Real-time Packet Sniffer & Live Audit Engine
│   ├── about.html                # Platform Architecture & Standards Reference
│   ├── settings.html             # Platform Preferences & Threshold Synchronizer
│   └── js/
│       ├── api.js                # Universal API Gateway Resolver
│       └── titan-turbo.js        # UI Navigation & Animation Engine
├── backend/
│   ├── app.py                    # Unified Flask REST API & Socket Sniffer
│   └── __init__.py
├── analyzer/                     # Core Forensic & ML Engine Modules
│   ├── feature_extractor.py      # Scapy Packet Dissector & Shannon Entropy Math
│   ├── security_analyzer.py      # Risk Scoring, Grade Calculator & Per-SA Anti-Replay
│   ├── eta_fingerprint.py        # Multi-Moment Statistical ETA Discrimination
│   ├── cipher_mode_infer.py      # Tunnel/Transport Mode & AES-GCM Cipher Inference
│   ├── remediation_generator.py  # Multi-Vendor Remediation Script Generator
│   ├── advanced_security_auditor.py # PQC Tier Scoring & MITRE ATT&CK Mapping
│   ├── ml_predict.py             # Random Forest Inference Pipeline
│   ├── train_ml_model.py         # 1,600-Sample Model Trainer with 5-Fold CV
│   ├── generate_report.py        # Comprehensive JSON Report Builder
│   ├── generate_pdf_report.py    # Multi-Section PDF Report Generator (fpdf2)
│   ├── validate_features.py      # Structural Data Integrity Validator
│   ├── run_pipeline.py           # End-to-End Orchestrator Pipeline
│   └── __init__.py
├── dataset/                      # Reference Models & Test Captures
│   ├── ipsec_ml_model.joblib     # Pre-Trained 200-Tree Random Forest Model
│   ├── ml_training_dataset.json  # 1,600-Sample Labeled Training Dataset
│   ├── final_ipsec.pcap          # Ground-Truth 100% Encrypted ESP Capture (Grade A+)
│   ├── test_voip_esp.pcap        # Ground-Truth VoIP ESP Capture (Mean 179B, Std 9B)
│   ├── test_video_esp.pcap       # Ground-Truth Video ESP Capture (Bursty I/P Frames)
│   ├── test_bulk_esp.pcap        # Ground-Truth Bulk Transfer ESP Capture (MSS 1420B)
│   ├── test_plain_http.pcap      # Ground-Truth Plain HTTP Capture (Non-IPsec Baseline)
│   └── varied_ipsec.pcap         # Multi-Protocol Traffic Capture
├── reports/                      # Runtime Generated JSON & PDF Audit Reports
├── requirements.txt              # Production Dependencies
└── README.md                     # Master Documentation
`

---

## 🛠️ Quick Start & Local Execution

### 1. Prerequisites
- **Python 3.9+** (Windows, Linux, or macOS)
- Standard pip package manager

### 2. Installation
`ash
# Clone the repository
git clone https://github.com/attardeharshal143-hash/SIH_TITAN_2026.git
cd SIH_TITAN_2026/sih

# Install required dependencies
pip install -r requirements.txt
`

### 3. Launch the Platform
`ash
python backend/app.py
`
*The unified backend and web interface will start at **http://localhost:5000**.*

### 4. Direct Web Routes
- **Home**: http://localhost:5000/
- **PCAP Analyzer**: http://localhost:5000/analyzer.html
- **Reports Dashboard**: http://localhost:5000/reports.html
- **Live Packet Monitor**: http://localhost:5000/live_monitor.html
- **Platform Settings**: http://localhost:5000/settings.html
- **Architecture & About**: http://localhost:5000/about.html

---

## 🔌 Complete REST API Reference

| Endpoint | Method | Description | Data Returned |
|---|---|---|---|
| /api/health | GET | System health check and engine status | Service status, engine version |
| /api/analyze | POST | Upload .pcap / .pcapng for instant deep analysis | Full report JSON, features, PDF link |
| /api/report | GET | Retrieve latest report or query by ?id=... | Complete report JSON |
| /api/reports | GET | List all historical reports in database | Array of report summaries |
| /api/reports/<id>/pdf | GET | Download official formatted PDF audit report | Binary pplication/pdf stream |
| /api/reports/<id>/remediation | GET | Download remediation scripts (?target=cisco|strongswan|fortinet) | Script text / JSON |
| /api/reports/<id>/siem | GET | Export report telemetry formatted for SIEM (ECS v1.12) | SIEM JSON alert event |
| /api/reports/clear | POST | Purge all stored reports and PDFs | Confirmation status |
| /api/settings | GET/POST| Fetch or update runtime platform settings | Settings JSON object |
| /api/guide/pdf | GET | Download the Master Team Guide PDF | Binary pplication/pdf stream |
| /api/compliance/pdf | GET | Download Problem Statement Compliance Report PDF | Binary pplication/pdf stream |
| /api/live/interfaces | GET | List all physical and virtual network adapters | Array of network interfaces |
| /api/live/start | POST | Start real-time packet capture on specified NIC | Status, active adapter name |
| /api/live/stop | POST | Pause live packet capture | Status confirmation |
| /api/live/packets | GET | Poll live packet stream & throughput metrics | Ingress/Egress Mbps, packet array |
| /api/live/analyze | POST | Analyze live captured frames & generate report | Report JSON and PDF URL |

---

## 📄 License & Attribution

Developed for the **Smart India Hackathon (SIH 2026)**. Distributed under the MIT License.
