# 🛡️ TITAN: IPsec Security Intelligence & Automated Audit Platform
> **AI-Driven Deep Packet Inspection, Multi-Tunnel Security Association Partitioning, Cryptographic Vulnerability Auditing, Multi-Moment Encrypted Traffic Analysis (ETA), Post-Quantum Readiness Scoring & MITRE ATT&CK Mapping for IPsec VPNs.**

---

## 🌟 Executive Summary & Problem Statement

Modern enterprise, banking, and defense infrastructures rely heavily on **IPsec Virtual Private Networks (VPNs)** to secure sensitive site-to-site and remote-access communications. However, security teams and SOC analysts face critical operational blindspots:

1. **The "Encrypted Black Box" Blindspot**: Standard network monitoring tools treat IPsec ESP (Protocol 50) traffic as opaque blobs, creating zero visibility into tunnel health, anti-replay synchronization, or cryptographic downgrade risks.
2. **Multi-Tunnel / Per-SA Conflation**: Legacy audit tools treat multi-tunnel captures as a single global pass, causing strong tunnels to mask weak proposals, blending unrelated traffic distributions, and duplicating bidirectional packet rows.
3. **Cryptographic Weaknesses & Downgrades**: Legacy proposals (e.g., IKEv1 Aggressive Mode hash exposures, DES/3DES ciphers, MD5 hashes, weak Diffie-Hellman groups) expose organizations to active adversary interception and Logjam/Shor attacks.
4. **Silent Cleartext Leakage**: Misconfigurations (such as split-tunneling bypasses) often allow unencrypted enterprise traffic to escape the VPN tunnel unnoticed.
5. **Post-Quantum Vulnerability**: Most enterprise tunnels lack quantitative assessment against upcoming quantum computing decryption threats ("Harvest Now, Decrypt Later").

**TITAN** solves these challenges by providing an **automated, context-aware cybersecurity auditing engine** that partitions captures into individual Security Associations (SAs), evaluates cryptographic posture and ETA profiles per tunnel in seconds, assigns a **Security Grade (A+ to F)**, and generates **Certified PDF Audit Reports**, **Hardened Remediation Scripts**, and **SIEM Telemetry Events**.

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
               │  1. Multi-Tunnel Security Association (SA) Partitioner   │
               │  2. Deep IKEv1 (ISAKMP) & IKEv2 Binary Transform Parser  │
               │  3. RFC 4301 Per-SA Anti-Replay Sequence Validation      │
               │  4. Exact Byte-Level Shannon Entropy Calculation         │
               │  5. Multi-Moment Encrypted Traffic Analysis (ETA)        │
               │  6. Unified IKE-First Cipher & Mode Auto-Inference       │
               │  7. Multi-Tier Post-Quantum (PQC) Readiness Scoring      │
               │  8. Hard Cryptographic Downgrade Gating (Grade C/F Cap)  │
               │  9. MITRE ATT&CK Matrix Mapping (T1048.003, T1040)       │
               │ 10. 1,600-Sample Random Forest Machine Learning Model    │
               │ 11. Automated Multi-Vendor Hardening Script Generator    │
               └────────────────────────────┬─────────────────────────────┘
                                            │
                                            ▼
               ┌──────────────────────────────────────────────────────────┐
               │                       OUTPUTS                            │
               │  • Interactive 7-Section Glassmorphic Web Dashboard      │
               │  • Partitioned Per-SA Multi-Tunnel Breakdown Table       │
               │  • Dynamic Grade Color Themes (Emerald, Blue, Amber, Red)│
               │  • StrongSwan, Cisco IOS-XE & Fortinet Remediation CLI   │
               │  • Fresh Certified PDF Security Audit Report (fpdf2)     │
               │  • Standardized SIEM JSON Event Stream (Elastic / Splunk)│
               └──────────────────────────────────────────────────────────┘
`

---

## 🔬 Core Engineering Innovations & Architecture

### 1. 🌐 Multi-Tunnel / Per-Security Association (Per-SA) Partitioning Engine (	unnel_partitioner.py)
- **Strict Per-SPI Deduplication**: Buckets capture packets strictly by unique 32-bit SPI (spi_key), completely eliminating 2x bidirectional row explosion.
- **4-Tier IKE Proposal Correlation Waterfall**:
  1. **Tier 1 (Direct Child SA SPI)**: Matches the 32-bit Child SPI negotiated in IKE SA Proposals / Notify payloads.
  2. **Tier 2 (Exact Bidirectional IP Endpoint Pair)**: Matches 	uple(sorted([src_ip, dst_ip])) isolated strictly to that SA's packet stream.
  3. **Tier 3 (Single Endpoint IP)**: Matches against either local or remote gateway IP.
  4. **Tier 4 (Sequential Proposal Index)**: Correlates SA #N with Handshake #N when multiple concurrent handshakes are present.
- **Independent Per-SA Crypto Posture**: Each unique SPI independently computes its own **Inferred Cipher**, **PQC Score**, **PQC Status**, **Anti-Replay Monotonicity**, and **ETA Application Profile**.

### 2. 🔑 Deep IKEv1 (ISAKMP) & IKEv2 Binary Dissector (ike_dissector.py)
- Deep binary unpacking supporting both **IKEv1 (ISAKMP RFC 2408/2409)** and **IKEv2 (RFC 7296)**.
- Walks all 4 transform substructures (ENCR, PRF, INTEG, DH) without premature termination.
- Dissects both Basic and Variable-length TLV attributes:
  - **Encryption**: DES-CBC (56b), IDEA-CBC (128b), Blowfish, 3DES-CBC (168b), AES-CBC (128/256b), AES-GCM (128/256b), ChaCha20-Poly1305.
  - **Key Exchange Groups**: MODP-768 (Group 1), MODP-1024 (Group 2), MODP-1536 (Group 5), MODP-2048 (Group 14), Curve25519 (Group 19), Curve384 (Group 20), ML-KEM-768/1024 (Kyber Groups 31/32).
  - **Integrity / PRF**: HMAC-MD5-96, HMAC-SHA1-96, HMAC-SHA2-256/384/512.

### 3. 🚨 Hard Cryptographic Downgrade Gating & Worst-Case Aggregation (security_analyzer.py & generate_report.py)
- **Independent Compliance Gating**: If any active SA negotiates DES, 3DES, RC4, MD5, or small MODP groups (Group 1/2/5):
  - Overall Capture Grade is capped at **Grade C (or Grade F)**.
  - Risk Score is raised to **$\ge 75 / 100$ (HIGH or CRITICAL)**.
  - Compliance Status is set to **NON-COMPLIANT (Cryptographic Downgrade in SA <SPI>)**.
- **Unified Cipher Inference**: Eliminates contradictory guesses; Inferred Cipher deterministically reads parsed IKE transform data.

### 4. 🧮 Mathematical Shannon Entropy & Anti-Replay Monotonicity
- **Byte-Level Shannon Entropy ($)**:
  H = -\sum_{i=0}^{255} p_i \log_2(p_i)
  - Encrypted ESP frames:  pprox 6.58	ext{ to }7.98	ext{ bits/byte}$ (Cryptographic pseudorandomness confirmed).
  - Cleartext ASCII/HTTP frames:  pprox 3.2	ext{ to }4.8	ext{ bits/byte}$ (Flags unencrypted transport).
- **RFC 4301 / 4303 Per-SA Sequence Validation**:
  - Validates strictly increasing sequence numbers ({i+1} > s_i$) and detects packet replay injection attacks ( = s_j$).

### 5. 🎙️ Multi-Moment Encrypted Traffic Analysis (ETA) Discrimination
Statistically profiles packet lengths, variances, burstiness indices ( = \sigma_L / \mu_L$), and quantiles to discriminate application classes inside encrypted ESP tunnels without decryption:

| Traffic Class | Typical Packet Profile | Statistical Moments | Real-World Application |
| :--- | :---: | :---: | :---: |
| **VoIP / Real-Time Voice** | 	ext{–}260	ext{B}$ fixed audio frames | $\mu_L pprox 180	ext{B}, \sigma_L < 45	ext{B}, B < 0.10$ | RTP / Opus / G.711 voice calls |
| **Adaptive Video Stream** | Bursty I/P frame cadence | $\mu_L pprox 685	ext{B}, \sigma_L > 220	ext{B}, B > 0.35$ | H.264 / H.265 video teleconferencing |
| **Bulk Data Transfer** | MSS MTU saturating ($\ge 1350	ext{B}$) | $\mu_L > 1200	ext{B}, \ge 65\% 	ext{ MTU packets}$ | Database replication, cloud backup |
| **Interactive Shell** | Lightweight keystroke frames | $\mu_L < 150	ext{B}, 100\% < 200	ext{B}$ | SSH remote management / CLI |
| **Web API / REST** | Request-response transactions | $\mu_L pprox 300	ext{–}900	ext{B}$, bimodal | HTTPS / REST microservices |

### 6. ⚛️ Multi-Tier Post-Quantum Cryptography (PQC) Calculation
Quantitatively measures resistance against quantum adversaries (Shor's and Grover's algorithms) based on **NSA CNSA 2.0 & NIST SP 800-77**:
	ext{PQC Score} = 	ext{Symmetric Tier (Max 40)} + 	ext{KEM Tier (Max 40)} + 	ext{Integrity Tier (Max 20)}
- **AES-GCM-256 + ML-KEM-768 + SHA-384**:  + 40 + 20 = \mathbf{100\% 	ext{ (CNSA 2.0 Complete)}}$.
- **AES-GCM-256 + Curve25519 + SHA-384**:  + 25 + 20 = \mathbf{85\% 	ext{ (CNSA 2.0 Symmetric Tier)}}$.
- **DES-CBC + MODP-768 (Group 1) + MD5**:  + 0 + 0 = \mathbf{0\% 	ext{ (QUANTUM-VULNERABLE Downgrade)}}$.

---

## 🧪 Comprehensive 5-PCAP Regression Test Matrix

| Test Capture File | Active SAs | Overall Grade | PQC Score | Inferred Cipher | ETA Classification | Ground-Truth Verification |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **1. synthetic_ipsec_traffic.pcap** | 1 SA | **Grade A+** (10) | 85% Safe | AES-GCM-256 AEAD | Web API / REST | Baseline healthy single tunnel (100% Encapsulated) |
| **2. synthetic_ipsec_voip_only.pcap** | 1 SA | **Grade A+** (10) | 85% Safe | AES-GCM-256 AEAD | VoIP Voice Stream | Fixed 180B cadence, low jitter audio flow |
| **3. synthetic_ipsec_weak_cipher.pcap** | 1 SA | **Grade C** (75) | 0% Safe | DES-CBC (56-bit) | Web API / REST | Standalone weak cipher downgrade gating |
| **4. synthetic_ipsec_multi_hazard.pcap** | 1 SA | **Grade F** (100) | 0% Safe | DES-CBC (56-bit) | Web API / REST | Multi-hazard: DES + AH + 5 leaks + 10 replays |
| **5. synthetic_ipsec_three_tunnels.pcap** | 3 SAs | **Grade C** (75) | 0% Safe *(Worst)* | DES-CBC *(Worst)* | SA #1: VoIP (100% PQC)<br>SA #2: Video (85% PQC)<br>SA #3: Bulk (0% PQC) | 3 concurrent independent tunnels with per-SA crypto isolation |

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
│   ├── report_viewer.html        # 7-Section Report Viewer with Dynamic Grade Color Badges & Per-SA Table
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
│   ├── tunnel_partitioner.py     # Multi-Tunnel SA Partitioner & 4-Tier IKE Correlation Engine
│   ├── ike_dissector.py          # Deep IKEv1 (ISAKMP) & IKEv2 Binary Transform Parser
│   ├── feature_extractor.py      # Scapy Packet Dissector & Shannon Entropy Math
│   ├── security_analyzer.py      # Hard Cryptographic Downgrade Gating & Anti-Replay Validation
│   ├── eta_fingerprint.py        # Multi-Moment Statistical ETA Discrimination
│   ├── cipher_mode_infer.py      # Unified IKE-First Cipher & Operating Mode Inference
│   ├── remediation_generator.py  # Multi-Vendor Remediation Script Generator (StrongSwan/Cisco/Fortinet)
│   ├── advanced_security_auditor.py # PQC Tier Scoring & MITRE ATT&CK Mapping
│   ├── ml_predict.py             # Random Forest Inference Pipeline
│   ├── train_ml_model.py         # 1,600-Sample Model Trainer with 5-Fold CV
│   ├── generate_report.py        # Comprehensive JSON Report Builder with Worst-Case Aggregation
│   ├── generate_pdf_report.py    # Fresh Multi-Section PDF Report Generator with Multi-SA Tables (fpdf2)
│   ├── validate_features.py      # Structural Data Integrity Validator
│   ├── run_pipeline.py           # End-to-End Orchestrator Pipeline
│   └── __init__.py
├── dataset/                      # Reference Models & Test Captures
│   ├── ipsec_ml_model.joblib     # Pre-Trained 200-Tree Random Forest Model
│   ├── ml_training_dataset.json  # 1,600-Sample Labeled Training Dataset
│   ├── synthetic_ipsec_traffic.pcap       # Ground-Truth Baseline Capture (Grade A+)
│   ├── synthetic_ipsec_voip_only.pcap     # Ground-Truth VoIP Capture (Mean 180B)
│   ├── synthetic_ipsec_weak_cipher.pcap   # Ground-Truth Standalone Weak Cipher (Grade C)
│   ├── synthetic_ipsec_multi_hazard.pcap  # Ground-Truth Multi-Hazard (Grade F)
│   └── synthetic_ipsec_three_tunnels.pcap # Ground-Truth 3 Concurrent Independent Tunnels
├── reports/                      # Runtime Generated JSON & Fresh PDF Audit Reports
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
- **Home**: [http://localhost:5000/](http://localhost:5000/)
- **PCAP Analyzer**: [http://localhost:5000/analyzer.html](http://localhost:5000/analyzer.html)
- **Reports Dashboard**: [http://localhost:5000/reports.html](http://localhost:5000/reports.html)
- **Live Packet Monitor**: [http://localhost:5000/live_monitor.html](http://localhost:5000/live_monitor.html)
- **Platform Settings**: [http://localhost:5000/settings.html](http://localhost:5000/settings.html)
- **Architecture & About**: [http://localhost:5000/about.html](http://localhost:5000/about.html)

---

## 🔌 Complete REST API Reference

| Endpoint | Method | Description | Data Returned |
|---|---|---|---|
| /api/health | GET | System health check and engine status | Service status, engine version |
| /api/analyze | POST | Upload .pcap / .pcapng for instant deep audit | Full report JSON, features, PDF link |
| /api/report | GET | Retrieve latest report or query by ?id=... | Complete report JSON |
| /api/reports | GET | List all historical reports in database | Array of report summaries |
| /api/reports/<id>/pdf | GET | Fresh on-the-fly zero-cache certified PDF download | Binary pplication/pdf stream |
| /api/reports/<id>/remediation | GET | Download remediation scripts (?target=cisco\|strongswan\|fortinet) | Script text / JSON |
| /api/reports/<id>/siem | GET | Export report telemetry formatted for SIEM (ECS v1.12) | SIEM JSON alert event |
| /api/reports/clear | POST | Purge all stored reports and PDFs | Confirmation status |
| /api/settings | GET/POST| Fetch or update runtime platform settings | Settings JSON object |
| /api/guide/pdf | GET | Download Master Team Guide PDF | Binary pplication/pdf stream |
| /api/compliance/pdf | GET | Download Compliance Blueprint PDF | Binary pplication/pdf stream |
| /api/live/interfaces | GET | List all physical and virtual network adapters | Array of network interfaces |
| /api/live/start | POST | Start real-time packet capture on specified NIC | Status, active adapter name |
| /api/live/stop | POST | Pause live packet capture | Status confirmation |
| /api/live/packets | GET | Poll live packet stream & throughput metrics | Ingress/Egress Mbps, packet array |
| /api/live/analyze | POST | Analyze live captured frames & generate report | Report JSON and PDF URL |

---

## 📄 License & Attribution

Developed for the **Smart India Hackathon (SIH 2026)**. Distributed under the MIT License.
