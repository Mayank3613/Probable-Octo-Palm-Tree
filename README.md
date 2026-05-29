# 🛡️ Probable-Octo-Palm-Tree

> An Advanced Browser & Network Threat Attribution Platform designed to detect, analyze, attribute, and automatically respond to malicious websites, phishing campaigns, suspicious infrastructure, and hidden attacker networks.

![Python](https://img.shields.io/badge/Python-3.14+-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-teal?logo=fastapi)
![JavaScript](https://img.shields.io/badge/Vanilla_JS-ES6-yellow?logo=javascript)
![HTML/CSS](https://img.shields.io/badge/UI-TailwindCSS-cyan?logo=tailwindcss)
![Security](https://img.shields.io/badge/Security-Advanced-red?logo=security)

Probable-Octo-Palm-Tree is a hybrid cybersecurity platform that combines:
- Browser extension–based threat detection
- System-wide traffic interception
- CDN/origin attribution
- AI-powered threat intelligence
- Real-time behavioral monitoring
- Self-healing browser security

---

## 📋 Table of Contents
- [Features](#-features)
- [System Architecture](#-system-architecture)
- [Project Structure](#-project-structure)
- [Technology Stack](#-technology-stack)
- [Installation & Setup](#-installation)
- [Core Modules](#-core-modules)
- [Security Features](#-security-features)
- [API Endpoints](#-api-endpoints)
- [AI Models](#-ai-models)
- [Development Roadmap](#-development-roadmap)
- [Security & Legal Notice](#-security--legal-notice)

---

## ✨ Features

### 🕸️ Browser Security Engine
- Real-time URL analysis
- Phishing detection
- DOM & JavaScript monitoring
- Hidden iframe detection
- Cookie/session protection
- Download scanning
- WebSocket monitoring
- Browser API interception

### 📡 Network Monitoring Engine
- Packet capture
- DNS monitoring
- TLS fingerprinting
- Process-to-network mapping
- Traffic correlation
- Fast-flux detection
- Suspicious infrastructure detection

### 🌐 Attribution Engine
- CDN bypass analysis
- Passive DNS correlation
- ASN mapping
- Certificate correlation
- Infrastructure clustering
- Hidden backend discovery
- Threat relationship mapping

### 🧠 AI & Threat Intelligence
- URL reputation scoring
- Behavioral anomaly detection
- Infrastructure graph AI
- Threat classification
- ML-based phishing detection
- Attack pattern recognition

### 🛡️ Self-Healing Security
- Automatic tab isolation
- Session invalidation
- Cookie cleanup
- Browser rollback
- DNS sinkholing
- IP blocking
- Process quarantine

---

## 🏗️ System Architecture

```text
┌───────────────────────────────────────────────┐
│               Browser Extension               │
│-----------------------------------------------│
│ URL Analysis                                  │
│ DOM Monitoring                                │
│ Script Detection                              │
│ Session Protection                            │
└──────────────────────┬────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────┐
│          Local Security Agent                 │
│-----------------------------------------------│
│ Packet Capture                                │
│ DNS Monitoring                                │
│ TLS Fingerprinting                            │
│ Process Mapping                               │
│ Traffic Correlation                           │
└──────────────────────┬────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────┐
│           Attribution Engine                  │
│-----------------------------------------------│
│ Passive DNS                                   │
│ Certificate Analysis                          │
│ CDN Correlation                               │
│ Infrastructure Mapping                        │
└──────────────────────┬────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────┐
│            Cloud AI Platform                  │
│-----------------------------------------------│
│ Threat Intelligence                           │
│ ML Classification                             │
│ Risk Scoring                                  │
│ Attack Pattern Detection                      │
└───────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```text
probable-octo-palm-tree/
│
├── browser-extension/
├── local-agent/
├── attribution-engine/
├── backend-api/
├── ai-engine/
├── dashboard/
├── sandbox/
├── databases/
├── deployment/
├── docs/
└── tests/
```

---

## 🛠️ Technology Stack

### Frontend
| Technology | Purpose |
|---|---|
| TypeScript | Browser extension |
| React | Dashboard |
| Next.js | Frontend framework |
| TailwindCSS | UI styling |

### Backend
| Technology | Purpose |
|---|---|
| FastAPI | REST API |
| Python | AI/ML backend |
| Rust | Packet engine |
| Redis | Cache |
| PostgreSQL | Database |
| Elasticsearch | Telemetry search |
| Neo4j | Infrastructure graph |

### Networking & Security
| Tool | Purpose |
|---|---|
| WinDivert | Packet interception |
| Npcap | Packet capture |
| Wireshark | Traffic analysis |
| JA3 | TLS fingerprinting |
| eBPF | Linux monitoring |

### AI/ML
| Framework | Purpose |
|---|---|
| PyTorch | Deep learning |
| TensorFlow | ML models |
| Scikit-learn | Classification |
| XGBoost | Threat scoring |

---

## 🚀 Installation

### Prerequisites
Install the following software:
- Node.js
- Python 3.11+
- Rust
- Docker
- Git
- Npcap

### Clone Repository
```bash
git clone https://github.com/Mayank3613/Probable-Octo-Palm-Tree.git
cd Probable-Octo-Palm-Tree
```

### Setup Backend API
```bash
cd backend-api
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Setup Browser Extension
```bash
cd browser-extension
npm install
npm run build
```
Load extension in Chrome: `Chrome → Extensions → Developer Mode → Load Unpacked`

### Setup Dashboard
```bash
cd dashboard
npm install
npm run dev
```

### Setup Local Security Agent
```bash
cd local-agent
cargo build --release
```

---

## 📦 Core Modules

### Browser Extension
Responsible for: Browser monitoring, DOM analysis, Threat detection, Session protection, Browser self-healing.
*Main files: `background.js`, `content.js`, `url-analyzer.js`, `threat-detector.js`, `self-healing.js`*

### Local Security Agent
Responsible for: Packet interception, DNS analysis, TLS fingerprinting, Process correlation, Network telemetry.
*Main files: `packet_capture.rs`, `dns_monitor.rs`, `tls_fingerprint.rs`, `traffic_correlator.rs`*

### Attribution Engine
Responsible for: Infrastructure mapping, Passive DNS analysis, Certificate correlation, CDN attribution.
*Main files: `ip_cluster.py`, `cert_correlator.py`, `backend_locator.py`*

### AI Engine
Responsible for: Threat classification, URL scoring, Infrastructure AI, Behavioral detection.
*Main files: `train_url_model.py`, `predictor.py`, `scoring_engine.py`*

---

## 🔐 Security Features

### Threat Detection
- Phishing domains, Malicious redirects, Suspicious JavaScript, Malware traffic, Fake login forms, Session hijacking.

### Infrastructure Attribution
- Hidden origin detection, CDN correlation, TLS analysis, ASN mapping, Shared attacker infrastructure.

### Self-Healing
- Session cleanup, Cookie invalidation, Cache clearing, Process isolation, Automatic remediation.

---

## 🔌 API Endpoints

**Threat APIs**
```http
POST /scan/url
POST /scan/file
POST /scan/traffic
```

**Attribution APIs**
```http
POST /attribution/domain
POST /attribution/ip
```

**Telemetry APIs**
```http
POST /telemetry/upload
GET /alerts/live
```

---

## 🧠 AI Models

### URL Classification
* **Features:** Entropy, Redirect chains, Domain age, Special characters, DNS anomalies
* **Models:** Random Forest, XGBoost

### Traffic Anomaly Detection
* **Detects:** Malware traffic, Beaconing, Exfiltration, Botnet communication
* **Models:** LSTM, Autoencoders

### Infrastructure Graph AI
* **Uses:** Graph Neural Networks
* **Purpose:** Discover attacker relationships, Cluster malicious infrastructure

---

## 🗺️ Development Roadmap

- **Phase 1:** Browser extension MVP, URL monitoring, Rule-based detection
- **Phase 2:** Packet interception, DNS monitoring, TLS fingerprinting
- **Phase 3:** Traffic correlation, Process mapping, Infrastructure attribution
- **Phase 4:** AI threat scoring, Behavioral analysis, Attack clustering
- **Phase 5:** Self-healing automation, Enterprise deployment, Distributed intelligence

---

## 🚢 Deployment

**Docker**
```bash
docker-compose up --build
```
**Kubernetes**
Deployment files are available in `deployment/kubernetes/`

---

## 🧪 Testing

- **Backend:** `pytest`
- **Frontend:** `npm test`
- **Rust Agent:** `cargo test`

---

## 🔮 Future Enhancements
- Zero-day behavioral detection
- Autonomous malware analysis
- Distributed threat intelligence
- Browser memory inspection
- Cross-device synchronization
- AI-powered forensic reports
- SOC integration

---

## ⚖️ Security & Legal Notice
This project is intended strictly for Cybersecurity research, Threat intelligence, Defensive security, Infrastructure attribution, Malware analysis, and Educational purposes. Unauthorized monitoring or misuse against systems without permission may violate local laws and regulations.

---

### License
MIT License

### Author
**Probable-Octo-Palm-Tree Security Research Project**
*Advanced Browser & Network Threat Attribution Framework*
