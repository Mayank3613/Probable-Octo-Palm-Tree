# Probable-Octo-Palm-Tree

> An Advanced Browser & Network Threat Attribution Platform designed to detect, analyze, attribute, and automatically respond to malicious websites, phishing campaigns, suspicious infrastructure, and hidden attacker networks.

![Python](https://img.shields.io/badge/Python-3.14+-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-teal?logo=fastapi)
![JavaScript](https://img.shields.io/badge/Vanilla_JS-ES6-yellow?logo=javascript)
![scikit-learn](https://img.shields.io/badge/ML-scikit--learn-orange?logo=scikitlearn)
![Chrome](https://img.shields.io/badge/Chrome-MV3-green?logo=googlechrome)
![Security](https://img.shields.io/badge/Security-Advanced-red?logo=security)

Probable-Octo-Palm-Tree is a hybrid cybersecurity platform that combines:
- Browser extension-based threat detection (Chrome Manifest V3)
- System-wide network connection monitoring
- CDN/origin attribution & infrastructure mapping
- AI/ML-powered threat intelligence (Random Forest)
- Real-time behavioral monitoring
- Self-healing browser security

---

## Table of Contents
- [Features](#-features)
- [System Architecture](#-system-architecture)
- [Project Structure](#-project-structure)
- [Technology Stack](#-technology-stack)
- [Installation & Setup](#-installation--setup)
- [One-Click Launch](#-one-click-launch)
- [Core Modules](#-core-modules)
- [Security Features](#-security-features)
- [API Endpoints](#-api-endpoints)
- [AI Engine](#-ai-engine)
- [Testing & Detection Rate](#-testing--detection-rate)
- [Development Roadmap](#-development-roadmap)
- [Security & Legal Notice](#%EF%B8%8F-security--legal-notice)

---

## Features

### Browser Security Engine
- Real-time URL analysis with 100+ heuristic signals
- Phishing detection (brand typosquatting, homoglyph attacks, Punycode/IDN)
- DOM & JavaScript monitoring (MutationObserver + Shadow DOM inspection)
- Hidden iframe detection (invisible/off-screen/zero-size)
- Cookie/session protection (JWT scanning, session fixation detection)
- Download scanning (file type, MIME validation, VirusTotal integration)
- WebSocket monitoring (Proxy-based interception)
- Browser API interception (fetch, XHR, document.cookie hooks)
- Suspicious redirect chain detection (5+ redirects in 8s)
- Self-healing: automatic tab quarantine, cookie purge, storage cleanup

### Network Monitoring Engine
- Real-time system network connection monitoring via `psutil`
- Process-to-network mapping (identifies which process is making connections)
- Suspicious process detection (PowerShell, cmd, certutil, etc.)
- Automatic telemetry reporting to the backend API

### Attribution Engine
- CDN bypass and origin server discovery
- DNS A/AAAA/MX/NS record resolution
- WHOIS lookup and registrar analysis
- Infrastructure mapping (IP, ASN, nameservers, country)
- Certificate transparency analysis

### AI & Threat Intelligence
- URL reputation scoring (Random Forest classifier)
- Feature extraction: entropy, length, subdomains, suspicious keywords, TLD analysis
- Hybrid scoring: 60% rule-based + 40% ML-based blended scores
- 99% detection rate across live malware feeds (URLhaus, Shodan TLS)

### Self-Healing Security
- Automatic tab isolation for critical threats
- Session invalidation (localStorage + sessionStorage cleanup)
- Cookie purge for malicious domains
- Redirect to quarantine page with bypass/trust options
- User-controlled whitelist for false positive management

---

## System Architecture

```text
+-----------------------------------------------+
|           Browser Extension (MV3)             |
|-----------------------------------------------|
| URL Analyzer    | Threat Detector             |
| API Interceptor | Session Monitor             |
| Download Scanner| Logger (Token Bucket)       |
| Content Script  | Inject.js (MAIN world)      |
+-------------------+---------------------------+
                    |
                    v
+-----------------------------------------------+
|           Backend API (FastAPI)                |
|-----------------------------------------------|
| /telemetry/upload | /scan/url                 |
| /alerts/live      | /alerts/stats             |
| /attribution/domain                           |
+-------------------+---------------------------+
                    |
          +---------+---------+
          |                   |
          v                   v
+-----------------+  +-----------------+
| AI Engine       |  | Local Agent     |
| (scikit-learn)  |  | (psutil)        |
| Port 8001       |  | Network Monitor |
| Random Forest   |  | Process Tracker |
+-----------------+  +-----------------+
          |
          v
+-----------------+
| Dashboard       |
| (Vite + JS)     |
| Port 3000       |
| Chart.js        |
+-----------------+
```

---

## Project Structure

```text
probable-octo-palm-tree/
|
+-- browser-extension/     # Chrome MV3 extension
|   +-- modules/           # ES6 security modules
|   |   +-- url-analyzer.js
|   |   +-- threat-detector.js
|   |   +-- api-interceptor.js
|   |   +-- session-monitor.js
|   |   +-- download-scanner.js
|   |   +-- logger.js
|   +-- background.js      # Service worker
|   +-- content.js         # Content script orchestrator
|   +-- inject.js          # MAIN world API hooks
|   +-- popup.html/js      # Extension popup UI
|   +-- blocked.html       # Quarantine page
|   +-- manifest.json      # Manifest V3
|
+-- backend-api/           # FastAPI REST API
|   +-- app/
|   |   +-- main.py        # Application entry point
|   |   +-- routers/       # API route handlers
|   |   +-- services/      # URL analyzer, domain lookup
|   |   +-- models.py      # Pydantic data models
|   |   +-- database.py    # SQLite via aiosqlite
|   +-- tests/             # pytest test suite
|
+-- ai-engine/             # ML classification service
|   +-- app.py             # FastAPI inference API
|   +-- train.py           # Model training script
|   +-- features.py        # Feature extraction
|   +-- model.joblib       # Trained Random Forest model
|
+-- attribution-engine/    # Infrastructure attribution
|   +-- attribution.py     # DNS + WHOIS + CDN bypass
|
+-- dashboard/             # Threat intelligence dashboard
|   +-- index.html         # Entry point
|   +-- src/css/           # Design system (variables, components)
|   +-- src/js/            # Modules, views, charts
|
+-- local-agent/           # System network monitor
|   +-- agent_main.py      # psutil-based connection tracker
|
+-- start_all.py           # One-click launcher (all platforms)
+-- start.bat              # Windows launcher
+-- start.sh               # macOS/Linux launcher
+-- UPDATE_LOG.md          # Chronological development log
```

---

## Technology Stack

### Frontend & Extension
| Technology | Purpose |
|---|---|
| Vanilla JavaScript (ES6) | Browser extension & dashboard |
| HTML5 / CSS3 | Dashboard & popup UI |
| Chart.js | Dashboard data visualizations |
| Chrome Manifest V3 | Extension platform |
| Vite | Dashboard dev server & bundler |

### Backend & Services
| Technology | Purpose |
|---|---|
| FastAPI | REST API framework |
| Python 3.14+ | Backend language |
| aiosqlite | Async SQLite database |
| dnspython | DNS resolution |
| python-whois | WHOIS lookups |
| httpx | Async HTTP client |
| psutil | System process monitoring |

### AI / Machine Learning
| Framework | Purpose |
|---|---|
| scikit-learn | Random Forest classifier |
| pandas | Data manipulation |
| numpy | Numerical computation |
| joblib | Model serialization |

---

## Installation & Setup

### Prerequisites
- **Python 3.11+** (3.14 recommended)
- **Node.js 18+** (for dashboard dev server)
- **Git**
- **Google Chrome** (for the browser extension)

### Clone Repository
```bash
git clone https://github.com/Mayank3613/Probable-Octo-Palm-Tree.git
cd Probable-Octo-Palm-Tree
```

### Setup Backend API
```bash
cd backend-api
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

### Setup AI Engine
```bash
cd ai-engine
pip install -r requirements.txt
python train.py            # Train the ML model (generates model.joblib)
python -m uvicorn app:app --port 8001
```

### Setup Dashboard
```bash
cd dashboard
npm install
npm run dev                # Starts on http://localhost:3000
```

### Setup Browser Extension
1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer Mode** (top-right toggle)
3. Click **Load Unpacked**
4. Select the `browser-extension/` directory
5. The extension icon appears in the toolbar

### Setup Local Agent
```bash
cd local-agent
pip install psutil requests
python agent_main.py
```

---

## One-Click Launch

Start all services simultaneously with a single command:

**Windows:**
```bash
start.bat
```

**macOS / Linux:**
```bash
chmod +x start.sh && ./start.sh
```

**Cross-platform (Python):**
```bash
python start_all.py
```

This launches:
- Backend API on port `8000`
- AI Engine on port `8001`
- Dashboard on port `3000`
- Local Security Agent (background)

All logs are multiplexed with color-coded prefixes.

---

## Core Modules

### Browser Extension
6 security modules running as content scripts + 1 service worker:
- **URL Analyzer** — 100+ heuristic signals, brand typosquatting, entropy analysis, Punycode detection
- **Threat Detector** — DOM scanning, hidden iframes, credential form detection, Shadow DOM inspection
- **API Interceptor** — fetch/XHR/WebSocket interception, blocked domain enforcement, request body scanning
- **Session Monitor** — JWT vulnerability scanning, cookie security auditing, session fixation detection
- **Download Scanner** — File type validation, MIME mismatch detection, RTL override detection
- **Logger** — Token bucket rate limiting, priority queuing, deduplication, batched message delivery

### Attribution Engine
- CDN bypass discovery (Cloudflare, Akamai, Fastly, AWS CloudFront)
- DNS record resolution (A, AAAA, MX, NS, TXT, SOA)
- WHOIS registration data analysis
- Infrastructure fingerprinting

### AI Engine
- Random Forest classifier trained on synthetic safe/malicious URL dataset
- 11 numerical features extracted per URL
- Hybrid scoring: blended rule-based (60%) + ML (40%) scores
- FastAPI inference endpoint with sub-millisecond latency

---

## Security Features

### Threat Detection
- Phishing domains (typosquatting, homoglyphs, suspicious TLDs)
- Malicious redirects (chain detection with 5-hop threshold)
- Suspicious JavaScript (eval, document.write, obfuscation)
- Credential harvesting forms
- Session hijacking attempts
- Malware downloads (executable extensions, MIME mismatches)

### Infrastructure Attribution
- Hidden origin detection (CDN bypass)
- DNS correlation (passive DNS, nameserver analysis)
- TLS/certificate analysis
- WHOIS registrar and registration date analysis
- ASN and IP geolocation mapping

### Self-Healing
- Automatic session cleanup (localStorage, sessionStorage, cookies)
- Tab quarantine with informative blocked page
- User-controlled domain whitelist
- One-click "Trust This Site" and "Go Back to Safety" actions

---

## API Endpoints

### Threat Scanning
```http
POST /scan/url          # Analyze URL with rule-based + ML scoring
```

### Telemetry
```http
POST /telemetry/upload  # Upload threat events from extension/agent
GET  /telemetry/live    # Live threat feed
GET  /telemetry/stats   # Aggregated statistics
GET  /telemetry/critical # Critical threats only
```

### Alerts
```http
GET  /alerts/live       # Last 50 threats
GET  /alerts/history    # Paginated history with filters
GET  /alerts/stats      # Severity breakdown + top domains
```

### Attribution
```http
POST /attribution/domain  # DNS + WHOIS + infrastructure lookup
```

### AI Engine
```http
POST /predict/url       # ML-based URL classification (port 8001)
GET  /health            # Service health check
```

### System
```http
GET  /health            # Backend health + uptime
GET  /docs              # Swagger UI
GET  /redoc             # ReDoc documentation
```

---

## AI Engine

### URL Classification Model
- **Algorithm:** Random Forest (100 trees, max depth 10)
- **Training Data:** 2,200 synthetic URLs (safe + malicious)
- **Features:** URL length, domain entropy, subdomain count, IP detection, suspicious keyword count, TLD analysis, path depth, special characters, Punycode detection, data URI detection
- **Training Accuracy:** 100% on training set
- **Live Detection Rate:** 99.0% across 202 real-world malicious URLs

### Blended Scoring
The backend scanner combines:
- **60%** Rule-based score (heuristic engine with 100+ signals)
- **40%** ML-based score (Random Forest probability)

This hybrid approach catches both known patterns (rules) and novel threats (ML).

---

## Testing & Detection Rate

### Backend API Tests
```bash
cd backend-api
python -m pytest tests/ -v    # 12 tests, all passing
```

### Multi-Feed Threat Testing
Tested against live threat intelligence feeds:

| Feed | URLs | Detection Rate |
|---|---|---|
| URLhaus (Malware) | 150 | **100.0%** |
| RapidDNS (Suspicious DNS) | 33 | **93.9%** |
| Shodan TLS (Certificate) | 19 | **100.0%** |
| **Overall** | **202** | **99.0%** |

Only 2 URLs missed: URL shorteners (`bit.ly`, `tinyurl.com`) which require redirect-following to classify.

---

## Development Roadmap

- [x] **Phase 1:** Browser extension MVP, URL monitoring, Rule-based detection
- [x] **Phase 2:** Backend API, Telemetry pipeline, Dashboard
- [x] **Phase 3:** Attribution engine, CDN bypass, Infrastructure mapping
- [x] **Phase 4:** AI threat scoring, Random Forest classification, Hybrid scoring
- [x] **Phase 5:** Self-healing automation, Quarantine pages, Session cleanup
- [ ] **Phase 6:** Zero-day behavioral detection, Advanced anomaly models
- [ ] **Phase 7:** Enterprise deployment, SOC integration, Distributed intelligence

---

## Security & Legal Notice

This project is intended strictly for:
- Cybersecurity research
- Threat intelligence
- Defensive security
- Infrastructure attribution
- Malware analysis
- Educational purposes

Unauthorized monitoring or misuse against systems without permission may violate local laws and regulations.

---

### License
MIT License

### Author
**Probable-Octo-Palm-Tree Security Research Project**
*Advanced Browser & Network Threat Attribution Framework*
