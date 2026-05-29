# 🛡️ Probable-Octo-Palm-Tree

> A hybrid cybersecurity platform that combines browser extension–based threat detection, system-wide traffic interception, CDN/origin attribution, and AI-powered threat intelligence for self-healing browser security.

![Python](https://img.shields.io/badge/Python-3.14+-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-teal?logo=fastapi)
![JavaScript](https://img.shields.io/badge/Vanilla_JS-ES6-yellow?logo=javascript)
![HTML/CSS](https://img.shields.io/badge/UI-TailwindCSS-cyan?logo=tailwindcss)
![Security](https://img.shields.io/badge/Security-Advanced-red?logo=security)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Technology Stack](#-technology-stack)
- [Installation](#-installation)
- [Usage](#-usage)

---

## 🌟 Overview

**Probable-Octo-Palm-Tree** is designed to detect, analyze, attribute, and automatically respond to malicious websites, phishing campaigns, suspicious infrastructure, and hidden attacker networks. By operating both inside the browser and at the host OS level, it provides comprehensive coverage against modern web threats.

---

## 🏗️ Architecture

```text
┌───────────────────────────────────────────────┐
│               Browser Extension              │
│-----------------------------------------------│
│ 🔍 URL Analysis                               │
│ 📜 DOM Monitoring                             │
│ 🛡️ Session Protection                         │
└──────────────────────┬────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────┐
│          Local Security Agent                │
│-----------------------------------------------│
│ 📡 DNS Monitoring                             │
│ 🚦 Process Mapping                            │
│ 🔌 Traffic Correlation                        │
└──────────────────────┬────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────┐
│           Backend API & AI Engine            │
│-----------------------------------------------│
│ 🧠 Threat Intelligence                        │
│ 📊 Live Dashboard                             │
│ 🌐 CDN/Origin Attribution                     │
└───────────────────────────────────────────────┘
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🕸️ **Real-time URL Analysis** | Scores URLs for entropy, typosquatting, IDN homoglyphs, and suspicious TLDs. |
| 🛡️ **Self-Healing Security** | Automatically blocks malicious domains and quarantines malicious downloads. |
| 📊 **Live Threat Dashboard** | Premium, responsive dark-mode UI to monitor all network alerts globally. |
| 🖥️ **OS-Level Monitoring** | Python-based local agent tracks system-wide process networking (via `psutil`). |
| 🤖 **Threat Intelligence** | Connects with URLhaus and performs DNS/WHOIS lookups for IP attribution. |

---

## 📁 Project Structure

```text
probable-octo-palm-tree/
│
├── browser-extension/     # Vanilla JS Chrome Extension
│   ├── background.js      # Main service worker
│   └── modules/           # URL/Download analyzers
│
├── local-agent/           # System-wide python agent
│   └── agent_main.py      # Process & network monitor
│
└── backend-api/           # FastAPI backend server
    ├── app/               # Routers and services
    ├── tests/             # Pytest framework & live tester
    └── templates/         # Dashboard HTML
```

---

## 🛠️ Technology Stack

| Category | Technologies |
|---|---|
| **Frontend (Extension)** | Vanilla JavaScript (ES6), HTML5, CSS3 |
| **Backend & Dashboard** | FastAPI, Python 3, Jinja2, TailwindCSS, SQLite |
| **Local Agent** | Python, `psutil`, `requests` |
| **Testing** | `pytest`, URLhaus Threat Feed API |

---

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/Mayank3613/Probable-Octo-Palm-Tree.git
cd Probable-Octo-Palm-Tree
```

### 2. Setup Backend Server
```bash
cd backend-api
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```
*The dashboard will be available at `http://localhost:8000/dashboard`*

### 3. Load Browser Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** in the top right.
3. Click **Load unpacked** and select the `browser-extension` folder.

### 4. Start Local Agent (Optional)
```bash
cd local-agent
pip install -r requirements.txt
python agent_main.py
```

---

## 💡 Usage

Once everything is running:
- **Browse Safely:** The extension will monitor your web traffic. If you land on a malicious site, you will be redirected to the safe quarantine page.
- **View Telemetry:** Open `http://localhost:8000/dashboard` to see a live stream of all blocked threats, blocked network connections, and system-wide process alerts.
- **Run Tests:** You can execute `pytest` in the `backend-api` folder, or run `python tests/live_malware_tester.py` to benchmark the engine against real-world malware.

---
*Developed as a next-generation hybrid cybersecurity platform.*
