# OctoPlamTree — Browser Threat Detection Layer

## Advanced Hybrid Cybersecurity Browser Extension

---

# Browser Extension Architecture

```text
User Opens Website
        ↓
Browser Extension Intercepts Request
        ↓
URL + DOM + Script Analysis
        ↓
Threat Detection Engine
        ↓
Threat Logging System
        ↓
Backend Telemetry Upload
```

---

# Objectives

The Browser Threat Detection Layer aims to:

- Detect phishing websites
- Detect suspicious redirects
- Identify malicious scripts
- Monitor suspicious browser behavior
- Detect hidden iframes
- Intercept suspicious requests
- Monitor cookies and sessions
- Generate threat logs
- Send telemetry to backend systems

---

# Software Requirements

| Software           | Purpose               |
| ------------------ | --------------------- |
| Visual Studio Code | Main development IDE  |
| Google Chrome      | Browser testing       |
| Node.js            | Runtime environment   |
| npm                | Dependency management |
| Git                | Version control       |

---

# Technology Stack

| Technology  | Purpose                       |
| ----------- | ----------------------------- |
| TypeScript  | Extension logic               |
| JavaScript  | Runtime scripts               |
| Manifest V3 | Chrome extension architecture |
| HTML/CSS    | Extension UI                  |
| Chrome APIs | Browser monitoring            |

---

# Project Structure

```text
browser-extension/
│
├── manifest.json
├── background.js
├── content.js
├── popup.html
├── popup.js
├── styles.css
├── logger.js
├── threat-detector.js
├── url-analyzer.js
├── session-monitor.js
├── api-interceptor.js
├── download-scanner.js
└── logs/
```

---

# Installation

## Step 1 — Create Project

```bash
mkdir browser-extension
cd browser-extension
```

---

## Step 2 — Initialize Node Project

```bash
npm init -y
```

---

## Step 3 — Install Dependencies

```bash
npm install typescript vite axios
```

### Dependency Purpose

- TypeScript → safer and scalable coding
- Vite → fast build system
- Axios → backend communication

---

# Manifest Configuration

## manifest.json

```json
{
  "manifest_version": 3,
  "name": "OctoPlamTree Threat Detector",
  "version": "1.0",

  "permissions": [
    "tabs",
    "storage",
    "webRequest",
    "downloads",
    "scripting",
    "activeTab"
  ],

  "host_permissions": [
    "<all_urls>"
  ],

  "background": {
    "service_worker": "background.js"
  },

  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"]
    }
  ],

  "action": {
    "default_popup": "popup.html"
  }
}
```

---

# MODULE 1 — URL Monitoring

## Objective

Detect:

- phishing URLs
- suspicious redirects
- typosquatting domains
- malicious keywords

---

## Explanation

This module intercepts browser requests using Chrome APIs and analyzes URLs before webpages fully load.

The system checks for suspicious keywords commonly used in phishing attacks.

---

## background.js

```javascript
chrome.webRequest.onBeforeRequest.addListener(

    function(details) {

        console.log("Visited URL:", details.url);

        detectThreat(details.url);

    },

    { urls: ["<all_urls>"] }

);
```

---

## Threat Detection Logic

```javascript
const suspiciousWords = [
    "login",
    "verify",
    "secure",
    "update-password",
    "banking"
];

function detectThreat(url) {

    suspiciousWords.forEach(word => {

        if(url.includes(word)) {

            console.log("Potential phishing detected");

        }

    });

}
```

---

# MODULE 2 — DOM Monitoring

## Objective

Detect:

- hidden iframes
- injected HTML elements
- phishing overlays
- clickjacking attacks

---

## Explanation

This module scans webpage DOM elements in real time to identify suspicious browser manipulations.

Large numbers of hidden iframes may indicate exploit kits or credential theft mechanisms.

---

## content.js

```javascript
const iframes = document.getElementsByTagName("iframe");

if(iframes.length > 5) {

    console.log("Suspicious iframe activity");

}
```

---

# MODULE 3 — Script Analysis

## Objective

Detect:

- obfuscated JavaScript
- crypto miners
- malicious injections
- hidden malware payloads

---

## Explanation

The Script Analysis Engine scans webpage scripts and identifies potentially malicious JavaScript patterns.

Very large inline scripts may indicate obfuscation or hidden malware execution.

---

## Script Detection Code

```javascript
const scripts = document.getElementsByTagName("script");

for(let script of scripts) {

    if(script.innerHTML.length > 10000) {

        console.log("Possible obfuscated script detected");

    }

}
```

---

# MODULE 4 — Cookie & Session Monitoring

## Objective

Detect:

- token theft
- unauthorized session activity
- suspicious cookie access
- session hijacking

---

## Explanation

Cookies and browser sessions contain sensitive authentication data.

This module monitors browser cookies and session activity to identify unauthorized access attempts.

---

## session-monitor.js

```javascript
console.log("Cookies:", document.cookie);
```

---

# MODULE 5 — API Interception

## Objective

Intercept:

- fetch()
- XMLHttpRequest
- WebSocket communication

---

## Explanation

Modern malicious websites communicate with remote servers using APIs.

This module overrides browser networking functions to monitor outgoing communication.

---

## api-interceptor.js

```javascript
const originalFetch = window.fetch;

window.fetch = async (...args) => {

    console.log("Fetch Request:", args);

    return originalFetch(...args);

};
```

---

# MODULE 6 — Download Monitoring

## Objective

Detect:

- executable downloads
- malware payloads
- suspicious files
- unauthorized download activity

---

## Explanation

This module tracks browser downloads and identifies potentially dangerous files before execution.

---

## download-scanner.js

```javascript
chrome.downloads.onCreated.addListener(

    function(downloadItem) {

        console.log("Download:", downloadItem.filename);

    }

);
```

---

# MODULE 7 — Threat Logging System

## Objective

Store:

- suspicious URLs
- malicious scripts
- browser alerts
- threat telemetry

---

## Explanation

Threat logging creates a historical database of detected browser threats and suspicious activities.

The logs help with:

- forensic analysis
- threat attribution
- SIEM integration
- incident investigation

---

## logger.js

```javascript
function logThreat(type, details) {

    const log = {

        timestamp: new Date(),
        threat_type: type,
        details: details

    };

    console.log(log);

}
```

---

## Example Log Format

```json
{
  "timestamp": "2026-05-13T10:30:00",
  "threat_type": "phishing",
  "url": "http://fake-login-example.com",
  "risk_score": 85
}
```

---

# MODULE 8 — Backend Telemetry

## Objective

Send:

- threat alerts
- browser telemetry
- risk scores
- suspicious browser events

---

## Explanation

The Telemetry Layer transfers browser security events to centralized backend infrastructure for advanced threat intelligence.

This enables:

- centralized monitoring
- threat intelligence
- machine learning analysis
- attack correlation

---

## Backend API Communication

```javascript
fetch("http://localhost:8000/telemetry/upload", {

    method: "POST",

    headers: {
        "Content-Type": "application/json"
    },

    body: JSON.stringify({

        url: window.location.href,
        threat: "suspicious"

    })

});
```

---

# Popup User Interface

## popup.html

```html
<!DOCTYPE html>

<html>

<head>
  <title>Threat Monitor</title>
</head>

<body>

<h2>OctoPlamTree</h2>

<div id="status">
Protection Active
</div>

</body>

</html>
```

---

# Loading Extension into Chrome

## Step 1

Open:

```text
chrome://extensions
```

---

## Step 2

Enable:

```text
Developer Mode
```

---

## Step 3

Click:

```text
Load Unpacked
```

---

## Step 4

Select:

```text
browser-extension/
```

---

# Testing

## Test Against

- phishing demo websites
- suspicious redirects
- malicious JavaScript
- fake login forms

---

## Recommended Tools

| Tool            | Purpose            |
| --------------- | ------------------ |
| Chrome DevTools | Debugging          |
| Wireshark       | Network inspection |

---

# Expected Output

The Browser Threat Detection Layer should successfully:

✅ Monitor URLs\
✅ Detect phishing pages\
✅ Inspect DOM activity\
✅ Detect suspicious scripts\
✅ Monitor browser sessions\
✅ Intercept browser APIs\
✅ Detect suspicious downloads\
✅ Generate threat logs\
✅ Upload telemetry to backend servers

---

# Future Enhancement

## Next Layer — Local Security Agent Layer

The next layer of the platform will implement:

- packet capture
- DNS monitoring
- TLS fingerprinting
- browser-to-network correlation



