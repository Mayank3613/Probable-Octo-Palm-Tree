# OctoPlamTree — Update Log

All changes to the project are documented here in reverse chronological order.

---

## [2026-05-27] Customer-Ready Polish — Everyday Use Improvements

### Added (New Features)
- **Desktop Notifications** — Chrome OS-level alerts for critical/high threats (30s cooldown to avoid spam)
- **User Whitelist** — custom trusted domains in Settings → add/remove your own domains
- **Trust This Site** button on quarantine page — permanently whitelist a domain with one click
- **Notifications toggle** — enable/disable desktop alerts from Settings
- **Badge auto-decay** — badge counter only shows threats from the last 1 hour, not forever

### Fixed (Daily Use Issues)
- **Self-healing was too aggressive** — now only quarantines `critical` threats (previously `high` too, which blocked borderline sites)
- **Console spam eliminated** — removed `console.log` on every page load, logger only prints `critical` to DevTools
- **CPU waste fixed** — DOM scanning skips trusted domains entirely (Google, YouTube, Gmail, etc.)
- **Scan interval reduced** — 30s polling (was 15s) + completely disabled on trusted sites
- **Telemetry errors silenced** — exponential backoff when backend is offline (no more error every 30s)
- **Clear logs now requires confirmation** — prevents accidental data loss
- **Dedup window extended** — 10s (was 5s) to prevent duplicate threat entries
- **Log capacity increased** — 500 entries (was 300)

### Files Changed
- `manifest.json` — added `notifications` permission
- `background.js` — notifications, user whitelist, telemetry backoff, badge decay
- `content.js` — trusted domain skip, removed console spam, 30s scan interval
- `popup.html` — notifications toggle, whitelist UI section
- `popup.js` — whitelist management, notification settings, clear confirm
- `styles.css` — whitelist input/list/remove styles, settings divider
- `blocked.html` — Trust This Site button with green styling
- `blocked.js` — trust button logic (adds domain to whitelist)
- `modules/logger.js` — only console.warn for critical threats

---

## [2026-05-27] Phase 2 — Backend API Server
**Commit:** `3b2ef50`

### Added
- **Complete FastAPI backend** at `backend-api/` — the telemetry server the browser extension connects to
- `POST /telemetry/upload` — receives threat events from browser extension, stores in SQLite
- `POST /scan/url` — server-side URL threat analysis (same scoring engine as extension)
- `GET /alerts/live` — last 50 real-time threat alerts
- `GET /alerts/history` — paginated threat history with severity/type filters
- `GET /alerts/stats` — severity breakdown, top 10 flagged domains, 24h counts
- `POST /attribution/domain` — DNS resolution + WHOIS lookup for domain intelligence
- `GET /health` — server health check
- Server-side URL analyzer (`services/url_analyzer.py`) — mirrors extension logic with 100+ trusted domains
- Domain lookup service (`services/domain_lookup.py`) — async DNS + WHOIS with graceful error handling
- Pydantic v2 request/response validation across all endpoints
- CORS middleware enabled for browser extension communication
- Auto-generated Swagger docs at `/docs`
- `.gitignore` for Python artifacts, database, virtualenv

### How to Run
```bash
cd backend-api
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
# Open http://localhost:8000/docs
```

---

## [2026-05-26] False Positive Fix — Trusted Domains Whitelist
**Commit:** `cb44634`

### Fixed
- **Google, YouTube, Gmail, Amazon, Facebook, GitHub** and 100+ trusted domains no longer trigger false alerts
- Root cause: keywords like `accounts`, `signin`, `verify` matched legitimate Google URLs (`accounts.google.com`)
- Added comprehensive trusted domains whitelist to `url-analyzer.js` (100+ domains)
- Split keywords into domain-only vs path keywords — `/signin` path on trusted sites no longer flagged
- Cross-domain form check now compares **root domains** (not exact hostnames) — `accounts.google.com → google.com` no longer triggers credential exfiltration alert
- Cookie monitoring skips trusted domains — no more noise on every Google page load
- Fake login form detection skips trusted domains entirely

### Files Changed
- `browser-extension/modules/url-analyzer.js` — whitelist + keyword split
- `browser-extension/modules/threat-detector.js` — trusted domain checks
- `browser-extension/modules/session-monitor.js` — cookie alert whitelist
- `test-harness.html` — complete rewrite with new test panels

---

## [2026-05-23] Production Quality Rewrite
**Commit:** `61074e6`

### Fixed (Correctness)
- **WebSocket hook broken** — `window.WebSocket = function()` doesn't work with `new`. Replaced with `Proxy` + `Reflect.construct`
- **Self-healing race condition** — `executeScript` and `tabs.update` fired simultaneously. Now chained with `.then()`
- **`setInterval` dies in service worker** — replaced with `chrome.alarms` API
- **Relative URLs crash api-interceptor** — `new URL("/api/data")` throws. Added `window.location.href` as base
- **Cookie events flood** — `document.cookie` getter fires hundreds of times/sec. Added 2-second debounce
- **Logger crashes on extension reload** — wrapped `chrome.runtime.sendMessage` in try-catch
- **Badge resets on browser restart** — added `onStartup` listener

### Added (Polish)
- Popup resized to 420×560px (proper Chrome extension size)
- Scan Now button with spinner animation
- Export Logs button (downloads threat logs as JSON)
- Smart rendering — dashboard only re-renders when data changes (no flicker)
- Better dates: "Today 14:32" / "Yesterday 09:15" / "May 22 10:30"
- Rate limiting: 20 threats/10s in background, 10 msgs/s in logger
- Card hover effects, shimmer loading state, 4px scrollbar
- `alarms` permission added to manifest

### Files Changed
- `background.js`, `inject.js`, `manifest.json`, `popup.html`, `popup.js`, `styles.css`
- `modules/logger.js`, `modules/api-interceptor.js`, `modules/session-monitor.js`

---

## [2026-05-22] Critical Bug Fixes + Major Feature Improvements
**Commit:** `894c9a7`

### Fixed
- Added missing `cookies` permission — self-healing cookie cleanup was silently failing
- Added missing `api-interceptor.js` to content_scripts — connection blacklisting was broken
- Added `chrome.runtime.lastError` handling in cookie operations

### Added
- **Redirect chain detection** — tracks rapid redirects, alerts after 5+ within 8 seconds
- **Fake login form detection** — non-HTTPS password fields, cross-domain credential exfiltration
- **MutationObserver** — instant real-time DOM threat detection (replaces 10s polling)
- **Shannon entropy scoring** — detects randomized/DGA phishing domains
- **Punycode/IDN homoglyph** attack detection
- **Suspicious TLD scoring** (`.tk`, `.ml`, `.xyz`, etc.)
- **Data URI scheme** and `@`-sign URL obfuscation detection
- **Live badge icon** — red for critical, amber for warnings
- **Current page risk indicator** in popup dashboard
- **Severity breakdown stats** — Critical/High/Medium/Sessions Blocked counters
- **Severity filter bar** in Threats tab
- **Enhanced self-healing** — now clears localStorage/sessionStorage
- **Bypass confirmation dialog** on quarantine page

---

## [2026-05-22] Initial MV3 Browser Extension
**Commit:** `7e276c2`

### Added
- Complete Manifest V3 Chrome extension with 8 security modules:
  1. URL Monitoring — phishing/typosquatting detection via `webRequest` API
  2. DOM Monitoring — hidden iframes, clickjacking overlays
  3. Script Analysis — obfuscated JavaScript, cryptominer detection
  4. Cookie & Session Monitoring — auth token access tracking
  5. API Interception — fetch/XHR/WebSocket hooks via inject.js
  6. Download Scanning — dangerous file extension detection
  7. Threat Logging — centralized event storage
  8. Backend Telemetry — sync to local API server
- Popup dashboard with tabs (Overview, Threats, Network, Settings)
- Quarantine page (blocked.html) for self-healing redirects
- Test harness for interactive module testing

---

## [2026-05-22] Initial Commit
**Commits:** `2d5c14b`, `9f6f1f7`, `30362ac`

### Added
- Repository created
- README.md with full project specification
- `octoplantree_first_layer.md` — detailed browser extension specification
