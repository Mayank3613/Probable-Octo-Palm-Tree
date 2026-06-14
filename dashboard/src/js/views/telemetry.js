
/* ────────────────────────────────────────────────────────────────
   LIVE TELEMETRY VIEW
   Fully SQLite-driven realtime dashboard
──────────────────────────────────────────────────────────────── */

let telemetryPolling = null;

/* ────────────────────────────────────────────────────────────────
   MAIN VIEW
──────────────────────────────────────────────────────────────── */

async function renderTelemetryView() {

  const main = document.getElementById("main-content");

  if (!main) return;

  main.innerHTML = `
    <div id="view-telemetry">

      <!-- HEADER -->
      <div class="header">

        <div>
          <h1 style="text-shadow: 0 0 15px rgba(99, 102, 241, 0.4)">Live Telemetry</h1>
          <p>
            Realtime SQLite threat intelligence feed
          </p>
        </div>

        <div class="header-right">

          <button
            class="btn"
            onclick="exportReport()"
          >
            Export
          </button>

          <button
            class="btn btn-danger"
            onclick="clearAll()"
          >
            Clear
          </button>

          <div class="live-badge">
            <div class="pulse"></div>
            LIVE
          </div>

        </div>

      </div>

      <!-- KPI GRID -->
      <div class="kpi-grid">

        <div class="kpi danger">
          <div class="kpi-label">Critical</div>
          <div class="kpi-value" id="kpi-critical">0</div>
        </div>

        <div class="kpi warn">
          <div class="kpi-label">High</div>
          <div class="kpi-value" id="kpi-high">0</div>
        </div>

        <div class="kpi accent">
          <div class="kpi-label">Total Threats</div>
          <div class="kpi-value" id="kpi-total">0</div>
        </div>

        <div class="kpi info">
          <div class="kpi-label">Average Risk</div>
          <div class="kpi-value" id="kpi-risk">0</div>
        </div>

      </div>

      <!-- MAIN GRID -->
      <div class="grid-main">

        <!-- LIVE FEED -->
        <div class="panel">

          <div class="panel-header">

            <div class="panel-title">
              <div class="panel-dot" style="background:var(--danger)"></div>
              Live Threat Feed
            </div>

          </div>

          <div class="search-bar">

            <input
              id="search-input"
              class="search-input"
              placeholder="Search threats..."
              oninput="renderThreatFeed()"
            >

          </div>

          <div
            id="threat-feed"
            class="scroll-y"
            style="max-height: 720px"
          >

            <div class="empty">
              Waiting for live telemetry...
            </div>

          </div>

        </div>

        <!-- SIDE PANEL -->
        <div
          style="
            display:flex;
            flex-direction:column;
            gap:16px;
          "
        >

          <!-- CYBER THREAT RADAR -->
          <div class="panel radar-panel">
            <div class="panel-header" style="width:100%; margin-bottom: 8px">
              <div class="panel-title">
                <div class="panel-dot" style="background:var(--cyber-blue)"></div>
                Cyber Threat Radar
              </div>
            </div>
            
            <div class="radar-container" id="radar-screen">
              <div class="radar-grid"></div>
              <div class="radar-crosshair-h"></div>
              <div class="radar-crosshair-v"></div>
              <div class="radar-sweep-line"></div>
            </div>
            
            <div style="font-size: 10px; color: var(--muted); font-family: var(--font-mono); text-align: center; margin-top: 4px;">
              SYSTEM SCANNER ACTIVE · SWEEPING
            </div>
          </div>

          <!-- THREAT SIMULATOR -->
          <div class="panel">
            <div class="panel-header" style="margin-bottom: 8px">
              <div class="panel-title">
                <div class="panel-dot" style="background:var(--purple)"></div>
                Threat Simulator Console
              </div>
            </div>
            <p style="font-size: 11px; color: var(--muted); margin-bottom: 10px;">
              Inject mock attack vectors to test telemetry pipelines:
            </p>
            <div class="sim-grid">
              <button class="sim-btn" onclick="simulateAttack('xss')">💥 XSS Inject</button>
              <button class="sim-btn" onclick="simulateAttack('cred')">🔑 Cred Exfil</button>
              <button class="sim-btn" onclick="simulateAttack('miner')">⛏️ Miner Exec</button>
              <button class="sim-btn" onclick="simulateAttack('ransom')">🔒 Ransomware</button>
              <button class="sim-btn" onclick="simulateAttack('scan')">📡 Port Scan</button>
              <button class="sim-btn" onclick="simulateAttack('phish')">🎣 Phish Click</button>
            </div>
          </div>

          <!-- TELEMETRY STATUS -->
          <div class="panel">

            <div class="panel-header">

              <div class="panel-title">
                <div class="panel-dot" style="background:var(--info)"></div>
                Telemetry Status
              </div>

            </div>

            <div class="risk-stats">

              <div class="risk-stat">
                <div
                  class="risk-stat-val"
                  id="rs-active"
                >
                  0
                </div>

                <div class="risk-stat-lbl">
                  Active
                </div>
              </div>

              <div class="risk-stat">
                <div
                  class="risk-stat-val"
                  id="rs-phishing"
                >
                  0
                </div>

                <div class="risk-stat-lbl">
                  Phishing
                </div>
              </div>

              <div class="risk-stat">
                <div
                  class="risk-stat-val"
                  id="rs-malware"
                >
                  0
                </div>

                <div class="risk-stat-lbl">
                  Malware
                </div>
              </div>

            </div>

          </div>

        </div>

      </div>

    </div>
  `;

  await hydrateTelemetry();

  startTelemetryPolling();
}

/* ────────────────────────────────────────────────────────────────
   HYDRATE LIVE TELEMETRY
   Now also updates the active cyber radar screen
──────────────────────────────────────────────────────────────── */

async function hydrateTelemetry() {

  try {

    const data = await fetchFromAPI();

    AppState.stats = data.stats || {};

    AppState.threats = data.threats || [];

    updateKPIs();

    updateStats();

    renderThreatFeed();
    
    renderRadarDots();

  } catch (err) {

    console.error(
      "Live telemetry hydration failed",
      err
    );
  }
}

/* ────────────────────────────────────────────────────────────────
   LIVE POLLING
──────────────────────────────────────────────────────────────── */

function startTelemetryPolling() {

  if (telemetryPolling) {
    clearInterval(telemetryPolling);
  }

  telemetryPolling = startLivePolling(
    async () => {

      await hydrateTelemetry();

    },
    1000
  );
}

/* ────────────────────────────────────────────────────────────────
   KPI UPDATE
──────────────────────────────────────────────────────────────── */

function updateKPIs() {

  const stats = AppState.stats || {};

  setText(
    "kpi-critical",
    stats.critical || 0
  );

  setText(
    "kpi-high",
    stats.high || 0
  );

  setText(
    "kpi-total",
    stats.total || 0
  );

  setText(
    "kpi-risk",
    stats.avg_risk || 0
  );
}

/* ────────────────────────────────────────────────────────────────
   SIDE STATS
──────────────────────────────────────────────────────────────── */

function updateStats() {

  const threats = AppState.threats || [];

  setText(
    "rs-active",
    threats.length
  );

  setText(
    "rs-phishing",
    threats.filter(t =>
      t.threat_type
        ?.toLowerCase()
        .includes("phish")
    ).length
  );

  setText(
    "rs-malware",
    threats.filter(t =>
      t.threat_type
        ?.toLowerCase()
        .includes("malware")
    ).length
  );
}

/* ────────────────────────────────────────────────────────────────
   THREAT FEED
──────────────────────────────────────────────────────────────── */

window.renderThreatFeed = function () {

  const feed =
    document.getElementById("threat-feed");

  if (!feed) return;

  const threats = AppState.threats || [];

  const search = (
    document.getElementById("search-input")
      ?.value || ""
  ).toLowerCase();

  const filtered = threats.filter(t =>

    !search ||

    t.url
      ?.toLowerCase()
      .includes(search) ||

    t.threat_type
      ?.toLowerCase()
      .includes(search) ||

    t.details
      ?.toLowerCase()
      .includes(search)
  );

  if (!filtered.length) {

    feed.innerHTML = `
      <div class="empty">
        No live threats detected
      </div>
    `;

    return;
  }

  feed.innerHTML = filtered.map(t => `

    <div
      class="threat-item ${t.severity || 'medium'}"
    >

      <div class="threat-top">

        <div>

          <div
            class="threat-type ${t.severity}"
          >
            ${t.threat_type || "Unknown"}
          </div>

          <div class="threat-meta">
            ${timeAgo(t.timestamp)}
          </div>

        </div>

        <div
          class="threat-score ${t.severity}"
        >
          ${t.risk_score || 0}
        </div>

      </div>

      <div class="threat-url">
        ${t.url || "Unknown URL"}
      </div>

      <div class="threat-details">
        ${t.details || ""}
      </div>

      <div class="threat-actions">

        <button
          class="ta-btn block"
          onclick="blockThreat(${t.id})"
        >
          🚫 Block
        </button>

        <button
          class="ta-btn"
          onclick="copyURL('${t.url}')"
        >
          📋 Copy
        </button>

      </div>

    </div>

  `).join("");
};

/* ────────────────────────────────────────────────────────────────
   HELPERS
──────────────────────────────────────────────────────────────── */

function setText(id, value) {

  const el = document.getElementById(id);

  if (el) {
    el.textContent = value;
  }
}

function timeAgo(timestamp) {

  if (!timestamp) return "now";

  const seconds = Math.floor(
    (
      Date.now() -
      new Date(timestamp)
    ) / 1000
  );

  if (seconds < 60) {
    return `${seconds}s ago`;
  }

  if (seconds < 3600) {
    return `${Math.floor(seconds / 60)}m ago`;
  }

  if (seconds < 86400) {
    return `${Math.floor(seconds / 3600)}h ago`;
  }

  return `${Math.floor(seconds / 86400)}d ago`;
}

/* ────────────────────────────────────────────────────────────────
   ACTIONS
──────────────────────────────────────────────────────────────── */

window.copyURL = function(url) {

  navigator.clipboard.writeText(url);

  toast("URL copied");
};

window.blockThreat = async function(id) {

  toast(`Threat ${id} blocked`);
};

window.exportReport = function() {

  const data = JSON.stringify(
    AppState.threats,
    null,
    2
  );

  const blob = new Blob(
    [data],
    { type: "application/json" }
  );

  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");

  a.href = url;

  a.download = "telemetry-report.json";

  a.click();

  URL.revokeObjectURL(url);

  toast("Telemetry exported");
};

window.clearAll = async function() {

  try {

    await fetch(
      "http://127.0.0.1:8000/telemetry/clear",
      {
        method: "DELETE"
      }
    );

    AppState.threats = [];

    AppState.stats = {};

    renderThreatFeed();

    updateKPIs();

    updateStats();

    toast("Telemetry cleared");

  } catch (err) {

    console.error(err);

    toast("Failed to clear telemetry");
  }
};

/* ────────────────────────────────────────────────────────────────
   CYBER RADAR DOT PLOTTING
──────────────────────────────────────────────────────────────── */
function renderRadarDots() {
  const radar = document.getElementById("radar-screen");
  if (!radar) return;

  // Remove existing dots
  radar.querySelectorAll(".radar-dot").forEach(d => d.remove());

  const threats = AppState.threats || [];
  
  // Plot up to 6 threats
  threats.slice(0, 6).forEach((t, index) => {
    // Generate deterministic coordinates based on id/hash so the dot stays in place
    const seed = t.id || index;
    const angle = (seed * 57) % 360; // Deterministic angle
    // Deterministic distance: 20% to 80% from center
    const radius = 20 + ((seed * 31) % 60); 
    
    const x = 50 + radius * Math.cos(angle * Math.PI / 180);
    const y = 50 + radius * Math.sin(angle * Math.PI / 180);

    const dot = document.createElement("div");
    dot.className = `radar-dot ${t.severity || "medium"}`;
    dot.style.left = `${x}%`;
    dot.style.top = `${y}%`;
    dot.title = `${t.threat_type} (${t.severity})`;
    
    radar.appendChild(dot);
  });
}

/* ────────────────────────────────────────────────────────────────
   THREAT SIMULATION ACTION
──────────────────────────────────────────────────────────────── */
window.simulateAttack = async function(type) {
  const templates = {
    xss: {
      threat_type: "XSS Dynamic Injection",
      severity: "critical",
      url: "https://victim-spa.com/dashboard",
      details: "Dynamically injected inline script matches XSS pattern: <img src=x onerror='alert(document.cookie)'>",
      risk_score: 90
    },
    cred: {
      threat_type: "Credential Exfiltration Request",
      severity: "critical",
      url: "https://stealer-api.ru/collect",
      details: "POST to credential endpoint: request body contains plain-text passwords",
      risk_score: 85
    },
    miner: {
      threat_type: "Cryptominer Script",
      severity: "high",
      url: "https://coinhive.com/miner.js",
      details: "CoinHive signature detected in dynamically loaded script",
      risk_score: 75
    },
    ransom: {
      threat_type: "Possible Ransomware Activity",
      severity: "critical",
      url: "local-file://system32/encrypt",
      details: "Encrypted file extensions (.locked) detected in local volume",
      risk_score: 95
    },
    scan: {
      threat_type: "Suspicious Port Scan",
      severity: "medium",
      url: "https://internal-subnet.net",
      details: "Detected scan on ports 22, 80, 443, 8080 within 2s",
      risk_score: 40
    },
    phish: {
      threat_type: "Phishing/Malicious URL",
      severity: "high",
      url: "http://phishing-login-page.tk/signin.html",
      details: "Request to suspicious TLD .tk matches credential exfiltration keywords",
      risk_score: 80
    }
  };

  const payload = templates[type];
  if (!payload) return;

  // Add a timestamp
  payload.timestamp = new Date().toISOString();
  payload.source = "simulator";
  payload.action = "detected";

  try {
    const res = await fetch("http://127.0.0.1:8000/telemetry/upload", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ events: [payload] })
    });
    const data = await res.json();
    if (data.success) {
      toast(`Simulated ${payload.threat_type} injected!`);
      // Trigger a re-fetch immediately so the feed is instant
      await hydrateTelemetry();
    } else {
      toast("Simulator injection failed");
    }
  } catch (err) {
    console.error(err);
    toast("Error injecting simulated threat");
  }
};

