
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
          <h1>Live Telemetry</h1>
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
            style="max-height: 700px"
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
            gap:14px;
          "
        >

          <!-- TELEMETRY STATUS -->
          <div class="panel">

            <div class="panel-header">

              <div class="panel-title">
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
──────────────────────────────────────────────────────────────── */

async function hydrateTelemetry() {

  try {

    const data = await fetchFromAPI();

    AppState.stats = data.stats || {};

    AppState.threats = data.threats || [];

    updateKPIs();

    updateStats();

    renderThreatFeed();

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

