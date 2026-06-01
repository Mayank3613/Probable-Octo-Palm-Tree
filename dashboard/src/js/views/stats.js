
/* ────────────────────────────────────────────────────────────────
   LIVE STATISTICS VIEW
   Fully realtime SQLite analytics dashboard
──────────────────────────────────────────────────────────────── */

import {
  fetchFromAPI
} from "../modules/api.js";

let weeklyChart = null;
let severityChart = null;
let statsPolling = null;

/* ────────────────────────────────────────────────────────────────
   MAIN STATS VIEW
──────────────────────────────────────────────────────────────── */

export async function renderStatsView() {

  const main = document.getElementById("main-content");

  if (!main) return;

  const existing =
    document.getElementById("view-stats");

  if (existing) {
    existing.remove();
  }

  main.insertAdjacentHTML("beforeend", `

    <div id="view-stats">

      <!-- HEADER -->
      <div class="header">

        <div class="header-left">

          <h1>Realtime Analytics</h1>

          <p>
            Live SQLite telemetry metrics
          </p>

        </div>

        <div class="header-right">

          <div class="live-badge">
            <div class="pulse"></div>
            LIVE
          </div>

        </div>

      </div>

      <!-- CHART ROW -->
      <div
        style="
          display:grid;
          grid-template-columns:1fr 1fr;
          gap:16px;
          margin-bottom:16px
        "
      >

        <!-- WEEKLY TREND -->
        <div class="panel">

          <div class="panel-header">

            <div class="panel-title">

              <div
                class="panel-dot"
                style="background:var(--accent)"
              ></div>

              Weekly Threat Trend

            </div>

          </div>

          <div
            class="chart-wrap"
            style="height:250px"
          >

            <canvas
              id="chart-weekly"
              role="img"
              aria-label="Weekly Threat Trend"
            ></canvas>

          </div>

        </div>

        <!-- SEVERITY DISTRIBUTION -->
        <div class="panel">

          <div class="panel-header">

            <div class="panel-title">

              <div
                class="panel-dot"
                style="background:var(--warn)"
              ></div>

              Severity Distribution

            </div>

          </div>

          <div
            class="chart-wrap"
            style="height:250px"
          >

            <canvas
              id="chart-sev"
              role="img"
              aria-label="Severity Distribution"
            ></canvas>

          </div>

        </div>

      </div>

      <!-- KPI PANEL -->
      <div class="panel">

        <div class="panel-header">

          <div class="panel-title">

            <div
              class="panel-dot"
              style="background:var(--purple)"
            ></div>

            Live Threat Metrics

          </div>

        </div>

        <div
          style="
            display:grid;
            grid-template-columns:repeat(4,1fr);
            gap:12px
          "
        >

          <div class="risk-stat">

            <div
              class="risk-stat-val"
              id="live-total"
            >
              0
            </div>

            <div class="risk-stat-lbl">
              Total Threats
            </div>

          </div>

          <div class="risk-stat">

            <div
              class="risk-stat-val"
              id="live-critical"
            >
              0
            </div>

            <div class="risk-stat-lbl">
              Critical Threats
            </div>

          </div>

          <div class="risk-stat">

            <div
              class="risk-stat-val"
              id="live-high"
            >
              0
            </div>

            <div class="risk-stat-lbl">
              High Severity
            </div>

          </div>

          <div class="risk-stat">

            <div
              class="risk-stat-val"
              id="live-risk"
            >
              0
            </div>

            <div class="risk-stat-lbl">
              Average Risk
            </div>

          </div>

        </div>

      </div>

    </div>

  `);

  await hydrateStatsView();

  startStatsPolling();
}

/* ────────────────────────────────────────────────────────────────
   HYDRATE LIVE ANALYTICS
──────────────────────────────────────────────────────────────── */

async function hydrateStatsView() {

  try {

    // Main telemetry stats
    const data = await fetchFromAPI();

    AppState.stats = data.stats || {};

    updateLiveStats();

    // Analytics endpoint
    const response = await fetch(
      "http://127.0.0.1:8000/telemetry/analytics"
    );

    const analytics = await response.json();

    renderWeeklyChart(
      analytics.weekly || []
    );

    renderSeverityChart(
      analytics.severity || []
    );

  } catch (err) {

    console.error(
      "Stats hydration failed",
      err
    );
  }
}

/* ────────────────────────────────────────────────────────────────
   LIVE KPI UPDATE
──────────────────────────────────────────────────────────────── */

function updateLiveStats() {

  const stats = AppState.stats || {};

  setStat(
    "live-total",
    stats.total || 0
  );

  setStat(
    "live-critical",
    stats.critical || 0
  );

  setStat(
    "live-high",
    stats.high || 0
  );

  setStat(
    "live-risk",
    stats.avg_risk || 0
  );
}

/* ────────────────────────────────────────────────────────────────
   WEEKLY TREND CHART
──────────────────────────────────────────────────────────────── */

function renderWeeklyChart(data) {

  const ctx =
    document.getElementById("chart-weekly");

  if (!ctx) return;

  if (weeklyChart) {
    weeklyChart.destroy();
  }

  weeklyChart = new Chart(ctx, {

    type: "line",

    data: {

      labels: data.map(d => d.day),

      datasets: [{

        label: "Threat Count",

        data: data.map(d => d.count),

        fill: false,

        tension: 0.4
      }]
    },

    options: {

      responsive: true,

      maintainAspectRatio: false,

      plugins: {
        legend: {
          display: true
        }
      },

      scales: {
        y: {
          beginAtZero: true
        }
      }
    }
  });
}

/* ────────────────────────────────────────────────────────────────
   SEVERITY DISTRIBUTION
──────────────────────────────────────────────────────────────── */

function renderSeverityChart(data) {

  const ctx =
    document.getElementById("chart-sev");

  if (!ctx) return;

  if (severityChart) {
    severityChart.destroy();
  }

  severityChart = new Chart(ctx, {

    type: "doughnut",

    data: {

      labels: data.map(
        d => d.severity || "unknown"
      ),

      datasets: [{

        data: data.map(d => d.count)
      }]
    },

    options: {

      responsive: true,

      maintainAspectRatio: false,

      plugins: {
        legend: {
          position: "bottom"
        }
      }
    }
  });
}

/* ────────────────────────────────────────────────────────────────
   LIVE POLLING
──────────────────────────────────────────────────────────────── */

function startStatsPolling() {

  if (statsPolling) {
    clearInterval(statsPolling);
  }

  statsPolling = setInterval(
    async () => {

      await hydrateStatsView();

    },
    3000
  );
}

/* ────────────────────────────────────────────────────────────────
   HELPERS
──────────────────────────────────────────────────────────────── */

function setStat(id, value) {

  const el =
    document.getElementById(id);

  if (el) {
    el.textContent = value;
  }
}

