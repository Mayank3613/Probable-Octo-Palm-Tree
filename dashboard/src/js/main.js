/* ──────────────────────────────────────────────────────────────────────────
   OCTO-PALM MAIN ENTRY
   Bootstraps the entire realtime dashboard application
────────────────────────────────────────────────────────────────────────── */


/* =========================================================================
   APPLICATION BOOTSTRAP
========================================================================= */
(async function bootstrap() {

  console.log(
    "[OCTO-PALM] Initializing dashboard..."
  );

  /* ─── BUILD UI ───────────────────────────────────────────────────── */

  renderSidebar();
  renderTelemetryView();
  renderIntelligenceView();
  renderScannerView();
  renderInfrastructureView();
  renderStatsView();
  renderSettingsView();
  /* ─── DEFAULT VIEW ───────────────────────────────────────────────── */

  switchView(
    "telemetry",
    document.querySelector(".sb-item.active")
  );
  /* ─── INITIAL DATA LOAD ──────────────────────────────────────────── */

  await fetchData();
  /* ─── LIVE DATA POLLING ──────────────────────────────────────────── */

  setInterval(async () => {
    await fetchData();
  }, 3000);
  /* ─── CLOCK ──────────────────────────────────────────────────────── */

  updateClock();
  setInterval(updateClock, 1000);
  /* ─── CHARTS ─────────────────────────────────────────────────────── */

  setTimeout(() => {
    try {
      initCharts();
    } catch (err) {
      console.warn(
        "[OCTO-PALM] Charts failed to initialize",
        err
      );
    }

  }, 300);
  console.log(
    "[OCTO-PALM] Dashboard initialized successfully"
  );

})();
/* =========================================================================
   LIVE DATA ORCHESTRATOR
========================================================================= */

async function fetchData() {
  try {
    const {
      stats,
      threats,
      critical
    } = await fetchFromAPI();
    /* ─── STORE GLOBAL STATE ──────────────────────────────────────── */

    AppState.stats = stats || {};
    AppState.threats = threats || [];
    AppState.critical = critical || [];

    /* ─── REFRESH TELEMETRY UI ────────────────────────────────────── */

    if (typeof updateKPIs === "function") {
      updateKPIs();
    }
    if (typeof renderThreatFeed === "function") {
      renderThreatFeed();
    }
    if (typeof updateStats === "function") {
      updateStats();
    }

    /* ─── OPTIONAL MODULES ───────────────────────────────────────── */

    if (typeof renderDomains === "function") {
      renderDomains();
    }
    if (typeof renderGeo === "function") {
      renderGeo();
    }
    if (typeof renderTimeline === "function") {
      renderTimeline();
    }
    if (typeof updateRing === "function") {
      updateRing();
    }
    if (typeof updateBadge === "function") {
      updateBadge();
    }
    /* ─── LIVE STATUS LOG ────────────────────────────────────────── */
    console.log(
      `[OCTO-PALM] Live telemetry updated (${AppState.threats.length} threats)`
    );

  } catch (err) {

    console.error(
      "[OCTO-PALM] Failed to fetch dashboard data",
      err
    );
  }
}