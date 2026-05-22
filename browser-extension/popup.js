// OctoPlamTree Dashboard Controller
// Manages real-time popup rendering, severity filtering, current-page risk, and settings

document.addEventListener("DOMContentLoaded", () => {
  // --- UI Elements ---
  const tabs = document.querySelectorAll(".nav-tab");
  const panels = document.querySelectorAll(".tab-panel");
  const clearLogsBtn = document.getElementById("btn-clear-logs");
  const filterBtns = document.querySelectorAll(".filter-btn");

  const statThreats = document.getElementById("stat-threats");
  const statConns = document.getElementById("stat-conns");
  const statCritical = document.getElementById("stat-critical");
  const statHigh = document.getElementById("stat-high");
  const statMedium = document.getElementById("stat-medium");
  const statBlocked = document.getElementById("stat-blocked");
  const threatBadge = document.getElementById("threat-badge");
  const sysStatus = document.getElementById("sys-status");
  const sysStatusText = document.getElementById("sys-status-text");

  const logsContainer = document.getElementById("logs-container");
  const connsContainer = document.getElementById("conns-container");
  const lastEventContainer = document.getElementById("last-event-container");

  // Risk indicator
  const riskIndicator = document.getElementById("current-page-risk");
  const riskScoreBadge = document.getElementById("risk-score-badge");
  const riskUrl = document.getElementById("risk-url");
  const riskDetail = document.getElementById("risk-detail");

  // Settings
  const settingUrl = document.getElementById("setting-url");
  const settingDom = document.getElementById("setting-dom");
  const settingDownloads = document.getElementById("setting-downloads");
  const settingHealing = document.getElementById("setting-healing");
  const settingTelemetry = document.getElementById("setting-telemetry");

  let activeFilter = "all";

  // --- Tab Navigation ---
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      panels.forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      const targetPanel = document.getElementById(`panel-${tab.dataset.tab}`);
      if (targetPanel) targetPanel.classList.add("active");
    });
  });

  // --- Severity Filter ---
  filterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      filterBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeFilter = btn.dataset.filter;
      renderDashboard();
    });
  });

  // --- Scan Current Page ---
  function scanCurrentPage() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabList) => {
      if (!tabList || tabList.length === 0) return;
      const currentTab = tabList[0];
      const url = currentTab.url || "";

      riskUrl.textContent = truncateUrl(url, 55);
      riskUrl.title = url;

      if (url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("about:")) {
        riskIndicator.className = "risk-indicator safe";
        riskScoreBadge.textContent = "INTERNAL";
        riskScoreBadge.className = "risk-score safe";
        riskDetail.textContent = "Browser internal page — no risk assessment needed.";
        return;
      }

      // Ask background to analyze
      chrome.runtime.sendMessage({ action: "scan_current_url", url: url }, (analysis) => {
        if (chrome.runtime.lastError || !analysis) {
          riskDetail.textContent = "Unable to analyze this page.";
          return;
        }

        if (analysis.score >= 70) {
          riskIndicator.className = "risk-indicator critical";
          riskScoreBadge.textContent = `RISK: ${analysis.score}`;
          riskScoreBadge.className = "risk-score critical";
        } else if (analysis.score >= 35) {
          riskIndicator.className = "risk-indicator warning";
          riskScoreBadge.textContent = `RISK: ${analysis.score}`;
          riskScoreBadge.className = "risk-score warning";
        } else {
          riskIndicator.className = "risk-indicator safe";
          riskScoreBadge.textContent = "SAFE";
          riskScoreBadge.className = "risk-score safe";
        }

        riskDetail.textContent = analysis.reason || "No threats detected on this domain.";
      });
    });
  }

  // --- Main Render ---
  function renderDashboard() {
    chrome.storage.local.get(["threatLogs", "connections", "settings", "stats"], (result) => {
      const logs = result.threatLogs || [];
      const conns = result.connections || [];
      const settings = result.settings || {};
      const stats = result.stats || {};

      // Stats
      statThreats.textContent = logs.length;
      threatBadge.textContent = logs.length;
      statConns.textContent = conns.length;
      statCritical.textContent = stats.critical || 0;
      statHigh.textContent = stats.high || 0;
      statMedium.textContent = stats.medium || 0;
      statBlocked.textContent = stats.sessionsBlocked || 0;

      // System status
      const criticalThreats = logs.filter(l => l.severity === "critical" || l.severity === "high");
      if (criticalThreats.length > 0) {
        sysStatus.className = "sys-status-badge danger";
        sysStatusText.textContent = "THREAT DETECTED";
      } else {
        sysStatus.className = "sys-status-badge";
        sysStatusText.textContent = "SECURE";
      }

      // Settings
      settingUrl.checked = settings.enableUrlMonitoring !== false;
      settingDom.checked = settings.enableDomMonitoring !== false;
      settingDownloads.checked = settings.enableDownloadScanning !== false;
      settingHealing.checked = settings.enableSelfHealing !== false;
      settingTelemetry.checked = settings.enableTelemetry !== false;

      // --- Filter logs ---
      const filtered = activeFilter === "all"
        ? logs
        : logs.filter(l => l.severity === activeFilter);

      // Render threats
      if (filtered.length === 0) {
        logsContainer.innerHTML = `
          <div class="empty-state">
            <div class="empty-state-icon">🛡️</div>
            <div>${activeFilter === "all" ? "No threats detected yet" : `No ${activeFilter} severity threats`}</div>
          </div>`;
      } else {
        logsContainer.innerHTML = filtered.map(log => {
          const time = new Date(log.timestamp).toLocaleTimeString();
          const scoreTag = log.risk_score ? `<span class="log-score">${log.risk_score}</span>` : "";
          return `
            <div class="log-item ${log.severity || 'medium'}">
              <div class="log-header">
                <span class="log-title">${escapeHTML(log.threat_type)}</span>
                <span class="log-time">${scoreTag} ${time}</span>
              </div>
              <div class="log-body">${escapeHTML(log.details)}</div>
              <div class="log-url">${escapeHTML(log.url)}</div>
            </div>`;
        }).join("");
      }

      // Last event in overview
      if (logs.length === 0) {
        lastEventContainer.innerHTML = `<div class="empty-state">No threats detected on current workspace</div>`;
      } else {
        const newest = logs[0];
        const newestTime = new Date(newest.timestamp).toLocaleTimeString();
        lastEventContainer.innerHTML = `
          <div class="log-item ${newest.severity || 'medium'}" style="margin: 0;">
            <div class="log-header">
              <span class="log-title">${escapeHTML(newest.threat_type)}</span>
              <span class="log-time">${newestTime}</span>
            </div>
            <div class="log-body">${escapeHTML(newest.details)}</div>
            <div class="log-url">${escapeHTML(newest.url)}</div>
          </div>`;
      }

      // Connections
      if (conns.length === 0) {
        connsContainer.innerHTML = `
          <div class="empty-state">
            <div class="empty-state-icon">📡</div>
            <div>No network telemetry intercepted yet</div>
          </div>`;
      } else {
        connsContainer.innerHTML = conns.map(conn => {
          const time = new Date(conn.timestamp).toLocaleTimeString();
          const tag = conn.type === "websocket" ? "WS" : conn.method || "GET";
          const cls = conn.type === "websocket" ? "ws" : conn.type === "xhr" ? "xhr" : "";
          return `
            <div class="conn-item">
              <span class="conn-tag ${cls}">${escapeHTML(tag)}</span>
              <span class="conn-url" title="${escapeHTML(conn.url)}">${escapeHTML(conn.url)}</span>
              <span class="conn-time">${time}</span>
            </div>`;
        }).join("");
      }
    });
  }

  // --- Settings ---
  function saveSettings() {
    chrome.storage.local.set({
      settings: {
        enableUrlMonitoring: settingUrl.checked,
        enableDomMonitoring: settingDom.checked,
        enableDownloadScanning: settingDownloads.checked,
        enableSelfHealing: settingHealing.checked,
        enableTelemetry: settingTelemetry.checked
      }
    }, renderDashboard);
  }

  [settingUrl, settingDom, settingDownloads, settingHealing, settingTelemetry].forEach(el => {
    el.addEventListener("change", saveSettings);
  });

  // --- Clear ---
  clearLogsBtn.addEventListener("click", () => {
    chrome.storage.local.set({
      threatLogs: [],
      connections: [],
      stats: { critical: 0, high: 0, medium: 0, total: 0, sessionsBlocked: 0 }
    }, renderDashboard);
  });

  // --- Helpers ---
  function escapeHTML(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }

  function truncateUrl(url, maxLen) {
    if (!url || url.length <= maxLen) return url;
    return url.substring(0, maxLen) + "…";
  }

  // --- Init ---
  scanCurrentPage();
  renderDashboard();
  setInterval(renderDashboard, 2000);
});
