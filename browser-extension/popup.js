// Probable-Octo-Palm-Tree Dashboard Controller
// Manages real-time popup rendering, severity filtering, current-page risk,
// settings, user whitelist, and notifications

document.addEventListener("DOMContentLoaded", () => {
  // --- UI Elements ---
  const tabs = document.querySelectorAll(".nav-tab");
  const panels = document.querySelectorAll(".tab-panel");
  const clearLogsBtn = document.getElementById("btn-clear-logs");
  const exportLogsBtn = document.getElementById("btn-export-logs");
  const scanNowBtn = document.getElementById("btn-scan-now");
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
  const settingNotifications = document.getElementById("setting-notifications");

  // Whitelist
  const whitelistInput = document.getElementById("whitelist-input");
  const addWhitelistBtn = document.getElementById("btn-add-whitelist");
  const whitelistList = document.getElementById("whitelist-list");

  let activeFilter = "all";
  let lastDataFingerprint = "";

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
      lastDataFingerprint = "";
      renderDashboard();
    });
  });

  // --- Date Formatting ---
  function formatTimestamp(isoString) {
    if (!isoString) return "";
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return "";

    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const yesterday = new Date(today.getTime() - 86400000);
    const dateDay = new Date(date.getFullYear(), date.getMonth(), date.getDate());

    const hours = String(date.getHours()).padStart(2, "0");
    const minutes = String(date.getMinutes()).padStart(2, "0");
    const timeStr = `${hours}:${minutes}`;

    if (dateDay.getTime() === today.getTime()) return `Today ${timeStr}`;
    if (dateDay.getTime() === yesterday.getTime()) return `Yesterday ${timeStr}`;

    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    return `${months[date.getMonth()]} ${date.getDate()} ${timeStr}`;
  }

  // --- Scan Current Page ---
  function scanCurrentPage() {
    if (!chrome || !chrome.tabs) return;

    chrome.tabs.query({ active: true, currentWindow: true }, (tabList) => {
      if (chrome.runtime.lastError || !tabList || tabList.length === 0) return;
      const currentTab = tabList[0];
      if (!currentTab) return;
      const url = currentTab.url || "";

      if (!riskUrl || !riskIndicator || !riskScoreBadge || !riskDetail) return;

      riskUrl.textContent = truncateUrl(url, 48);
      riskUrl.title = url;

      if (url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("about:")) {
        riskIndicator.className = "risk-indicator safe";
        riskScoreBadge.textContent = "INTERNAL";
        riskScoreBadge.className = "risk-score safe";
        riskDetail.textContent = "Browser internal page — no risk assessment needed.";
        return;
      }

      riskIndicator.classList.add("loading");

      chrome.runtime.sendMessage({ action: "scan_current_url", url: url }, (analysis) => {
        riskIndicator.classList.remove("loading");

        if (chrome.runtime.lastError || !analysis) {
          riskDetail.textContent = "Unable to analyze this page.";
          return;
        }

        if (analysis.score !== undefined && analysis.score !== null && analysis.score >= 70) {
          riskIndicator.className = "risk-indicator critical";
          riskScoreBadge.textContent = `RISK: ${analysis.score}`;
          riskScoreBadge.className = "risk-score critical";
        } else if (analysis.score !== undefined && analysis.score !== null && analysis.score >= 35) {
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

  // --- Scan Now Button ---
  if (scanNowBtn) {
    scanNowBtn.addEventListener("click", () => {
      scanNowBtn.classList.add("scanning");
      scanNowBtn.textContent = "Scanning";
      scanCurrentPage();
      setTimeout(() => {
        scanNowBtn.classList.remove("scanning");
        scanNowBtn.textContent = "Scan Now";
      }, 1200);
    });
  }

  // --- Export Logs ---
  function exportLogsAsJSON() {
    chrome.storage.local.get(["threatLogs"], (result) => {
      if (chrome.runtime.lastError) return;
      const logs = result.threatLogs || [];
      const exportData = {
        exported_at: new Date().toISOString(),
        extension: "Probable-Octo-Palm-Tree",
        version: "1.0.0",
        total_entries: logs.length,
        threat_logs: logs
      };

      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `probable-octo-palm-tree-logs-${Date.now()}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
    });
  }

  if (exportLogsBtn) {
    exportLogsBtn.addEventListener("click", exportLogsAsJSON);
  }

  // --- Whitelist Management ---
  function loadWhitelist() {
    if (!whitelistList) return;
    chrome.runtime.sendMessage({ action: "get_whitelist" }, (whitelist) => {
      if (chrome.runtime.lastError || !whitelist) {
        whitelistList.innerHTML = '<div class="whitelist-empty">No custom trusted domains</div>';
        return;
      }
      if (whitelist.length === 0) {
        whitelistList.innerHTML = '<div class="whitelist-empty">No custom trusted domains</div>';
        return;
      }
      whitelistList.innerHTML = whitelist.map(domain =>
        `<div class="whitelist-item">
          <span class="whitelist-domain">${escapeHTML(domain)}</span>
          <button class="whitelist-remove-btn" data-domain="${escapeHTML(domain)}">✕</button>
        </div>`
      ).join("");

      // Attach remove handlers
      whitelistList.querySelectorAll(".whitelist-remove-btn").forEach(btn => {
        btn.addEventListener("click", () => {
          chrome.runtime.sendMessage({ action: "remove_from_whitelist", domain: btn.dataset.domain }, () => {
            loadWhitelist();
          });
        });
      });
    });
  }

  if (addWhitelistBtn && whitelistInput) {
    addWhitelistBtn.addEventListener("click", () => {
      const domain = whitelistInput.value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      if (!domain || !domain.includes(".")) return;
      chrome.runtime.sendMessage({ action: "add_to_whitelist", domain: domain }, () => {
        whitelistInput.value = "";
        loadWhitelist();
      });
    });
    whitelistInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") addWhitelistBtn.click();
    });
  }

  loadWhitelist();

  // --- Main Render ---
  function renderDashboard() {
    chrome.storage.local.get(["threatLogs", "connections", "settings", "stats"], (result) => {
      if (chrome.runtime.lastError) return;

      const logs = result.threatLogs || [];
      const conns = result.connections || [];
      const settings = result.settings || {};
      const stats = result.stats || {};

      // Smart change detection
      const fingerprint = String(logs.length) + ":" + String(conns.length) + ":" +
        String(stats.critical || 0) + ":" + String(stats.high || 0) + ":" +
        String(stats.medium || 0) + ":" + String(stats.sessionsBlocked || 0) + ":" +
        String(settings.enableUrlMonitoring) + ":" + String(settings.enableDomMonitoring) + ":" +
        String(settings.enableDownloadScanning) + ":" + String(settings.enableSelfHealing) + ":" +
        String(settings.enableTelemetry) + ":" + String(settings.enableNotifications) + ":" + activeFilter;

      if (fingerprint === lastDataFingerprint) return;
      lastDataFingerprint = fingerprint;

      // Stats
      if (statThreats) statThreats.textContent = logs.length;
      if (threatBadge) threatBadge.textContent = logs.length;
      if (statConns) statConns.textContent = conns.length;
      if (statCritical) statCritical.textContent = stats.critical || 0;
      if (statHigh) statHigh.textContent = stats.high || 0;
      if (statMedium) statMedium.textContent = stats.medium || 0;
      if (statBlocked) statBlocked.textContent = stats.sessionsBlocked || 0;

      // System status
      const criticalThreats = logs.filter(l => l.severity === "critical" || l.severity === "high");
      if (sysStatus && sysStatusText) {
        if (criticalThreats.length > 0) {
          sysStatus.className = "sys-status-badge danger";
          sysStatusText.textContent = "THREAT DETECTED";
        } else {
          sysStatus.className = "sys-status-badge";
          sysStatusText.textContent = "SECURE";
        }
      }

      // Settings — only update if not focused
      const activeEl = document.activeElement;
      if (settingUrl && activeEl !== settingUrl) settingUrl.checked = settings.enableUrlMonitoring !== false;
      if (settingDom && activeEl !== settingDom) settingDom.checked = settings.enableDomMonitoring !== false;
      if (settingDownloads && activeEl !== settingDownloads) settingDownloads.checked = settings.enableDownloadScanning !== false;
      if (settingHealing && activeEl !== settingHealing) settingHealing.checked = settings.enableSelfHealing !== false;
      if (settingTelemetry && activeEl !== settingTelemetry) settingTelemetry.checked = settings.enableTelemetry !== false;
      if (settingNotifications && activeEl !== settingNotifications) settingNotifications.checked = settings.enableNotifications !== false;

      // --- Filter logs ---
      const filtered = activeFilter === "all"
        ? logs
        : logs.filter(l => l.severity === activeFilter);

      // Render threats
      if (logsContainer) {
        if (filtered.length === 0) {
          logsContainer.innerHTML = `
            <div class="empty-state">
              <div class="empty-state-icon">🛡️</div>
              <div>${activeFilter === "all" ? "No threats detected yet" : `No ${activeFilter} severity threats`}</div>
            </div>`;
        } else {
          logsContainer.innerHTML = filtered.map(log => {
            const time = formatTimestamp(log.timestamp);
            const scoreTag = log.risk_score ? `<span class="log-score">${log.risk_score}</span>` : "";
            const severityPill = log.severity ? `<span class="severity-pill ${log.severity}">${log.severity}</span>` : "";
            return `
              <div class="log-item ${log.severity || 'medium'}">
                <div class="log-header">
                  <span class="log-title">${escapeHTML(log.threat_type)} ${severityPill}</span>
                  <span class="log-time">${scoreTag} ${time}</span>
                </div>
                <div class="log-body">${escapeHTML(log.details)}</div>
                <div class="log-url">${escapeHTML(log.url)}</div>
              </div>`;
          }).join("");
        }
      }

      // Last event in overview
      if (lastEventContainer) {
        if (logs.length === 0) {
          lastEventContainer.innerHTML = `<div class="empty-state">No threats detected on current workspace</div>`;
        } else {
          const newest = logs[0];
          const newestTime = formatTimestamp(newest.timestamp);
          const newestPill = newest.severity ? `<span class="severity-pill ${newest.severity}">${newest.severity}</span>` : "";
          lastEventContainer.innerHTML = `
            <div class="log-item ${newest.severity || 'medium'}" style="margin: 0;">
              <div class="log-header">
                <span class="log-title">${escapeHTML(newest.threat_type)} ${newestPill}</span>
                <span class="log-time">${newestTime}</span>
              </div>
              <div class="log-body">${escapeHTML(newest.details)}</div>
              <div class="log-url">${escapeHTML(newest.url)}</div>
            </div>`;
        }
      }

      // Connections
      if (connsContainer) {
        if (conns.length === 0) {
          connsContainer.innerHTML = `
            <div class="empty-state">
              <div class="empty-state-icon">📡</div>
              <div>No network telemetry intercepted yet</div>
            </div>`;
        } else {
          connsContainer.innerHTML = conns.map(conn => {
            const time = formatTimestamp(conn.timestamp);
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
      }
    });
  }

  // --- Settings ---
  function saveSettings() {
    if (!settingUrl || !settingDom || !settingDownloads || !settingHealing || !settingTelemetry) return;
    const newSettings = {
      enableUrlMonitoring: settingUrl.checked,
      enableDomMonitoring: settingDom.checked,
      enableDownloadScanning: settingDownloads.checked,
      enableSelfHealing: settingHealing.checked,
      enableTelemetry: settingTelemetry.checked,
      enableNotifications: settingNotifications ? settingNotifications.checked : true
    };
    lastDataFingerprint = "";
    chrome.storage.local.set({ settings: newSettings }, renderDashboard);
  }

  [settingUrl, settingDom, settingDownloads, settingHealing, settingTelemetry, settingNotifications].forEach(el => {
    if (el) el.addEventListener("change", saveSettings);
  });

  // --- Clear Logs (with confirmation) ---
  if (clearLogsBtn) {
    clearLogsBtn.addEventListener("click", () => {
      // Confirm before deleting all records
      const confirmed = confirm("Clear all threat logs and connection records? This cannot be undone.");
      if (!confirmed) return;

      lastDataFingerprint = "";
      chrome.storage.local.set({
        threatLogs: [],
        connections: [],
        stats: { critical: 0, high: 0, medium: 0, total: 0, sessionsBlocked: 0 }
      }, () => {
        renderDashboard();
        chrome.runtime.sendMessage({ action: "update_badge" }, () => {
          if (chrome.runtime.lastError) {}
        });
      });
    });
  }

  // --- Helpers ---
  function escapeHTML(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }

  function truncateUrl(url, maxLen) {
    if (!url || url.length <= maxLen) return url || "";
    return url.substring(0, maxLen) + "…";
  }

  // --- Init ---
  scanCurrentPage();
  renderDashboard();
  setInterval(renderDashboard, 3000);
});
