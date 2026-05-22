// OctoPlamTree Dashboard Interactivity Controller

document.addEventListener("DOMContentLoaded", () => {
  // --- UI Elements ---
  const tabs = document.querySelectorAll(".nav-tab");
  const panels = document.querySelectorAll(".tab-panel");
  const clearLogsBtn = document.getElementById("btn-clear-logs");
  
  const statThreats = document.getElementById("stat-threats");
  const statConns = document.getElementById("stat-conns");
  const threatBadge = document.getElementById("threat-badge");
  const sysStatus = document.getElementById("sys-status");
  const sysStatusText = document.getElementById("sys-status-text");

  const logsContainer = document.getElementById("logs-container");
  const connsContainer = document.getElementById("conns-container");
  const lastEventContainer = document.getElementById("last-event-container");

  // Settings elements
  const settingUrl = document.getElementById("setting-url");
  const settingDom = document.getElementById("setting-dom");
  const settingDownloads = document.getElementById("setting-downloads");
  const settingHealing = document.getElementById("setting-healing");
  const settingTelemetry = document.getElementById("setting-telemetry");

  // --- Tab Switch Logic ---
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      panels.forEach(p => p.classList.remove("active"));

      tab.classList.add("active");
      const targetPanel = document.getElementById(`panel-${tab.dataset.tab}`);
      if (targetPanel) targetPanel.classList.add("active");
    });
  });

  // --- UI Renderers ---
  function renderDashboard() {
    chrome.storage.local.get(["threatLogs", "connections", "settings"], (result) => {
      const logs = result.threatLogs || [];
      const conns = result.connections || [];
      const settings = result.settings || {};

      // 1. Update stats
      statThreats.textContent = logs.length;
      threatBadge.textContent = logs.length;
      statConns.textContent = conns.length;

      // 2. Update System Badge Status
      const criticalThreats = logs.filter(l => l.severity === "critical" || l.severity === "high");
      if (criticalThreats.length > 0) {
        sysStatus.className = "sys-status-badge danger";
        sysStatusText.textContent = "ATTACK ALERT";
      } else {
        sysStatus.className = "sys-status-badge";
        sysStatusText.textContent = "SECURE";
      }

      // 3. Render settings values
      if (settings) {
        settingUrl.checked = settings.enableUrlMonitoring !== false;
        settingDom.checked = settings.enableDomMonitoring !== false;
        settingDownloads.checked = settings.enableDownloadScanning !== false;
        settingHealing.checked = settings.enableSelfHealing !== false;
        settingTelemetry.checked = settings.enableTelemetry !== false;
      }

      // 4. Render logs view
      if (logs.length === 0) {
        logsContainer.innerHTML = `
          <div class="empty-state">
            <div class="empty-state-icon">🛡️</div>
            <div>No threats detected yet</div>
          </div>`;
        lastEventContainer.innerHTML = `
          <div class="empty-state">No threats detected on current workspace</div>`;
      } else {
        // Render detailed log panel list
        logsContainer.innerHTML = logs.map(log => {
          const time = new Date(log.timestamp).toLocaleTimeString();
          return `
            <div class="log-item ${log.severity || 'medium'}">
              <div class="log-header">
                <span class="log-title">${escapeHTML(log.threat_type)}</span>
                <span class="log-time">${time}</span>
              </div>
              <div class="log-body">${escapeHTML(log.details)}</div>
              <div class="log-url">${escapeHTML(log.url)}</div>
            </div>`;
        }).join("");

        // Render preview in Overview card
        const newestLog = logs[0];
        const newestTime = new Date(newestLog.timestamp).toLocaleTimeString();
        lastEventContainer.innerHTML = `
          <div class="log-item ${newestLog.severity || 'medium'}" style="margin: 0;">
            <div class="log-header">
              <span class="log-title">${escapeHTML(newestLog.threat_type)}</span>
              <span class="log-time">${newestTime}</span>
            </div>
            <div class="log-body">${escapeHTML(newestLog.details)}</div>
            <div class="log-url">${escapeHTML(newestLog.url)}</div>
          </div>`;
      }

      // 5. Render connections view
      if (conns.length === 0) {
        connsContainer.innerHTML = `
          <div class="empty-state">
            <div class="empty-state-icon">📡</div>
            <div>No network telemetry intercepted yet</div>
          </div>`;
      } else {
        connsContainer.innerHTML = conns.map(conn => {
          const time = new Date(conn.timestamp).toLocaleTimeString();
          const methodTag = conn.type === "websocket" ? "WS" : conn.method || "GET";
          const typeClass = conn.type === "websocket" ? "ws" : "";
          return `
            <div class="conn-item">
              <span class="conn-tag ${typeClass}">${escapeHTML(methodTag)}</span>
              <span class="conn-url" title="${escapeHTML(conn.url)}">${escapeHTML(conn.url)}</span>
              <span class="conn-time">${time}</span>
            </div>`;
        }).join("");
      }
    });
  }

  // --- Setting Save Listeners ---
  function saveSettings() {
    const settings = {
      enableUrlMonitoring: settingUrl.checked,
      enableDomMonitoring: settingDom.checked,
      enableDownloadScanning: settingDownloads.checked,
      enableSelfHealing: settingHealing.checked,
      enableTelemetry: settingTelemetry.checked
    };
    chrome.storage.local.set({ settings }, () => {
      console.log("Settings saved.");
      renderDashboard();
    });
  }

  [settingUrl, settingDom, settingDownloads, settingHealing, settingTelemetry].forEach(el => {
    el.addEventListener("change", saveSettings);
  });

  // --- Clear Database ---
  clearLogsBtn.addEventListener("click", () => {
    chrome.storage.local.set({ threatLogs: [], connections: [] }, () => {
      renderDashboard();
    });
  });

  // --- Helper: prevent HTML injection ---
  function escapeHTML(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;")
              .replace(/'/g, "&#039;");
  }

  // Initial draw & auto reload
  renderDashboard();
  setInterval(renderDashboard, 1500);
});
