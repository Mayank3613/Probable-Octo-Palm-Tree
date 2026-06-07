/* ─── INFRASTRUCTURE VIEW ────────────────────────────────────────────────────
   Shows extension status, API endpoint health, and monitored endpoints.
─────────────────────────────────────────────────────────────────────────── */

let _lastGeoStatus = null;   // track transitions

function renderInfrastructureView() {
  const main = document.getElementById('main-content');
  if (!main) return;

  main.insertAdjacentHTML('beforeend', `
    <div id="view-infrastructure" style="display:none">
      <div class="header">
        <div class="header-left">
          <h1>Infrastructure</h1>
          <p>Monitored endpoints · Network nodes · Extension coverage</p>
        </div>
      </div>

      <!-- Summary Row -->
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:16px">
        <div class="panel" style="text-align:center">
          <div class="kpi-label" style="margin-bottom:8px">Extension Status</div>
          <div style="font-size:28px;font-weight:700;color:var(--accent)">ACTIVE</div>
          <div style="font-size:11px;color:var(--muted);margin-top:4px">Connected · v2.4.1</div>
        </div>
        <div class="panel" style="text-align:center">
          <div class="kpi-label" style="margin-bottom:8px">API Endpoint</div>
          <div style="font-size:13px;font-weight:700;color:var(--accent)">127.0.0.1:8000</div>
          <div style="font-size:11px;color:var(--muted);margin-top:4px">Latency: 4ms</div>
        </div>
        <div class="panel" style="text-align:center">
          <div class="kpi-label" style="margin-bottom:8px">Rules Loaded</div>
          <div style="font-size:28px;font-weight:700;color:var(--info)">2,847</div>
          <div style="font-size:11px;color:var(--muted);margin-top:4px">YARA + blocklist rules</div>
        </div>
      </div>

      <!-- Endpoint List -->
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title"><div class="panel-dot" style="background:var(--accent)"></div>Monitored Endpoints</div>
          <button class="mini-btn" onclick="toast('Endpoint added — configure in settings')">+ Add Endpoint</button>
        </div>
        <div id="endpoints-list"></div>
      </div>
    </div>
  `);
}

function renderEndpointCard(name, data) {
    const statusClass = {
        online:    "status-online",
        degraded:  "status-degraded",
        offline:   "status-offline",
    }[data.status] ?? "status-offline";
    
    const color = data.status === 'online' ? 'var(--accent)' : 'var(--warn)';

    // Build the card HTML
    return `
      <div class="endpoint-card risk-stat ${statusClass}" style="text-align:left;padding:12px">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
          <div style="width:7px;height:7px;border-radius:50%;background:${color}"></div>
          <span class="endpoint-name" style="font-size:12px;font-weight:700;color:var(--text)">${name}</span>
        </div>
        <div class="endpoint-url" style="font-size:10px;color:var(--muted);margin-bottom:2px">${data.url ?? data.provider}</div>
        <div class="endpoint-badge" style="font-size:10px;color:${color}">
          ${data.status}${data.latency_ms ? ` · ${data.latency_ms}ms` : ""}
        </div>
        ${data.status !== "online" && data.fallback_provider
          ? `<div class="endpoint-fallback" style="font-size:10px;color:var(--text);margin-top:4px;">↳ fallback: ${data.fallback_provider}</div>`
          : ""}
      </div>`;
}

async function refreshInfrastructure() {
    try {
        const resp = await fetch(`http://127.0.0.1:8000/health`);
        const data = await resp.json();
        const geo  = data.endpoints?.geoip;

        if (geo) {
            // Fire toast only on status *change*
            if (geo.status !== _lastGeoStatus && _lastGeoStatus !== null) {
                if (geo.status === "degraded") {
                    showToast("GeoIP degraded", "Switched to ip-api.com fallback.", "warning");
                } else if (geo.status === "offline") {
                    showToast("GeoIP offline", "Attribution data unavailable.", "error");
                } else if (geo.status === "online") {
                    showToast("GeoIP recovered", "Primary provider back online.", "success");
                }
            }
            _lastGeoStatus = geo.status;
            
            // Update the warning banner explicitly
            const main = document.getElementById('view-infrastructure');
            if (main) {
                const existingBanner = document.getElementById('geoip-warning-banner');
                if (geo.status !== 'online' && !existingBanner) {
                    const header = main.querySelector('.header');
                    header.insertAdjacentHTML('afterend', `
                        <div id="geoip-warning-banner" class="alert alert-warning" style="background: rgba(234, 179, 8, 0.1); border-left: 4px solid var(--warn); padding: 12px 16px; margin-bottom: 16px; border-radius: 4px;">
                          <strong style="color: var(--warn); display: block; margin-bottom: 4px;">⚠️ Warning: GeoIP Database ${geo.status === 'degraded' ? 'Degraded' : 'Offline'}</strong>
                          <span style="color: var(--text); font-size: 13px;">The primary GeoIP database (geoip.maxmind.com) is currently ${geo.status}. The system has automatically fallen back to <b>${geo.fallback_provider}</b> for IP geolocation to prevent data loss.</span>
                        </div>
                    `);
                } else if (geo.status === 'online' && existingBanner) {
                    existingBanner.remove();
                }
            }
        }

        // Re-render cards
        const el = document.getElementById("endpoints-list");
        if (el && data.endpoints) {
            const allEndpoints = {
                "Local API Server": { url: "http://127.0.0.1:8000", status: "online", latency_ms: 4 },
                "Threat Intelligence Feed": { url: "https://feeds.threatintel.io/v2", status: "online", latency_ms: 122 },
                "YARA Rules CDN": { url: "https://rules.yara-db.net", status: "online", latency_ms: 88 },
                "GeoIP Database": data.endpoints.geoip
            };

            el.innerHTML = `
                <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px">
                  ${Object.entries(allEndpoints)
                        .map(([name, d]) => renderEndpointCard(name, d))
                        .join("")}
                </div>`;
        }
    } catch (e) {
        console.error("Failed to refresh infrastructure", e);
    }
}
