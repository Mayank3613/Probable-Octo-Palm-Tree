/* ─── INFRASTRUCTURE VIEW ────────────────────────────────────────────────────
   Shows extension status, API endpoint health, and monitored endpoints.
─────────────────────────────────────────────────────────────────────────── */

const ENDPOINTS = [
  { name: 'Local API Server',        url: 'http://127.0.0.1:8000',            status: 'online',   latency: '4ms'   },
  { name: 'Threat Intelligence Feed',url: 'https://feeds.threatintel.io/v2',  status: 'online',   latency: '122ms' },
  { name: 'YARA Rules CDN',          url: 'https://rules.yara-db.net',        status: 'online',   latency: '88ms'  },
  { name: 'GeoIP Database',          url: 'https://geoip.maxmind.com',        status: 'degraded', latency: '320ms' },
];

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

function renderEndpoints() {
  const el = document.getElementById('endpoints-list');
  if (!el) return;

  el.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px">
      ${ENDPOINTS.map(e => `
        <div class="risk-stat" style="text-align:left;padding:12px">
          <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
            <div style="width:7px;height:7px;border-radius:50%;background:${e.status === 'online' ? 'var(--accent)' : 'var(--warn)'}"></div>
            <span style="font-size:12px;font-weight:700;color:var(--text)">${e.name}</span>
          </div>
          <div style="font-size:10px;color:var(--muted);margin-bottom:2px">${e.url}</div>
          <div style="font-size:10px;color:${e.status === 'online' ? 'var(--accent)' : 'var(--warn)'}">${e.status} · ${e.latency}</div>
        </div>`).join('')}
    </div>`;
}
