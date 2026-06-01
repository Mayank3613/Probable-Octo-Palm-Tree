/* ─── INTELLIGENCE VIEW ──────────────────────────────────────────────────────
   Threat Intelligence: IOC database (IP / Domain / Hash) + CVE tracker.
─────────────────────────────────────────────────────────────────────────── */

function renderIntelligenceView() {
  const main = document.getElementById('main-content');
  if (!main) return;

  main.insertAdjacentHTML('beforeend', `
    <div id="view-intelligence" style="display:none">
      <div class="header">
        <div class="header-left">
          <h1>Threat Intelligence</h1>
          <p>IOC database · YARA rules · CVE tracking</p>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">

        <!-- IOC Panel -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title"><div class="panel-dot" style="background:var(--danger)"></div>Indicators of Compromise</div>
            <button class="mini-btn">+ Add IOC</button>
          </div>
          <div class="tabs">
            <button class="tab active" onclick="iocTab('ip',this)">IP Addresses</button>
            <button class="tab"        onclick="iocTab('domain',this)">Domains</button>
            <button class="tab"        onclick="iocTab('hash',this)">File Hashes</button>
          </div>
          <div id="ioc-content" class="scroll-y" style="max-height:320px"></div>
        </div>

        <!-- CVE Panel -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title"><div class="panel-dot" style="background:var(--warn)"></div>Active CVEs</div>
          </div>
          <div id="cve-list" class="scroll-y" style="max-height:380px"></div>
        </div>

      </div>
    </div>
  `);
}

// ─── IOC ──────────────────────────────────────────────────────────────────────

function renderIOC(type) {
  AppState.curIocTab = type;
  const el = document.getElementById('ioc-content');
  if (!el) return;

  el.innerHTML = (IOC_DATA[type] || []).map(i => {
    const cls = i.risk === 'critical' ? 'dp-c' : i.risk === 'high' ? 'dp-h' : 'dp-m';
    return `
      <div class="domain-row">
        <span class="domain-name" style="font-family:monospace;font-size:11px">${i.val}</span>
        <span style="color:var(--muted);font-size:10px;margin-right:8px">${i.type}</span>
        <span class="domain-pill ${cls}">${i.risk.toUpperCase()}</span>
      </div>`;
  }).join('');
}

function iocTab(type, btn) {
  document.querySelectorAll('.tabs .tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  renderIOC(type);
}

// ─── CVEs ─────────────────────────────────────────────────────────────────────

function renderCVEs() {
  const el = document.getElementById('cve-list');
  if (!el) return;

  el.innerHTML = CVE_DATA.map(c => {
    const col = c.score >= 9 ? 'var(--danger)' : c.score >= 7 ? 'var(--warn)' : 'var(--accent)';
    return `
      <div class="domain-row" style="flex-direction:column;align-items:flex-start;gap:4px"
           onclick="toast('CVE detail: ${c.id} — searching NVD database')">
        <div style="display:flex;width:100%;align-items:center;gap:8px">
          <span style="font-size:11px;font-weight:700;color:var(--text)">${c.id}</span>
          <span style="font-size:10px;font-weight:700;color:${col};background:rgba(0,0,0,.3);padding:1px 6px;border-radius:4px">CVSS ${c.score}</span>
          <span style="margin-left:auto;font-size:10px;color:var(--muted)">${c.affected}</span>
        </div>
        <div style="font-size:11px;color:var(--muted2)">${c.desc}</div>
      </div>`;
  }).join('');
}
