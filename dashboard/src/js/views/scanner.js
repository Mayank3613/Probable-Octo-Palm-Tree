/* ─── URL SCANNER VIEW ───────────────────────────────────────────────────────
   Simulates URL / domain threat analysis with a risk score and check results.
   In production, wire runScan() to a real analysis API endpoint.
─────────────────────────────────────────────────────────────────────────── */

function renderScannerView() {
  const main = document.getElementById('main-content');
  if (!main) return;

  main.insertAdjacentHTML('beforeend', `
    <div id="view-scan" style="display:none">
      <div class="header">
        <div class="header-left">
          <h1>URL Scanner</h1>
          <p>Real-time URL analysis and threat scoring</p>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 340px;gap:16px">

        <!-- Scanner Input + Results -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title"><div class="panel-dot" style="background:var(--accent)"></div>Analyse URL / Domain</div>
          </div>
          <div class="scan-input-row">
            <input class="scan-input" id="scan-url-input" placeholder="https://suspicious-site.example.com/path?param=value" />
            <button class="scan-btn" onclick="runScan()">▶ Analyse</button>
          </div>
          <div id="scan-results"></div>
        </div>

        <!-- Scan History -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title"><div class="panel-dot" style="background:var(--info)"></div>Scan History</div>
          </div>
          <div id="scan-history" class="scroll-y" style="max-height:400px">
            <div class="empty">No scans run yet</div>
          </div>
        </div>

      </div>
    </div>
  `);
}

// ─── SCAN LOGIC ───────────────────────────────────────────────────────────────

function runScan() {
  const input = document.getElementById('scan-url-input');
  const url   = (input && input.value) || '';
  if (!url) { toast('Enter a URL to analyse'); return; }

  const el = document.getElementById('scan-results');
  if (el) el.innerHTML = '<div style="color:var(--muted);font-size:12px;padding:12px 0;text-align:center">🔍 Analysing...</div>';

  setTimeout(() => {
    const score  = Math.floor(Math.random() * 60) + 35;
    const isSafe = score < 50;

    const checks = [
      { label: 'Domain Age',      val: isSafe ? '4+ years'              : '< 30 days',                ok: isSafe },
      { label: 'SSL Certificate', val: isSafe ? 'Valid (trusted CA)'    : 'Self-signed / missing',    ok: isSafe },
      { label: 'IP Reputation',   val: isSafe ? 'Clean'                 : 'Flagged in 3 blocklists',  ok: isSafe },
      { label: 'Redirect Chain',  val: isSafe ? 'None'                  : '2 suspicious redirects',   ok: isSafe },
      { label: 'WHOIS Privacy',   val: isSafe ? 'Transparent'           : 'Hidden proxy',             ok: isSafe },
    ];

    if (el) {
      el.innerHTML = `
        <div class="scan-result ${isSafe ? 'safe' : 'unsafe'}">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
            <span style="font-size:20px">${isSafe ? '✅' : '🚨'}</span>
            <div>
              <div style="font-size:12px;font-weight:700;color:${isSafe ? 'var(--accent)' : 'var(--danger)'}">${isSafe ? 'LIKELY SAFE' : 'THREAT DETECTED'}</div>
              <div style="font-size:10px;color:var(--muted)">Risk score: ${score}/100</div>
            </div>
          </div>
          <div style="font-size:10px;color:var(--muted);margin-bottom:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${url}</div>
          ${checks.map(c => `
            <div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:11px">
              <span style="color:var(--muted)">${c.label}</span>
              <span style="color:${c.ok ? 'var(--accent)' : 'var(--danger)'}">${c.val}</span>
            </div>`).join('')}
        </div>`;
    }

    AppState.scanHistory.unshift({ url, score, safe: isSafe, time: 'just now' });
    renderScanHistory();
  }, 800);
}

function renderScanHistory() {
  const el = document.getElementById('scan-history');
  if (!el) return;

  if (!AppState.scanHistory.length) {
    el.innerHTML = '<div class="empty">No scans run yet</div>';
    return;
  }

  el.innerHTML = AppState.scanHistory.slice(0, 10).map(s => `
    <div class="domain-row" onclick="toast('Re-loading scan for: ${s.url}')">
      <span style="font-size:16px">${s.safe ? '✅' : '🚨'}</span>
      <div style="flex:1;min-width:0">
        <div class="domain-name">${s.url}</div>
        <div style="font-size:10px;color:var(--muted)">${s.time}</div>
      </div>
      <span style="font-size:10px;color:${s.safe ? 'var(--accent)' : 'var(--danger)'};font-weight:700">${s.score}</span>
    </div>`).join('');
}
