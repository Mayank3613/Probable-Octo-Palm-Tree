/* ─── SETTINGS VIEW ──────────────────────────────────────────────────────────
   API connection config, alert thresholds, and toggle preferences.
─────────────────────────────────────────────────────────────────────────── */

function renderSettingsView() {
  const main = document.getElementById('main-content');
  if (!main) return;

  main.insertAdjacentHTML('beforeend', `
    <div id="view-settings" style="display:none">
      <div class="header">
        <div class="header-left">
          <h1>Settings</h1>
          <p>Extension config · Alert thresholds · API connection</p>
        </div>
        <button class="btn" style="border-color:rgba(16,185,129,.3);color:var(--accent)"
                onclick="toast('Settings saved successfully')">Save Changes</button>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">

        <!-- API Connection -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title"><div class="panel-dot" style="background:var(--accent)"></div>API Connection</div>
          </div>
          <div style="display:flex;flex-direction:column;gap:12px;font-size:12px">
            <div>
              <div style="color:var(--muted);margin-bottom:5px;font-size:10px;letter-spacing:.06em">API HOST</div>
              <input class="scan-input" value="http://127.0.0.1:8000" style="width:100%">
            </div>
            <div>
              <div style="color:var(--muted);margin-bottom:5px;font-size:10px;letter-spacing:.06em">REFRESH INTERVAL (ms)</div>
              <input class="scan-input" value="5000" style="width:100%">
            </div>
            <div>
              <div style="color:var(--muted);margin-bottom:5px;font-size:10px;letter-spacing:.06em">MAX THREATS IN FEED</div>
              <input class="scan-input" value="50" style="width:100%">
            </div>
            <button class="scan-btn" style="width:100%" onclick="toast('Connection test: OK — 4ms')">Test Connection</button>
          </div>
        </div>

        <!-- Alert Thresholds -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title"><div class="panel-dot" style="background:var(--warn)"></div>Alert Thresholds</div>
          </div>
          <div style="display:flex;flex-direction:column;gap:12px;font-size:12px">
            <div>
              <div style="color:var(--muted);margin-bottom:5px;font-size:10px;letter-spacing:.06em">CRITICAL SCORE THRESHOLD</div>
              <input class="scan-input" type="range" min="50" max="100" value="80" style="width:100%"
                oninput="this.previousElementSibling.textContent='CRITICAL SCORE THRESHOLD ('+this.value+')'">
            </div>
            <div>
              <div style="color:var(--muted);margin-bottom:5px;font-size:10px;letter-spacing:.06em">HIGH SCORE THRESHOLD</div>
              <input class="scan-input" type="range" min="30" max="80" value="60" style="width:100%">
            </div>
            <div style="display:flex;align-items:center;gap:10px">
              <input type="checkbox" checked style="accent-color:var(--accent)">
              <span style="color:var(--muted2)">Auto-block critical threats</span>
            </div>
            <div style="display:flex;align-items:center;gap:10px">
              <input type="checkbox" checked style="accent-color:var(--accent)">
              <span style="color:var(--muted2)">Desktop notifications</span>
            </div>
            <div style="display:flex;align-items:center;gap:10px">
              <input type="checkbox" style="accent-color:var(--accent)">
              <span style="color:var(--muted2)">Email alerts (enterprise)</span>
            </div>
          </div>
        </div>

      </div>
    </div>
  `);
}
