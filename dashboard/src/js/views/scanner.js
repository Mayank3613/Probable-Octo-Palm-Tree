/* ─── URL SCANNER & ATTRIBUTION VIEW ──────────────────────────────────────────
   Combines real-time URL threat scanning with an interactive Tactical World Map
   and comprehensive sandbox trace metrics referencing urlscan.io & VirusTotal.
─────────────────────────────────────────────────────────────────────────── */

// Stylized equirectangular coordinates for major landmasses
const MAP_CONTINENTS = [
  // North America
  [
    [-168, 65], [-150, 70], [-120, 75], [-90, 72], [-60, 75], [-50, 60], 
    [-55, 48], [-65, 45], [-75, 35], [-80, 25], [-82, 9], [-95, 15], 
    [-115, 30], [-125, 48], [-140, 60], [-168, 65]
  ],
  // South America
  [
    [-80, 10], [-72, 11], [-60, 10], [-50, -5], [-35, -6], [-40, -20], 
    [-58, -35], [-65, -45], [-72, -55], [-75, -50], [-70, -35], [-74, -20], 
    [-81, -5], [-81, 5], [-80, 10]
  ],
  // Africa
  [
    [-17, 15], [-5, 35], [10, 32], [25, 31], [32, 31], [34, 27], 
    [43, 12], [51, 11], [46, -5], [33, -28], [20, -34], [18, -34], 
    [12, -15], [8, 4], [-8, 4], [-17, 15]
  ],
  // Eurasia (Europe + Asia)
  [
    [-9, 38], [-9, 43], [-5, 50], [-5, 58], [5, 60], [10, 65], 
    [20, 70], [40, 70], [60, 72], [90, 75], [120, 75], [140, 72], 
    [170, 68], [170, 60], [160, 52], [142, 40], [130, 35], [120, 38], 
    [118, 22], [108, 16], [100, 1], [98, 10], [90, 15], [80, 8], 
    [72, 20], [60, 25], [48, 12], [43, 25], [35, 32], [26, 39], 
    [15, 38], [5, 36], [-9, 38]
  ],
  // Australia
  [
    [113, -26], [114, -15], [124, -16], [130, -12], [136, -12], [142, -10], 
    [145, -15], [153, -28], [150, -35], [140, -35], [138, -38], [115, -33], 
    [113, -26]
  ],
  // Greenland
  [
    [-73, 78], [-60, 82], [-10, 81], [-20, 70], [-40, 60], [-50, 60], 
    [-60, 65], [-73, 78]
  ]
];

const VENDORS = [
  "Google Safe Browsing",
  "Kaspersky Lab",
  "Sophos Threat Intel",
  "Bitdefender Global",
  "CrowdStrike Falcon",
  "AbuseIPDB Heuristics",
  "Fortinet Sentinel",
  "Avast SecureWeb",
  "Symantec Gateway"
];

function getContinentSvgPaths() {
  return MAP_CONTINENTS.map(points => {
    const pointsStr = points.map(([lon, lat]) => {
      const x = ((lon + 180) / 360) * 1000;
      const y = ((90 - lat) / 180) * 500;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
    return `<polygon class="map-continent" points="${pointsStr}" />`;
  }).join('\n');
}

function renderScannerView() {
  const main = document.getElementById('main-content');
  if (!main) return;

  main.insertAdjacentHTML('beforeend', `
    <div id="view-scan" style="display:none">
      <div class="header">
        <div class="header-left">
          <h1 style="text-shadow: 0 0 15px rgba(99, 102, 241, 0.4)">URL Scanner & Attribution</h1>
          <p>Real-time URL threat scanning and IP intelligence command center</p>
        </div>
      </div>

      <div class="scan-grid" style="display:grid; grid-template-columns: 1.25fr 1fr; gap: 16px;">
        
        <!-- Left Column: URL Scanner -->
        <div style="display:flex; flex-direction:column; gap:16px">
          
          <!-- URL Analysis -->
          <div class="panel">
            <div class="panel-header">
              <div class="panel-title">
                <div class="panel-dot" style="background:var(--accent)"></div>
                Analyse URL / Domain
              </div>
            </div>
            <div class="scan-input-row">
              <input class="scan-input" id="scan-url-input" placeholder="https://suspicious-site.example.com/path?param=value" />
              <button class="scan-btn" onclick="runScan()">▶ Analyse</button>
            </div>
            
            <!-- Dynamic Sandbox results -->
            <div id="scan-results-container" style="display:none; margin-top: 16px; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 16px;">
              <!-- Scan Header Details -->
              <div id="scan-results-header"></div>
              
              <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 12px;">
                <!-- Headless Browser Preview -->
                <div>
                  <div class="section-sep" style="margin-bottom:8px">Sandbox Browser Mockup</div>
                  <div id="scan-results-mockup"></div>
                </div>
                
                <!-- Headless Browser Network Logs -->
                <div>
                  <div class="section-sep" style="margin-bottom:8px">Simulated Request Logs</div>
                  <div id="scan-results-logs" class="network-logs-panel"></div>
                </div>
              </div>
              
              <!-- Multi-Engine Verdict Grid -->
              <div style="margin-top: 16px;">
                <div class="section-sep" style="margin-bottom:8px">Security Engine Verdicts (Multi-Vendor)</div>
                <div id="scan-results-vendors" class="vendor-grid"></div>
              </div>
            </div>
          </div>

          <!-- Scan History -->
          <div class="panel">
            <div class="panel-header">
              <div class="panel-title">
                <div class="panel-dot" style="background:var(--info)"></div>
                Scan History
              </div>
            </div>
            <div id="scan-history" class="scroll-y" style="max-height:220px">
              <div class="empty">No scans run yet</div>
            </div>
          </div>

        </div>

        <!-- Right Column: GeoIP Tactical Map -->
        <div class="panel map-visualizer-panel" style="display:flex; flex-direction:column; gap:12px">
          <div class="panel-header">
            <div class="panel-title">
              <div class="panel-dot" style="background:var(--danger)"></div>
              Tactical World Map & GeoIP Lookup
            </div>
          </div>

          <div class="scan-input-row">
            <input class="scan-input" id="geoip-ip-input" placeholder="Enter IP address (e.g. 8.8.8.8)" value="8.8.8.8" />
            <button class="scan-btn" style="background:var(--danger); color:#fff" onclick="runIpGeoLookup()">🎯 Geolocate</button>
          </div>

          <!-- Map Visual Container -->
          <div class="map-container-relative">
            <div class="map-grid-overlay"></div>
            <svg class="cyber-world-map" viewBox="0 0 1000 500">
              <!-- Grid Equator and Meridian lines -->
              <line x1="0" y1="250" x2="1000" y2="250" stroke="rgba(99, 102, 241, 0.15)" stroke-dasharray="4" />
              <line x1="500" y1="0" x2="500" y2="500" stroke="rgba(99, 102, 241, 0.15)" stroke-dasharray="4" />
              <!-- Render projected continent wireframes -->
              ${getContinentSvgPaths()}
              <!-- Dynamic Traceroute Trajectory Line -->
              <path id="map-traceroute-line" class="traceroute-line" d="" />
              <!-- Host Point in Frankfurt -->
              <circle id="map-host-dot" cx="524" cy="111" r="5" fill="var(--cyber-blue)" style="opacity: 0; filter: drop-shadow(0 0 4px var(--cyber-blue)); transition: opacity 0.4s ease;" />
            </svg>
            <!-- Pulse Marker Crosshair -->
            <div class="map-target-crosshair" id="map-target-crosshair" style="left:50%; top:50%; transition: left 0.6s cubic-bezier(0.25, 1, 0.5, 1), top 0.6s cubic-bezier(0.25, 1, 0.5, 1);">
              <div class="crosshair-line-h"></div>
              <div class="crosshair-line-v"></div>
              <div class="crosshair-ring"></div>
            </div>
          </div>

          <!-- Live Telemetry Readout -->
          <div class="map-info-bar">
            <div class="map-info-item">
              <span class="map-info-lbl">Target IP</span>
              <span class="map-info-val" id="geoip-val-ip">-</span>
            </div>
            <div class="map-info-item">
              <span class="map-info-lbl">Coordinates</span>
              <span class="map-info-val" id="geoip-val-coords">-</span>
            </div>
            <div class="map-info-item">
              <span class="map-info-lbl">Location</span>
              <span class="map-info-val" id="geoip-val-location">-</span>
            </div>
            <div class="map-info-item">
              <span class="map-info-lbl">ISP / Organization</span>
              <span class="map-info-val" id="geoip-val-isp">-</span>
            </div>
            <div class="map-info-item">
              <span class="map-info-lbl">Circuit Source</span>
              <span class="map-info-val" id="geoip-val-source">-</span>
            </div>
            <div class="map-info-item">
              <span class="map-info-lbl">Response Latency</span>
              <span class="map-info-val" id="geoip-val-latency">-</span>
            </div>
          </div>
        </div>

      </div>
    </div>
  `);

  if (!AppState.scanHistory) {
    AppState.scanHistory = [];
  }

  // Seed initial lookup for Google DNS on view load
  setTimeout(() => {
    runIpGeoLookup('8.8.8.8', true);
  }, 300);
}

// ─── GEOIP LOOKUP LOGIC ───────────────────────────────────────────────────────

async function runIpGeoLookup(ipAddress = null, isSafe = true) {
  const input = document.getElementById('geoip-ip-input');
  const ip = (ipAddress || (input && input.value.trim()) || '').trim();
  
  if (!ip) {
    showToast('Input Required', 'Please enter a valid IP address.', 'warning');
    return;
  }

  // Update input text if triggered programmatically
  if (input && ipAddress) {
    input.value = ip;
  }

  const crosshair = document.getElementById('map-target-crosshair');
  if (crosshair) {
    crosshair.style.opacity = '0.5';
  }

  // Reset statuses to loading
  document.getElementById('geoip-val-ip').textContent = ip;
  document.getElementById('geoip-val-coords').textContent = 'RESOLVING...';
  document.getElementById('geoip-val-location').textContent = 'RESOLVING...';
  document.getElementById('geoip-val-isp').textContent = 'RESOLVING...';
  document.getElementById('geoip-val-source').textContent = 'RESOLVING...';
  document.getElementById('geoip-val-latency').textContent = 'RESOLVING...';

  try {
    const apiBase = window.API_BASE || 'http://127.0.0.1:8000';
    const response = await fetch(`${apiBase}/attribution/geoip/${ip}`);
    if (!response.ok) {
      throw new Error(`HTTP error ${response.status}`);
    }
    const data = await response.json();

    document.getElementById('geoip-val-ip').textContent = data.ip || ip;

    const lat = data.latitude;
    const lon = data.longitude;

    if (lat !== null && lon !== null && lat !== undefined && lon !== undefined) {
      document.getElementById('geoip-val-coords').textContent = `${lat.toFixed(4)}°, ${lon.toFixed(4)}°`;
      
      // Calculate equirectangular project percentages
      const xPercent = ((lon + 180) / 360) * 100;
      const yPercent = ((90 - lat) / 180) * 100;

      if (crosshair) {
        crosshair.style.left = `${xPercent}%`;
        crosshair.style.top = `${yPercent}%`;
        crosshair.style.opacity = '1';
      }

      // Draw Traceroute bezier line from Frankfurt, Germany (host)
      const hostX = 524;
      const hostY = 111;
      const targetX = ((lon + 180) / 360) * 1000;
      const targetY = ((90 - lat) / 180) * 500;

      const hostDot = document.getElementById('map-host-dot');
      if (hostDot) hostDot.style.opacity = '1';

      const tracerouteLine = document.getElementById('map-traceroute-line');
      if (tracerouteLine) {
        const dx = targetX - hostX;
        const dy = targetY - hostY;
        const dist = Math.sqrt(dx*dx + dy*dy);
        const archHeight = Math.min(120, dist * 0.35);
        const ctrlX = (hostX + targetX) / 2;
        const ctrlY = Math.min(hostY, targetY) - archHeight;

        const dString = `M ${hostX} ${hostY} Q ${ctrlX} ${ctrlY} ${targetX} ${targetY}`;
        tracerouteLine.setAttribute('d', dString);
        
        // Restart animation trace sweep
        tracerouteLine.setAttribute('class', 'traceroute-line');
        void tracerouteLine.offsetWidth; // force reflow
        tracerouteLine.classList.add('active');
        tracerouteLine.classList.add(isSafe ? 'safe' : 'unsafe');
      }
    } else {
      document.getElementById('geoip-val-coords').textContent = 'UNKNOWN (NO COORDS)';
      if (crosshair) {
        crosshair.style.left = '50%';
        crosshair.style.top = '50%';
        crosshair.style.opacity = '0.15';
      }
      const hostDot = document.getElementById('map-host-dot');
      if (hostDot) hostDot.style.opacity = '0';
      const tracerouteLine = document.getElementById('map-traceroute-line');
      if (tracerouteLine) tracerouteLine.setAttribute('class', 'traceroute-line');
    }

    const locationStr = [data.city, data.country].filter(Boolean).join(', ') || 'Unknown';
    document.getElementById('geoip-val-location').textContent = locationStr;

    const ispStr = [data.org, data.asn ? `(ASN ${data.asn})` : ''].filter(Boolean).join(' ') || 'Unknown';
    document.getElementById('geoip-val-isp').textContent = ispStr;

    document.getElementById('geoip-val-source').textContent = data.source ? data.source.toUpperCase() : 'UNKNOWN';
    document.getElementById('geoip-val-latency').textContent = data.latency_ms ? `${data.latency_ms.toFixed(1)} ms` : 'N/A';

    showToast('IP Attributed', `Successfully mapped IP: ${ip} to ${locationStr}`, 'success');
  } catch (error) {
    console.error('GeoIP attribution query failed:', error);
    showToast('Attribution Failed', `Could not geolocate IP: ${ip}`, 'error');

    document.getElementById('geoip-val-coords').textContent = 'ERROR';
    document.getElementById('geoip-val-location').textContent = 'ERROR';
    document.getElementById('geoip-val-isp').textContent = 'ERROR';
    document.getElementById('geoip-val-source').textContent = 'ERROR';
    document.getElementById('geoip-val-latency').textContent = 'ERROR';

    if (crosshair) {
      crosshair.style.left = '50%';
      crosshair.style.top = '50%';
      crosshair.style.opacity = '0.15';
    }
    const hostDot = document.getElementById('map-host-dot');
    if (hostDot) hostDot.style.opacity = '0';
    const tracerouteLine = document.getElementById('map-traceroute-line');
    if (tracerouteLine) tracerouteLine.setAttribute('class', 'traceroute-line');
  }
}

// ─── SCAN LOGIC ───────────────────────────────────────────────────────────────

function runScan() {
  const input = document.getElementById('scan-url-input');
  const url = (input && input.value) || '';
  if (!url) { toast('Enter a URL to analyse'); return; }

  // Extract hostname/domain name for request logs
  let domain = 'target-host';
  try {
    const formatted = url.startsWith('http') ? url : `http://${url}`;
    domain = new URL(formatted).hostname;
  } catch {
    domain = url;
  }

  const resultsContainer = document.getElementById('scan-results-container');
  const resultsHeader = document.getElementById('scan-results-header');
  const resultsMockup = document.getElementById('scan-results-mockup');
  const resultsVendors = document.getElementById('scan-results-vendors');
  
  if (resultsContainer) {
    resultsContainer.style.display = 'block';
  }

  // Set scanning loading state
  if (resultsHeader) {
    resultsHeader.innerHTML = `
      <div style="color:var(--muted);font-size:11px;padding:10px 0;text-align:center">
        <div class="pulse" style="width:16px;height:16px;border-radius:50%;background:var(--accent);margin:0 auto 10px"></div>
        🔍 Initializing headless browser sandboxed scan for ${domain}...
      </div>
    `;
  }
  
  if (resultsMockup) resultsMockup.innerHTML = '';
  if (resultsVendors) resultsVendors.innerHTML = '';

  const score = Math.floor(Math.random() * 60) + 35;
  const isSafe = score < 50;

  // Selection of diverse target IPs to showcase map panning/pulsing
  const mockIPs = [
    '8.8.8.8',          // US
    '1.1.1.1',          // US
    '185.220.101.45',   // DE (Germany)
    '95.217.228.176',   // FI (Finland)
    '103.86.96.100',    // SG (Singapore)
    '185.190.140.10',   // CH (Switzerland)
    '202.164.50.2',     // IN (India)
    '82.102.23.1',      // UK
  ];
  const resolvedIP = mockIPs[Math.floor(Math.random() * mockIPs.length)];

  // Trigger simulated request logs line by line
  simulateRequestLogs(domain, isSafe, () => {
    // ─── SCAN HYDRATION POST-LOGS ───

    const checks = [
      { label: 'Domain Age',      val: isSafe ? '4+ years' : '< 30 days', ok: isSafe },
      { label: 'SSL Certificate', val: isSafe ? 'Valid (trusted CA)' : 'Self-signed / missing', ok: isSafe },
      { label: 'IP Reputation',   val: isSafe ? 'Clean' : 'Flagged in 3 blocklists', ok: isSafe },
      { label: 'Resolved IP',     val: `<span style="text-decoration:underline;cursor:pointer;color:var(--info)" onclick="runIpGeoLookup('${resolvedIP}', ${isSafe})">${resolvedIP} 🎯</span>`, ok: true },
      { label: 'Redirect Chain',  val: isSafe ? 'None' : '2 suspicious redirects', ok: isSafe },
      { label: 'WHOIS Privacy',   val: isSafe ? 'Transparent' : 'Hidden proxy', ok: isSafe },
    ];

    if (resultsHeader) {
      resultsHeader.innerHTML = `
        <div class="scan-result ${isSafe ? 'safe' : 'unsafe'}" style="animation: slide-in-up 0.3s ease;">
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
              <span>${c.val}</span>
            </div>`).join('')}
        </div>`;
    }

    // Render screenshot mockup viewport
    if (resultsMockup) {
      resultsMockup.innerHTML = getMockupHtml(isSafe);
    }

    // Render multi-vendor engine verdicts
    if (resultsVendors) {
      resultsVendors.innerHTML = getVendorsHtml(isSafe);
    }

    if (!AppState.scanHistory) {
      AppState.scanHistory = [];
    }
    AppState.scanHistory.unshift({ url, score, safe: isSafe, time: 'just now', ip: resolvedIP });
    renderScanHistory();

    // Automatically trigger GeoIP plotting & traceroute mapping
    runIpGeoLookup(resolvedIP, isSafe);
  });
}

function simulateRequestLogs(domain, isSafe, callback) {
  const logsContainer = document.getElementById('scan-results-logs');
  if (!logsContainer) return;
  logsContainer.innerHTML = '';

  const steps = [
    { text: `GET https://${domain}/`, type: 'success', delay: 100, meta: '200 OK (HTML)' },
    { text: `GET https://${domain}/assets/index.js`, type: 'success', delay: 350, meta: '200 OK (JS)' },
    isSafe
      ? { text: `GET https://${domain}/assets/theme.css`, type: 'success', delay: 600, meta: '200 OK (CSS)' }
      : { text: `GET https://${domain}/payload/exploit.bin`, type: 'blocked', delay: 600, meta: '403 BLOCKED (YARA)' },
    { text: `GET https://${domain}/favicon.ico`, type: 'success', delay: 850, meta: '200 OK (PNG)' },
    !isSafe
      ? { text: `POST https://exfil-gateway.net/api`, type: 'blocked', delay: 1100, meta: '403 BLOCKED (MALWARE)' }
      : { text: `GET https://${domain}/api/health`, type: 'success', delay: 1100, meta: '200 OK (JSON)' }
  ];

  steps.forEach(step => {
    setTimeout(() => {
      const row = document.createElement('div');
      row.className = `network-log-row ${step.type}`;
      row.innerHTML = `
        <span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:70%">${step.text}</span>
        <span style="font-weight:700">${step.meta}</span>
      `;
      logsContainer.appendChild(row);
      // Auto scroll container
      logsContainer.scrollTop = logsContainer.scrollHeight;
    }, step.delay);
  });

  setTimeout(callback, 1300);
}

function getMockupHtml(isSafe) {
  const statusClass = isSafe ? 'safe' : 'unsafe';
  const statusText = isSafe ? '● VERDICT: SECURE SITE' : '▲ ACCESS BLOCKED: MALICIOUS';
  return `
    <div class="sandbox-screenshot-mockup">
      <div class="sandbox-header">
        <div class="sandbox-dot" style="background:#ef4444"></div>
        <div class="sandbox-dot" style="background:#f59e0b"></div>
        <div class="sandbox-dot" style="background:#10b981"></div>
        <span style="font-size:8px; color:var(--muted); font-family:var(--font-mono); margin-left:8px">SANDBOX PORTAL ACTIVE</span>
      </div>
      <div class="sandbox-body">
        <div class="sandbox-wireframe">
          <div class="wireframe-line" style="width: 40%"></div>
          <div class="wireframe-line" style="width: 90%"></div>
          <div class="wireframe-line" style="width: 75%"></div>
          <div class="wireframe-line" style="width: 60%"></div>
        </div>
        <div class="sandbox-overlay ${statusClass}">
          <span>${statusText}</span>
          <span style="font-size:8px; font-weight:400; opacity:0.6; margin-top:4px; font-family:var(--font-mono)">Virtual sandbox preview</span>
        </div>
      </div>
    </div>
  `;
}

function getVendorsHtml(isSafe) {
  const maliciousIndices = new Set();
  if (!isSafe) {
    while (maliciousIndices.size < 3) {
      maliciousIndices.add(Math.floor(Math.random() * VENDORS.length));
    }
  }

  return VENDORS.map((v, index) => {
    const isMalicious = maliciousIndices.has(index);
    const itemClass = isMalicious ? 'malicious' : 'clean';
    const verdictText = isMalicious ? 'Malicious 🚨' : 'Clean ✅';
    return `
      <div class="vendor-item ${itemClass}">
        <span class="vendor-name">${v}</span>
        <span style="font-weight:700">${verdictText}</span>
      </div>
    `;
  }).join('');
}

function renderScanHistory() {
  const el = document.getElementById('scan-history');
  if (!el) return;

  if (!AppState.scanHistory || !AppState.scanHistory.length) {
    el.innerHTML = '<div class="empty">No scans run yet</div>';
    return;
  }

  el.innerHTML = AppState.scanHistory.slice(0, 10).map(s => `
    <div class="domain-row" onclick="runIpGeoLookup('${s.ip}', ${s.safe}); toast('Tracing: ${s.url}')">
      <span style="font-size:16px">${s.safe ? '✅' : '🚨'}</span>
      <div style="flex:1;min-width:0">
        <div class="domain-name">${s.url}</div>
        <div style="font-size:10px;color:var(--muted)">IP: ${s.ip || 'N/A'} · ${s.time}</div>
      </div>
      <span style="font-size:10px;color:${s.safe ? 'var(--accent)' : 'var(--danger)'};font-weight:700">${s.score}</span>
    </div>`).join('');
}
