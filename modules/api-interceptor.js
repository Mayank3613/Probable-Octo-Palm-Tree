// OctoPlamTree API Interceptor v2.0 — Content Script scope

(function () {
  // ── Constants ───────────────────────────────────────────────────────────────
  const BLOCKED_DOMAINS = new Set([
    "malicious-api-example.com","phishing-backend.net","coinhive.com","cryptoloot.pro",
    "minero.cc","coin-hive.com","jsecoin.com","crypto-loot.com","webmine.pro",
    "authedmine.com","ppoi.org","crypma.com","keylogger-cdn.net","data-exfil.xyz","stealer-api.ru",
  ]);
  const BAD_TLDS    = new Set(["tk","ml","ga","cf","gq","xyz","top","buzz","club","icu"]);
  const CRED_PATHS  = [/\/login/i,/\/signin/i,/\/auth/i,/\/password/i,/\/credential/i,/\/wallet/i,/\/session/i,/\/token/i];
  const EXFIL_PATHS = [/\/collect/i,/\/track/i,/\/pixel/i,/\/beacon/i,/\/log/i,/\/exfil/i,/\/report/i,/\/submit/i];

  // Body inspection patterns: [label, regex, severity, score]
  const BODY_RULES = [
    ["Credit Card Number",     /\b(?:\d[ -]?){13,16}\b/,                                  "critical", 90],
    ["SSN Pattern",            /\b\d{3}-\d{2}-\d{4}\b/,                                   "critical", 90],
    ["JWT Token in Body",      /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/,  "high",     75],
    ["Session/Auth Key",       /"(?:token|jwt|session|sid|auth|access_token|refresh_token)"\s*:/i, "high", 70],
    ["Password in Plaintext",  /"(?:password|passwd|pwd|pass)"\s*:\s*"[^"]{3,}"/i,        "critical", 85],
    ["Private Key Block",      /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/,                "critical", 95],
    ["Base64 Blob",            /(?:[A-Za-z0-9+/]{60,}={0,2})/,                           "medium",   40],
    ["Email Address",          /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/,      "low",      15],
  ];

  // Threat correlation: ring-buffer of flagged events within time window
  const corrLog   = [];
  const CORR_WIN  = 5000;   // 5-second correlation window
  const CORR_THR  = 3;      // ≥3 threat signals = escalate

  // ── Helpers ─────────────────────────────────────────────────────────────────
  const seen  = new Set();
  const tld   = h => h.split(".").pop().toLowerCase();
  const hostOf = url => { try { return new URL(url, location.href).hostname.toLowerCase(); } catch { return ""; } };

  function emit(type, details, severity) {
    const k = `${type}::${details.slice(0, 80)}`;
    if (seen.has(k)) return;
    seen.add(k);
    if (window.OctoLogger) try { OctoLogger.log(type, details, severity); } catch {}
  }

  // ── Threat correlation engine ────────────────────────────────────────────────
  // Each call pushes a signal; if ≥CORR_THR distinct signal types hit in CORR_WIN ms
  // from the same host, a correlated alert fires.
  function correlate(host, signalType, details) {
    const now = Date.now();
    corrLog.push({ ts: now, host, signalType, details });
    // Prune old entries
    while (corrLog.length && corrLog[0].ts < now - CORR_WIN) corrLog.shift();

    const hostEvents = corrLog.filter(e => e.host === host);
    const types      = new Set(hostEvents.map(e => e.signalType));

    if (types.size >= CORR_THR) {
      emit(
        "Correlated Threat Cluster",
        `${types.size} distinct threat signals from "${host}" within ${CORR_WIN / 1000}s: [${[...types].join(", ")}]`,
        "critical"
      );
    }
  }

  // ── URL threat scoring ───────────────────────────────────────────────────────
  function assessUrl(url, method) {
    const alerts = [];
    const host = hostOf(url);
    if (!host) return alerts;

    try {
      const u = new URL(url, location.href);
      const isCross = u.hostname !== location.hostname;

      // Blocked domain list
      if (BLOCKED_DOMAINS.has(host) || [...BLOCKED_DOMAINS].some(d => host.endsWith("." + d))) {
        alerts.push(["Blocked Domain Request", `${method} to blacklisted host: ${host}`, "critical"]);
        correlate(host, "blocked-domain", url);
      }

      // Suspicious TLD
      if (BAD_TLDS.has(tld(host))) {
        alerts.push(["Suspicious TLD Request", `${method} to .${tld(host)} domain: ${host}`, "high"]);
        correlate(host, "bad-tld", url);
      }

      // Cross-origin credential endpoint
      if (isCross && /^(POST|PUT|PATCH)$/i.test(method)) {
        if (CRED_PATHS.some(r => r.test(u.pathname))) {
          alerts.push(["Credential Endpoint Exfiltration", `Cross-origin ${method} → ${host}${u.pathname}`, "critical"]);
          correlate(host, "cred-endpoint", url);
        }
        if (EXFIL_PATHS.some(r => r.test(u.pathname))) {
          alerts.push(["Data Exfiltration Endpoint", `Cross-origin ${method} → ${host}${u.pathname}`, "high"]);
          correlate(host, "exfil-endpoint", url);
        }
      }

      // HTTP (not HTTPS) cross-origin request
      if (isCross && u.protocol === "http:") {
        alerts.push(["Plaintext Cross-Origin Request", `${method} sent over HTTP to ${host} — no TLS`, "medium"]);
        correlate(host, "no-tls", url);
      }

      // Log benign connections for audit
      if (!alerts.length && window.OctoLogger?.logConnection)
        OctoLogger.logConnection("fetch", url, method);

    } catch {}
    return alerts;
  }

  // ── Request body inspection ──────────────────────────────────────────────────
  function inspectBody(body, url, method) {
    if (!body) return;
    const host = hostOf(url);
    let str;
    try {
      str = typeof body === "string" ? body
          : body instanceof URLSearchParams ? body.toString()
          : body instanceof FormData ? [...body.entries()].map(([k,v])=>`${k}=${v}`).join("&")
          : JSON.stringify(body);
    } catch { return; }

    for (const [label, re, severity, pts] of BODY_RULES) {
      if (!re.test(str)) continue;
      // Skip generic base64 if score is low and domain is same-origin
      if (label === "Base64 Blob" && host === location.hostname) continue;
      emit(`Request Body: ${label}`, `${method} to ${url} — body contains ${label}`, severity);
      correlate(host, `body:${label}`, url);
    }

    // Encoded payload ratio check (heavily base64-encoded body)
    if (str.length > 300) {
      const ratio = (str.match(/[A-Za-z0-9+/=]{20,}/g) || []).join("").length / str.length;
      if (ratio > 0.75)
        emit("Encoded Request Body", `${method} to ${url} — body is ${(ratio*100).toFixed(0)}% base64 encoded`, "high");
    }
  }

  // ── Fetch interception ───────────────────────────────────────────────────────
  const _fetch = window.fetch;
  window.fetch = function (input, init = {}) {
    const url    = typeof input === "string" ? input : (input?.url ?? String(input));
    const method = (init.method || "GET").toUpperCase();

    assessUrl(url, method).forEach(([type, details, sev]) => emit(type, details, sev));
    inspectBody(init.body, url, method);

    // Block if domain is on blocklist
    try {
      const host = hostOf(url);
      if (BLOCKED_DOMAINS.has(host) || [...BLOCKED_DOMAINS].some(d => host.endsWith("." + d))) {
        emit("Fetch Blocked", `Fetch to ${url} was blocked`, "critical");
        return Promise.reject(new Error(`[OctoPlamTree] Blocked request to: ${url}`));
      }
    } catch {}

    return _fetch.apply(this, arguments);
  };

  // ── XMLHttpRequest hooks ─────────────────────────────────────────────────────
  const _xhrOpen = XMLHttpRequest.prototype.open;
  const _xhrSend = XMLHttpRequest.prototype.send;
  const _xhrSetHeader = XMLHttpRequest.prototype.setRequestHeader;

  XMLHttpRequest.prototype.open = function (method, url) {
    this._om = method?.toUpperCase() || "GET";
    this._ou = url;
    this._oh = {};
    return _xhrOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
    if (this._oh) this._oh[name.toLowerCase()] = value;
    return _xhrSetHeader.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function (body) {
    const url    = this._ou || "";
    const method = this._om || "GET";

    assessUrl(url, method).forEach(([type, details, sev]) => emit(type, details, sev));
    inspectBody(body, url, method);

    // Block if domain is on blocklist
    const host = hostOf(url);
    if (BLOCKED_DOMAINS.has(host) || [...BLOCKED_DOMAINS].some(d => host.endsWith("." + d))) {
      emit("XHR Blocked", `XHR to ${url} was blocked`, "critical");
      this.abort();
      return;
    }

    return _xhrSend.apply(this, arguments);
  };

  // ── Public API ───────────────────────────────────────────────────────────────
  window.OctoApiInterceptor = {
    isBlocked:      url => { const h = hostOf(url); return BLOCKED_DOMAINS.has(h) || [...BLOCKED_DOMAINS].some(d => h.endsWith("." + d)); },
    addBlockedHost: host => BLOCKED_DOMAINS.add(host.toLowerCase()),
    getCorrLog:     () => [...corrLog],
    inspectBody,
  };
})();