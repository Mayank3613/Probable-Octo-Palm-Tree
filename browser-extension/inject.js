// Probable-Octo-Palm-Tree Hook Injection Script (Runs in the page context / MAIN world)
// Direct interceptor for APIs (Fetch, XHR, WebSocket), document.cookie, and localStorage.
// Merged logic from api-interceptor.js and session-monitor.js

(function() {
  if (window.__octo_injected) return;
  window.__octo_injected = true;

  // Helper to send events to content.js
  function dispatchSecurityEvent(action, payload) {
    try {
      const event = new CustomEvent("OctoSecurityEvent", { detail: { action, payload } });
      window.dispatchEvent(event);
    } catch (e) {}
  }
  
  function emitAlert(type, details, severity) {
    dispatchSecurityEvent("log_threat", { type, details, severity });
  }

  // --- Constants ---
  const BLOCKED_DOMAINS = new Set([
    "malicious-api-example.com","phishing-backend.net","coinhive.com","cryptoloot.pro",
    "minero.cc","coin-hive.com","jsecoin.com","crypto-loot.com","webmine.pro",
    "authedmine.com","ppoi.org","crypma.com","keylogger-cdn.net","data-exfil.xyz","stealer-api.ru",
  ]);
  const BAD_TLDS    = new Set(["tk","ml","ga","cf","gq","xyz","top","buzz","club","icu"]);
  const CRED_PATHS  = [/\/login/i,/\/signin/i,/\/auth/i,/\/password/i,/\/credential/i,/\/wallet/i,/\/session/i,/\/token/i];
  const EXFIL_PATHS = [/\/collect/i,/\/track/i,/\/pixel/i,/\/beacon/i,/\/log/i,/\/exfil/i,/\/report/i,/\/submit/i];
  
  const SESS_KEYS  = ["session","sess","sid","token","jwt","auth","authtoken","userid","user_session","oauth","access_token","refresh_token","id_token","csrftoken","xsrf"];
  const EXFIL_PAT  = [/coinhive/i,/ngrok\.io/i,/\.onion/i,/\.(tk|ml|ga|cf|gq|xyz|top|buzz)(\/|$)/i];
  
  function analyzeJWT(token, source) {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return;
      const decode = p => JSON.parse(atob(p.replace(/-/g,"+").replace(/_/g,"/")));
      const header  = decode(parts[0]);
      const payload = decode(parts[1]);
      
      const alg = (header.alg || "").toUpperCase();
      if (alg === "NONE" || alg === "") emitAlert("JWT Unsigned Token", `JWT with alg:none from ${source}`, "critical");
      else if (["HS256","HS384","HS512"].includes(alg)) emitAlert("JWT Weak Algorithm", `JWT uses symmetric HMAC (${alg}) from ${source}`, "medium");

      const nowSec = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < nowSec) emitAlert("JWT Expired Token", `JWT from ${source} expired`, "medium");
      if (!payload.exp) emitAlert("JWT No Expiry", `JWT from ${source} has no exp claim`, "high");
    } catch {}
  }

  const JWT_RE = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
  function scanForJWTs(str, source) {
    if (!str) return;
    for (const match of str.matchAll(JWT_RE)) analyzeJWT(match[0], source);
  }

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

  // --- Correlation State ---
  const corrLog = [];
  const CORR_WIN = 5000;
  const CORR_THR = 3;
  const exfilLog = [];
  const CORR_WINDOW_MS = 3000;
  
  const tld = h => h.split(".").pop().toLowerCase();
  const hostOf = url => { try { return new URL(url, location.href).hostname.toLowerCase(); } catch { return ""; } };

  function correlate(host, signalType, details) {
    const now = Date.now();
    corrLog.push({ ts: now, host, signalType, details });
    while (corrLog.length && corrLog[0].ts < now - CORR_WIN) corrLog.shift();
    const hostEvents = corrLog.filter(e => e.host === host);
    const types = new Set(hostEvents.map(e => e.signalType));
    if (types.size >= CORR_THR) {
      emitAlert("Correlated Threat Cluster", `${types.size} distinct threat signals from "${host}" within ${CORR_WIN / 1000}s: [${[...types].join(", ")}]`, "critical");
    }
  }

  function logExfilCandidate(type, keys, url) {
    exfilLog.push({ ts: Date.now(), type, keys, url });
    const cutoff = Date.now() - CORR_WINDOW_MS;
    while (exfilLog.length && exfilLog[0].ts < cutoff) exfilLog.shift();
    const hasTokenRead = exfilLog.some(e => e.type === "token_read");
    const hasNetReq = exfilLog.some(e => e.type === "net_req");
    if (hasTokenRead && hasNetReq) {
      const tokens = [...new Set(exfilLog.filter(e=>e.type==="token_read").flatMap(e=>e.keys))];
      const dest = exfilLog.find(e=>e.type==="net_req")?.url || "unknown";
      emitAlert("Correlated Token Exfiltration", `Session token(s) [${tokens.join(",")}] read then sent to ${dest} within ${CORR_WINDOW_MS}ms`, "critical");
    }
  }

  function assessUrl(url, method) {
    const host = hostOf(url);
    if (!host) return;
    
    try {
      const u = new URL(url, location.href);
      const isCross = u.hostname !== location.hostname;

      if (BLOCKED_DOMAINS.has(host) || [...BLOCKED_DOMAINS].some(d => host.endsWith("." + d))) {
        emitAlert("Blocked Domain Request", `${method} to blacklisted host: ${host}`, "critical");
        correlate(host, "blocked-domain", url);
      }
      if (BAD_TLDS.has(tld(host))) {
        emitAlert("Suspicious TLD Request", `${method} to .${tld(host)} domain: ${host}`, "high");
        correlate(host, "bad-tld", url);
      }
      if (isCross && /^(POST|PUT|PATCH)$/i.test(method)) {
        if (CRED_PATHS.some(r => r.test(u.pathname))) {
          emitAlert("Credential Endpoint Exfiltration", `Cross-origin ${method} → ${host}${u.pathname}`, "critical");
          correlate(host, "cred-endpoint", url);
        }
        if (EXFIL_PATHS.some(r => r.test(u.pathname))) {
          emitAlert("Data Exfiltration Endpoint", `Cross-origin ${method} → ${host}${u.pathname}`, "high");
          correlate(host, "exfil-endpoint", url);
        }
      }
      if (isCross && u.protocol === "http:") {
        emitAlert("Plaintext Cross-Origin Request", `${method} sent over HTTP to ${host} — no TLS`, "medium");
        correlate(host, "no-tls", url);
      }
    } catch {}
  }

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

    for (const [label, re, severity] of BODY_RULES) {
      if (!re.test(str)) continue;
      if (label === "Base64 Blob" && host === location.hostname) continue;
      emitAlert(`Request Body: ${label}`, `${method} to ${url} — body contains ${label}`, severity);
      correlate(host, `body:${label}`, url);
    }
    if (str.length > 300) {
      const ratio = (str.match(/[A-Za-z0-9+/=]{20,}/g) || []).join("").length / str.length;
      if (ratio > 0.75) emitAlert("Encoded Request Body", `${method} to ${url} — body is ${(ratio*100).toFixed(0)}% base64 encoded`, "high");
    }
  }

  // --- 1. Intercept Fetch ---
  const originalFetch = window.fetch;
  window.fetch = async function(...args) {
    const input = args[0];
    const options = args[1] || {};
    let url = "";
    let method = "GET";

    if (input) {
      try {
        if (typeof input === "string") { url = input; method = options.method || "GET"; }
        else if (input instanceof Request) { url = input.url; method = input.method || options.method || "GET"; }
        else { url = input.toString(); method = options.method || "GET"; }
        method = method.toUpperCase();

        dispatchSecurityEvent("log_connection", { type: "fetch", url, method });
        assessUrl(url, method);
        inspectBody(options.body, url, method);

        const host = hostOf(url);
        if (BLOCKED_DOMAINS.has(host) || [...BLOCKED_DOMAINS].some(d => host.endsWith("." + d))) {
          emitAlert("Fetch Blocked", `Fetch to ${url} was blocked`, "critical");
          return Promise.reject(new Error(`[OctoPlamTree] Blocked request to: ${url}`));
        }

        // Check for exfil correlation
        const u = new URL(url, location.href);
        const suspicious = EXFIL_PAT.some(r => r.test(url)) || CRED_PATHS.some(r => r.test(u.pathname)) || (u.hostname !== location.hostname && BAD_TLDS.has(tld(u.hostname)));
        if (suspicious) logExfilCandidate("net_req", [], u.hostname + u.pathname);

      } catch (e) {}
    }
    return originalFetch.apply(this, args);
  };

  // --- 2. Intercept XMLHttpRequest ---
  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    this._url = url;
    this._method = method?.toUpperCase() || "GET";
    if (url) dispatchSecurityEvent("log_connection", { type: "xhr", url: url.toString(), method: method });
    return originalOpen.apply(this, [method, url, ...args]);
  };
  XMLHttpRequest.prototype.send = function(body) {
    const url = this._url || "";
    const method = this._method || "GET";
    try {
      assessUrl(url, method);
      inspectBody(body, url, method);
      
      const host = hostOf(url);
      if (BLOCKED_DOMAINS.has(host) || [...BLOCKED_DOMAINS].some(d => host.endsWith("." + d))) {
        emitAlert("XHR Blocked", `XHR to ${url} was blocked`, "critical");
        this.abort();
        return;
      }
      const u = new URL(url, location.href);
      if (EXFIL_PAT.some(r => r.test(url)) || BAD_TLDS.has(tld(u.hostname))) {
        logExfilCandidate("net_req", [], u.hostname + u.pathname);
      }
    } catch {}
    return originalSend.apply(this, arguments);
  };

  // --- 3. Intercept WebSockets ---
  const OriginalWebSocket = window.WebSocket;
  window.WebSocket = new Proxy(OriginalWebSocket, {
    construct(target, args) {
      const [url] = args;
      dispatchSecurityEvent("log_connection", { type: "websocket", url: url, method: "WS" });
      const host = hostOf(url);
      if (BLOCKED_DOMAINS.has(host) || [...BLOCKED_DOMAINS].some(d => host.endsWith("." + d))) {
        emitAlert("WebSocket Blocked", `WebSocket to ${url} was blocked`, "critical");
        // To block WS, we throw an error or return a fake socket.
        throw new Error(`[OctoPlamTree] Blocked WebSocket to: ${url}`);
      }
      return Reflect.construct(target, args);
    },
    get(target, prop, receiver) { return Reflect.get(target, prop, receiver); }
  });

  // --- 4. Intercept Document.Cookie Getter/Setter ---
  try {
    const cookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, "cookie") || Object.getOwnPropertyDescriptor(HTMLDocument.prototype, "cookie");
    if (cookieDescriptor && cookieDescriptor.configurable) {
      let lastCookieReadDispatch = 0;
      const COOKIE_READ_DEBOUNCE_MS = 2000;
      Object.defineProperty(document, "cookie", {
        get: function() {
          const val = cookieDescriptor.get.call(document);
          scanForJWTs(val, "cookie(get)");
          const now = Date.now();
          if ((now - lastCookieReadDispatch) >= COOKIE_READ_DEBOUNCE_MS) {
            lastCookieReadDispatch = now;
            dispatchSecurityEvent("cookie_access", { type: "read", value: val });
          }
          // Correlation logic
          const keys = (val||"").split(";").map(c => c.split("=")[0].trim());
          const sensitive = keys.filter(k => SESS_KEYS.some(sk => k.toLowerCase().includes(sk)));
          if (sensitive.length) logExfilCandidate("token_read", sensitive, null);
          return val;
        },
        set: function(val) {
          dispatchSecurityEvent("cookie_access", { type: "write", value: val });
          scanForJWTs(val, "cookie(set)");
          const key = (val||"").split("=")[0].trim();
          if (SESS_KEYS.some(sk => key.toLowerCase().includes(sk))) {
            emitAlert("Sensitive Cookie Write", `Script wrote session/auth cookie: "${key}"`, "medium");
          }
          cookieDescriptor.set.call(document, val);
        },
        configurable: true,
        enumerable: true
      });
    }
  } catch (e) {}

  // --- 5. Intercept localStorage / sessionStorage ---
  function patchStorage(store, label) {
    try {
      const _setItem = store.setItem.bind(store);
      const _getItem = store.getItem.bind(store);
      store.setItem = function(key, value) {
        const isSensitive = SESS_KEYS.some(sk => key.toLowerCase().includes(sk));
        scanForJWTs(String(value), `${label}.setItem(${key})`);
        if (isSensitive) {
          emitAlert(`${label} Sensitive Write`, `setItem("${key}") stores sensitive data`, "medium");
          logExfilCandidate("token_read", [key], null);
        }
        if (value && value.length > 500) {
          const ratio = (String(value).match(/[A-Za-z0-9+/=]{20,}/g)||[]).join("").length / value.length;
          if (ratio > 0.75) emitAlert(`${label} Encoded Blob`, `setItem("${key}") stores large base64 blob (${value.length}ch)`, "medium");
        }
        return _setItem(key, value);
      };
      store.getItem = function(key) {
        const val = _getItem(key);
        scanForJWTs(String(val), `${label}.getItem(${key})`);
        const isSensitive = SESS_KEYS.some(sk => key.toLowerCase().includes(sk));
        if (isSensitive && val) {
          logExfilCandidate("token_read", [key], null);
        }
        return val;
      };
    } catch {}
  }
  if (window.localStorage) patchStorage(window.localStorage, "localStorage");
  if (window.sessionStorage) patchStorage(window.sessionStorage, "sessionStorage");

})();
