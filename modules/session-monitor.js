// OctoPlamTree Session Monitor v2.0 — Content Script scope
(function () {
  const seen = new Set();
  const exfilLog = [];  // stores { ts, type, keys, url } for correlation

  // ── Constants ───────────────────────────────────────────────────────────────
  const SESS_KEYS  = ["session","sess","sid","token","jwt","auth","authtoken","userid","user_session","oauth","access_token","refresh_token","id_token","csrftoken","xsrf"];
  const BAD_TLDS   = ["tk","ml","ga","cf","gq","xyz","top","buzz","club","icu"];
  const EXFIL_PAT  = [/coinhive/i,/ngrok\.io/i,/\.onion/i,/\.(tk|ml|ga|cf|gq|xyz|top|buzz)(\/|$)/i];
  const CRED_PAT   = [/\/collect/i,/\/track/i,/\/pixel/i,/\/beacon/i,/\/log/i,/\/exfil/i,/\/report/i];

  // ── Helpers ─────────────────────────────────────────────────────────────────
  const mk    = (type, details, severity) => ({ type, details, severity });
  const tld   = h => h.split(".").pop();
  const xhost = u => { try { return new URL(u, location.href).hostname !== location.hostname; } catch { return false; } };
  const now   = () => Date.now();

  function emit(a) {
    const k = `${a.type}::${a.details.slice(0, 80)}`;
    if (seen.has(k)) return;
    seen.add(k);
    if (window.OctoLogger) try { OctoLogger.log(a.type, a.details, a.severity); } catch {}
  }

  // ── Cookie security attribute checker ───────────────────────────────────────
  function checkCookieAttrs(cookieStr) {
    const parts = cookieStr.split(";").map(p => p.trim().toLowerCase());
    const missing = [];
    if (!parts.includes("secure"))            missing.push("Secure");
    if (!parts.includes("httponly"))          missing.push("HttpOnly");
    if (!parts.some(p => p.startsWith("samesite="))) missing.push("SameSite");
    return missing;
  }

  // ── JWT intelligence ─────────────────────────────────────────────────────────
  // Decodes header+payload (no sig verification) and flags weak/dangerous configs
  function analyzeJWT(token, source) {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return;
      const decode = p => JSON.parse(atob(p.replace(/-/g,"+").replace(/_/g,"/")));
      const header  = decode(parts[0]);
      const payload = decode(parts[1]);
      const out = [];

      // alg:none / weak algorithms
      const alg = (header.alg || "").toUpperCase();
      if (alg === "NONE" || alg === "")
        out.push(mk("JWT Unsigned Token", `JWT with alg:none from ${source} — no signature verification`, "critical"));
      else if (["HS256","HS384","HS512"].includes(alg))
        out.push(mk("JWT Weak Algorithm", `JWT uses symmetric HMAC (${alg}) from ${source} — shared-secret risk`, "medium"));

      // Expiry checks
      const nowSec = Math.floor(now() / 1000);
      if (payload.exp && payload.exp < nowSec)
        out.push(mk("JWT Expired Token", `JWT from ${source} expired ${new Date(payload.exp*1000).toISOString()}`, "medium"));
      if (!payload.exp)
        out.push(mk("JWT No Expiry", `JWT from ${source} has no exp claim — token lives forever`, "high"));

      // Suspicious claims
      if (payload.iss && xhost(payload.iss))
        out.push(mk("JWT Foreign Issuer", `JWT iss: "${payload.iss}" doesn't match current origin`, "medium"));
      if (payload.aud && String(payload.aud) !== location.hostname)
        out.push(mk("JWT Audience Mismatch", `JWT aud: "${payload.aud}" vs current host: ${location.hostname}`, "medium"));

      out.forEach(emit);
    } catch { /* not a valid JWT */ }
  }

  // Detect JWT-shaped strings (3 base64url segments separated by dots)
  const JWT_RE = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
  function scanForJWTs(str, source) {
    if (!str) return;
    for (const match of str.matchAll(JWT_RE)) analyzeJWT(match[0], source);
  }

  // ── Session fixation detection ───────────────────────────────────────────────
  // Track session IDs seen before and after navigation / login events
  const sessionSnapshot = { pre: null, postLogin: null };

  function captureSessionId() {
    // Grab first session-ish cookie value as a fingerprint
    const cookies = document.cookie.split(";");
    for (const c of cookies) {
      const [k, v] = c.split("=").map(s => s.trim());
      if (SESS_KEYS.some(sk => k.toLowerCase().includes(sk)) && v) return { key: k, val: v };
    }
    return null;
  }

  function checkSessionFixation() {
    const current = captureSessionId();
    if (!current) return;
    if (!sessionSnapshot.pre) { sessionSnapshot.pre = current; return; }

    // If session ID hasn't changed after a login (password field submitted), flag it
    if (sessionSnapshot.pre.key === current.key && sessionSnapshot.pre.val === current.val)
      emit(mk("Session Fixation Risk", `Session ID "${current.key}" unchanged after credential submission — fixation possible`, "high"));
  }

  // Hook form submit to snapshot pre/post session ID
  document.addEventListener("submit", e => {
    if (e.target.querySelector('[type="password"]')) {
      sessionSnapshot.pre = captureSessionId();
      setTimeout(checkSessionFixation, 500);   // check ~500ms after submit
    }
  }, true);

  // ── Exfiltration correlation ─────────────────────────────────────────────────
  // When a sensitive token is read AND a suspicious outbound request fires
  // within a short window, escalate to a correlated exfiltration alert.
  const CORR_WINDOW_MS = 3000;

  function logExfilCandidate(type, keys, url) {
    exfilLog.push({ ts: now(), type, keys, url });
    // Prune entries older than window
    const cutoff = now() - CORR_WINDOW_MS;
    while (exfilLog.length && exfilLog[0].ts < cutoff) exfilLog.shift();

    const hasTokenRead = exfilLog.some(e => e.type === "token_read");
    const hasNetReq    = exfilLog.some(e => e.type === "net_req");
    if (hasTokenRead && hasNetReq) {
      const tokens = [...new Set(exfilLog.filter(e=>e.type==="token_read").flatMap(e=>e.keys))];
      const dest   = exfilLog.find(e=>e.type==="net_req")?.url || "unknown";
      emit(mk("Correlated Token Exfiltration", `Session token(s) [${tokens.join(",")}] read then sent to ${dest} within ${CORR_WINDOW_MS}ms`, "critical"));
    }
  }

  // ── document.cookie hooks ────────────────────────────────────────────────────
  const _cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");

  Object.defineProperty(document, "cookie", {
    get() {
      const val = _cookieDesc.get.call(this);
      // Scan for JWTs in cookie values on read
      scanForJWTs(val, "cookie(get)");
      // Detect sensitive key reads for correlation
      const keys = val.split(";").map(c => c.split("=")[0].trim());
      const sensitive = keys.filter(k => SESS_KEYS.some(sk => k.toLowerCase().includes(sk)));
      if (sensitive.length) {
        emit(mk("Sensitive Cookie Read", `Script read session cookie(s): [${sensitive.join(", ")}]`, "medium"));
        logExfilCandidate("token_read", sensitive, null);
      }
      return val;
    },
    set(newCookie) {
      // Security attribute check on write
      const missing = checkCookieAttrs(newCookie);
      if (missing.length) emit(mk("Insecure Cookie Write", `Cookie set without: [${missing.join(", ")}] — "${newCookie.split(";")[0].split("=")[0].trim()}"`, "medium"));

      // Sensitive key write
      const key = newCookie.split("=")[0].trim();
      if (SESS_KEYS.some(sk => key.toLowerCase().includes(sk))) {
        emit(mk("Sensitive Cookie Write", `Script wrote session/auth cookie: "${key}"`, "medium"));
        scanForJWTs(newCookie, `cookie(set:${key})`);
      }

      // Session fixation: if a pre-existing session cookie is overwritten with a server-supplied value
      if (sessionSnapshot.pre?.key === key) {
        const newVal = newCookie.split("=")[1]?.split(";")[0];
        if (newVal && newVal === sessionSnapshot.pre.val)
          emit(mk("Session Fixation Risk", `Session cookie "${key}" set to same value as pre-auth snapshot`, "high"));
      }

      return _cookieDesc.set.call(this, newCookie);
    },
    configurable: true,
  });

  // ── localStorage / sessionStorage monitoring ─────────────────────────────────
  function patchStorage(store, label) {
    const _setItem = store.setItem.bind(store);
    const _getItem = store.getItem.bind(store);
    const _removeItem = store.removeItem.bind(store);
    const _clear = store.clear.bind(store);

    store.setItem = function(key, value) {
      const isSensitive = SESS_KEYS.some(sk => key.toLowerCase().includes(sk));
      if (isSensitive) {
        emit(mk(`${label} Sensitive Write`, `setItem("${key}") stores sensitive data`, "medium"));
        scanForJWTs(String(value), `${label}.setItem(${key})`);
        logExfilCandidate("token_read", [key], null);
      }
      // Flag storing large encoded blobs (potential credential caching)
      if (value && value.length > 500) {
        const ratio = (String(value).match(/[A-Za-z0-9+/=]{20,}/g)||[]).join("").length / value.length;
        if (ratio > 0.75) emit(mk(`${label} Encoded Blob`, `setItem("${key}") stores large base64 blob (${value.length}ch, ratio:${(ratio*100).toFixed(0)}%)`, "medium"));
      }
      return _setItem(key, value);
    };

    store.getItem = function(key) {
      const val = _getItem(key);
      const isSensitive = SESS_KEYS.some(sk => key.toLowerCase().includes(sk));
      if (isSensitive && val) {
        emit(mk(`${label} Sensitive Read`, `getItem("${key}") read session/auth data`, "low"));
        scanForJWTs(String(val), `${label}.getItem(${key})`);
        logExfilCandidate("token_read", [key], null);
      }
      return val;
    };

    store.removeItem = function(key) {
      if (SESS_KEYS.some(sk => key.toLowerCase().includes(sk)))
        emit(mk(`${label} Session Key Removed`, `removeItem("${key}") — session token deleted`, "low"));
      return _removeItem(key);
    };

    store.clear = function() {
      emit(mk(`${label} Cleared`, `${label}.clear() wiped all storage — possible session destruction`, "medium"));
      return _clear();
    };
  }

  patchStorage(localStorage,   "localStorage");
  patchStorage(sessionStorage, "sessionStorage");

  // ── Network hook for exfiltration correlation ────────────────────────────────
  // Wraps fetch/XHR to log outbound requests to suspicious hosts so
  // the correlation engine can pair them with token reads above.
  const _fetch = window.fetch;
  window.fetch = function(input, init = {}) {
    const url = typeof input === "string" ? input : (input?.url ?? String(input));
    try {
      const u = new URL(url, location.href);
      const suspicious = EXFIL_PAT.some(r => r.test(url))
        || CRED_PAT.some(r => r.test(u.pathname))
        || (u.hostname !== location.hostname && BAD_TLDS.includes(tld(u.hostname)));
      if (suspicious) logExfilCandidate("net_req", [], u.hostname + u.pathname);
    } catch {}
    return _fetch.apply(this, arguments);
  };

  const _xhrOpen = XMLHttpRequest.prototype.open, _xhrSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(m, u) { this._sm = m; this._su = u; return _xhrOpen.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function(body) {
    try {
      const u = new URL(this._su || "", location.href);
      if (EXFIL_PAT.some(r => r.test(this._su)) || BAD_TLDS.includes(tld(u.hostname)))
        logExfilCandidate("net_req", [], u.hostname + u.pathname);
    } catch {}
    return _xhrSend.apply(this, arguments);
  };

  // ── Public API ───────────────────────────────────────────────────────────────
  window.OctoSessionMonitor = {
    getExfilLog:      () => [...exfilLog],
    snapshotSession:  captureSessionId,
    scanJWT:          (token, src) => analyzeJWT(token, src || "manual"),
  };
})();