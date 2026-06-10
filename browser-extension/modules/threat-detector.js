// OctoPlamTree Threat Detector v2.1 — Content Script scope
// SPA-aware: detects threats in dynamically injected content via per-node
// inline analysis + History API / hashchange navigation handling.
(function () {
  const seen = new Set();
  const networkLog = [];
  const knownShadowRoots = new WeakSet();

  const MINER_KW   = ["coinhive","cryptoloot","deepminer","jsecoin","webminerPool","miner.start","cryptonight","CoinHive.Anonymous"];
  const BAD_TLDS   = ["tk","ml","ga","cf","gq","xyz","top","buzz","club","icu"];
  const NET_PAT    = [/coinhive/i,/cryptoloot/i,/deepminer/i,/jsecoin/i,/webminer/i,/base64[,;]/i,/\.onion/i,/ngrok\.io/i,/\.(tk|ml|ga|cf|gq|xyz|top|buzz)(\/|$)/i];
  const CRED_PAT   = [/\/login/i,/\/signin/i,/\/auth/i,/\/account/i,/\/credential/i,/\/password/i,/\/wallet/i,/\/session/i];
  const DYNA_CALLS = ["eval","unescape","String.fromCharCode","atob","document.write","Function(","setTimeout(atob","decodeURIComponent"];
  const WATCH_TAGS = {script:["src","type","integrity"],iframe:["src","srcdoc","sandbox"],a:["href","ping"],form:["action","formaction"],input:["type","formaction"],meta:["http-equiv","content"],link:["href","rel"],object:["data"],embed:["src"],base:["href"]};
  const RISKY_SET = new Set(["script","iframe","form","object","embed"]);

  // XSS inline-script patterns for per-node fast-path analysis
  const XSS_PAT = [
    /document\.cookie/i,
    /document\.write\s*\(/i,
    /eval\s*\(/i,
    /setTimeout\s*\(\s*['"`]/i,
    /setInterval\s*\(\s*['"`]/i,
    /new\s+Function\s*\(/i,
    /location\s*(?:\.href|\.replace|\.assign)\s*=/i,
    /window\.open\s*\(/i,
    /<script[^>]*>/i,
    /javascript\s*:/i,
    /on(?:load|error|click|mouse\w+|focus|blur|key\w+)\s*=/i,
  ];

  const mkAlert = (type, details, severity) => ({ type, details, severity });
  const tld   = h => h.split(".").pop();
  const xhost = url => { try { return new URL(url, location.href).hostname !== location.hostname; } catch { return false; } };

  function emit(a) {
    const k = `${a.type}::${a.details.slice(0,80)}`;
    if (seen.has(k)) return;
    seen.add(k);
    if (a.type.startsWith("net:")) networkLog.push(a);
    if (window.OctoLogger) try { OctoLogger.log(a.type, a.details, a.severity); } catch {}
  }

  // ── Network monitoring ──────────────────────────────────────────────────────
  function analyzeReq(url, method, body) {
    const out = [];
    if (NET_PAT.some(r => r.test(url)))
      out.push(mkAlert("Suspicious Network Request", `${method} → ${url}`, "high"));
    try {
      const u = new URL(url, location.href);
      if (u.hostname !== location.hostname && /^(POST|PUT|PATCH)$/i.test(method)) {
        out.push(mkAlert(
          CRED_PAT.some(r => r.test(u.pathname)) ? "Credential Exfiltration Request" : "Cross-Origin Data Submission",
          `${method} → ${u.hostname}${u.pathname}`,
          CRED_PAT.some(r => r.test(u.pathname)) ? "critical" : "medium"
        ));
      }
      if (body && body.length > 200) {
        const ratio = (body.match(/[A-Za-z0-9+/=]{20,}/g)||[]).join("").length / body.length;
        if (ratio > 0.7) out.push(mkAlert("Encoded Request Payload", `${method} → ${url} (b64 ratio ${(ratio*100).toFixed(0)}%)`, "medium"));
      }
    } catch {}
    return out;
  }

  const _fetch = fetch;
  window.fetch = function(input, init = {}) {
    const url = typeof input === "string" ? input : (input?.url ?? String(input));
    analyzeReq(url, (init.method||"GET").toUpperCase(), init.body ? String(init.body) : null).forEach(emit);
    return _fetch.apply(this, arguments);
  };

  const _open = XMLHttpRequest.prototype.open, _send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(m, u) { this._om = m; this._ou = u; return _open.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function(body) {
    analyzeReq(this._ou||"", this._om||"GET", body ? String(body) : null).forEach(emit);
    return _send.apply(this, arguments);
  };

  // ── Shadow DOM inspection ───────────────────────────────────────────────────
  function inspectShadow(root, host) {
    if (!root || knownShadowRoots.has(root)) return;
    knownShadowRoots.add(root);
    const id = host ? (host.id ? `#${host.id}` : host.tagName.toLowerCase()) : "?";

    for (const s of root.querySelectorAll("script")) {
      const src = s.getAttribute("src")||"", c = s.innerHTML;
      if (MINER_KW.some(k => src.includes(k)||c.includes(k)))
        emit(mkAlert("Shadow DOM Cryptominer", `Miner in shadow root of <${id}>`, "critical"));
      if (c.length > 5000 && DYNA_CALLS.filter(t => c.includes(t)).length >= 2)
        emit(mkAlert("Shadow DOM Obfuscated Script", `Obfuscated script (${c.length}ch) in <${id}>`, "high"));
    }

    const hidden = [...root.querySelectorAll("iframe")].filter(f => {
      const s = getComputedStyle(f);
      return s.display==="none"||s.visibility==="hidden"||+s.opacity===0||f.offsetWidth<=2||f.offsetHeight<=2;
    });
    if (hidden.length) emit(mkAlert("Shadow DOM Hidden Iframe", `${hidden.length} hidden iframe(s) in <${id}>`, "high"));

    if (root.querySelector('input[type="password"]'))
      emit(mkAlert("Shadow DOM Login Form", `Password input in shadow root of <${id}>`, "high"));

    if (root.mode === "closed")
      emit(mkAlert("Closed Shadow Root", `Uninspectable closed root on <${id}>`, "medium"));

    for (const el of root.querySelectorAll("*")) if (el.shadowRoot) inspectShadow(el.shadowRoot, el);
  }

  const _attachShadow = Element.prototype.attachShadow;
  Element.prototype.attachShadow = function(init) {
    const root = _attachShadow.call(this, init);
    setTimeout(() => inspectShadow(root, this), 0);
    return root;
  };

  // ── Attribute mutation analysis ─────────────────────────────────────────────
  function analyzeAttr(tag, attr, oldVal, newVal, el) {
    const out = [];
    if (["src","href","action","data"].includes(attr) && newVal) {
      if (newVal.startsWith("data:"))
        out.push(mkAlert("Data URI Injection", `<${tag}> ${attr} set to data: URI`, "high"));
      else if (xhost(newVal)) {
        try {
          const u = new URL(newVal, location.href);
          out.push(mkAlert("Suspicious Attribute Mutation", `<${tag}> ${attr} → ${u.href}${oldVal?` (was:${oldVal})`:""}`, BAD_TLDS.includes(tld(u.hostname))?"high":"medium"));
        } catch {}
      }
    }
    if (tag==="script" && attr==="type" && oldVal && newVal!==oldVal)
      out.push(mkAlert("Script Type Mutation", `<script> type: "${oldVal}" → "${newVal}"`, "medium"));
    if (tag==="meta" && attr==="http-equiv" && /refresh/i.test(newVal))
      out.push(mkAlert("Meta Refresh Injection", `<meta http-equiv="refresh"> set`, "high"));
    if (tag==="meta" && attr==="content" && el.getAttribute("http-equiv")==="refresh")
      out.push(mkAlert("Meta Refresh Content Changed", `refresh content → "${newVal}"`, "medium"));
    if (tag==="base" && attr==="href" && newVal)
      out.push(mkAlert("Base URL Hijack", `<base href> → "${newVal}"`, "critical"));
    if (attr==="formaction" && newVal && xhost(newVal))
      try { out.push(mkAlert("Form Action Hijack", `formaction → ${new URL(newVal,location.href).hostname}`, "critical")); } catch {}
    if (attr==="integrity" && oldVal && !newVal)
      out.push(mkAlert("SRI Integrity Removed", `<${tag}> integrity attribute removed`, "high"));
    return out;
  }

  // ── Per-node inline XSS fast-path (SPA dynamic injection) ──────────────────
  // Scans a single newly added element (and its descendants) for XSS patterns
  // without waiting for the next periodic runScan() cycle.
  function scanNodeForXSS(node) {
    const scripts = [];
    if (node.tagName && node.tagName.toLowerCase() === "script") scripts.push(node);
    if (node.querySelectorAll) scripts.push(...node.querySelectorAll("script"));

    for (const s of scripts) {
      const src = s.getAttribute("src") || "";
      const content = s.textContent || s.innerHTML || "";

      // Cryptominer signature
      if (MINER_KW.some(k => src.toLowerCase().includes(k.toLowerCase()) || content.includes(k)))
        emit(mkAlert("Cryptominer Script (Dynamic)", `Miner signature in dynamically injected script: ${src || "inline"}`, "critical"));

      // Obfuscation heuristic
      if (content.length > 8000 && DYNA_CALLS.filter(t => content.includes(t)).length >= 2)
        emit(mkAlert("Obfuscated Javascript (Dynamic)", `Large dynamic script (${content.length}ch) with dynamic exec calls`, "high"));

      // XSS payload patterns in inline scripts
      const xssMatches = XSS_PAT.filter(p => p.test(content));
      if (xssMatches.length >= 2)
        emit(mkAlert("XSS Payload in Dynamic Script", `Dynamically injected inline script matches ${xssMatches.length} XSS patterns${src ? ` src:${src}` : ""}`, "critical"));
      else if (xssMatches.length === 1 && content.length < 500)
        // Short inline scripts with even one XSS pattern are suspicious
        emit(mkAlert("Suspicious Dynamic Script", `Short dynamic inline script (${content.length}ch) matches XSS pattern`, "high"));

      // External script from bad TLD
      if (src) {
        try {
          const u = new URL(src, location.href);
          if (BAD_TLDS.includes(tld(u.hostname)))
            emit(mkAlert("Suspicious External Script (Dynamic)", `Dynamically injected script from suspicious TLD: ${src}`, "high"));
        } catch {}
      }
    }

    // Scan for dynamically injected iframes
    const iframes = [];
    if (node.tagName && node.tagName.toLowerCase() === "iframe") iframes.push(node);
    if (node.querySelectorAll) iframes.push(...node.querySelectorAll("iframe"));
    const hiddenFrames = iframes.filter(f => {
      const s = getComputedStyle(f);
      return s.display==="none"||s.visibility==="hidden"||+s.opacity===0||f.offsetWidth<=2||f.offsetHeight<=2;
    });
    if (hiddenFrames.length)
      emit(mkAlert("Hidden Iframe (Dynamic)", `${hiddenFrames.length} dynamically injected hidden iframe(s)`, "high"));
  }

  // ── Structural threat scans ─────────────────────────────────────────────────
  const Scans = {
    scripts() {
      const out = [];
      for (const s of document.scripts) {
        const src = s.getAttribute("src")||"", c = s.innerHTML;
        if (MINER_KW.some(k => src.toLowerCase().includes(k.toLowerCase())||c.includes(k)))
          out.push(mkAlert("Cryptominer Script", `Miner signature: ${src||"inline"}`, "critical"));
        if (c.length > 8000 && DYNA_CALLS.filter(t => c.includes(t)).length >= 2)
          out.push(mkAlert("Obfuscated Javascript", `Large script (${c.length}ch) with dynamic exec`, "high"));
        if (src) try { const u=new URL(src,location.href); if(BAD_TLDS.includes(tld(u.hostname))) out.push(mkAlert("Suspicious External Script",`Script from suspicious TLD: ${src}`,"medium")); } catch {}
      }
      return out;
    },
    iframes() {
      const hidden = [...document.getElementsByTagName("iframe")].filter(f => {
        const s = getComputedStyle(f);
        return s.display==="none"||s.visibility==="hidden"||+s.opacity===0||f.offsetWidth<=2||f.offsetHeight<=2||parseFloat(s.left)<-500||parseFloat(s.top)<-500;
      });
      if (!hidden.length) return [];
      return [mkAlert(hidden.length>=3?"Excessive Hidden Iframes":"Hidden Iframe Detected", `${hidden.length} invisible iframe(s): ${hidden.slice(0,3).map(f=>f.src||"about:blank").join(", ")}`, hidden.length>=3?"high":"medium")];
    },
    overlays() {
      for (const el of document.querySelectorAll("div,section,aside,span")) {
        const s = getComputedStyle(el), op = +s.opacity;
        if ((s.position==="fixed"||s.position==="absolute") && +s.zIndex>5000 && op>0 && op<0.3) {
          const r=el.getBoundingClientRect(), pct=r.width*r.height/(innerWidth*innerHeight);
          if (pct>0.6) return [mkAlert("Clickjacking Overlay",`Semi-transparent overlay: ${(pct*100).toFixed(0)}% viewport (z:${s.zIndex} op:${s.opacity})`,"high")];
        }
      }
      return [];
    },
    forms() {
      const out = [];
      const pw = document.querySelectorAll('input[type="password"]');
      if (!pw.length) return out;
      if (location.protocol==="http:") out.push(mkAlert("Insecure Login Form",`Password field on HTTP (${location.hostname})`,"critical"));
      for (const f of document.forms) {
        const a = f.getAttribute("action"); if (!a) continue;
        try { const u=new URL(a,location.href); if(u.hostname!==location.hostname&&f.querySelector('[type="password"]')) out.push(mkAlert("Credential Exfiltration Form",`Form POSTs to ${u.hostname}`,"critical")); } catch {}
      }
      const email = document.querySelector('input[type="email"],[name*="email"],[name*="user"],[placeholder*="email" i]');
      if (email && BAD_TLDS.includes(tld(location.hostname))) out.push(mkAlert("Phishing Login Page",`Login form on suspicious TLD (.${tld(location.hostname)})`,"critical"));
      return out;
    },
    docWrite() {
      return [...document.scripts].filter(s=>s.innerHTML.includes("document.write")&&s.innerHTML.length>500)
        .map(s=>mkAlert("Dynamic Page Rewrite",`document.write() in script (${s.innerHTML.length}ch)`,"medium"));
    },
    shadows() {
      for (const el of document.querySelectorAll("*")) if(el.shadowRoot) inspectShadow(el.shadowRoot,el);
      return [];
    }
  };

  const ThreatDetector = {
    runScan() {
      return [...Scans.scripts(),...Scans.iframes(),...Scans.overlays(),...Scans.forms(),...Scans.docWrite(),...Scans.shadows()]
        .filter(a=>{ const k=`${a.type}::${a.details.slice(0,80)}`; if(seen.has(k))return false; seen.add(k); return true; });
    },
    // Exposed so content.js can trigger a full re-scan on SPA navigation
    runSpaNavigationScan() {
      seen.clear(); // Clear dedup cache on navigation so new-page content is freshly evaluated
      return ThreatDetector.runScan();
    },
    getNetworkLog: () => [...networkLog],
  };

  // ── MutationObserver ────────────────────────────────────────────────────────
  const RISKY = "script,iframe,form,object,embed";
  new MutationObserver(mutations => {
    let scan = false;
    for (const m of mutations) {
      if (m.type === "childList") {
        for (const n of m.addedNodes) {
          if (n.nodeType !== 1) continue;
          const tag = n.tagName?.toLowerCase();
          if (RISKY_SET.has(tag)||(tag==="input"&&n.type==="password")) scan = true;
          if (n.querySelector?.(RISKY+",input[type='password']")) scan = true;
          for (const h of [n,...(n.querySelectorAll?.("*")||[])]) if(h.shadowRoot) inspectShadow(h.shadowRoot,h);

          // ── SPA XSS fast-path: per-node inline analysis fires immediately ──
          // This ensures dynamically injected scripts are caught between periodic
          // runScan() cycles, which is the exact gap exploited in SPA XSS attacks.
          scanNodeForXSS(n);
        }
      }
      if (m.type === "attributes") {
        const el=m.target, tag=el.tagName?.toLowerCase(), watched=WATCH_TAGS[tag];
        if (watched?.includes(m.attributeName))
          analyzeAttr(tag, m.attributeName, m.oldValue, el.getAttribute(m.attributeName), el).forEach(emit);
      }
    }
    if (scan) ThreatDetector.runScan().forEach(a => { if(window.OctoLogger) try{OctoLogger.log(a.type,a.details,a.severity);}catch{} });
  }).observe(document.documentElement, {
    childList: true, subtree: true,
    attributes: true, attributeOldValue: true,
    attributeFilter: ["src","href","action","formaction","data","type","integrity","http-equiv","content","srcdoc","sandbox"],
  });

  window.OctoThreatDetector = ThreatDetector;
})();
