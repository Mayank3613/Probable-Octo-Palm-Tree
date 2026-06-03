// OctoPlamTree Threat Detector v2.0 — Content Script scope
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

  const alert = (type, details, severity) => ({ type, details, severity });
  const tld   = h => h.split(".").pop();
  const xhost = url => { try { return new URL(url, location.href).hostname !== location.hostname; } catch { return false; } };

  function emit(a) {
    const k = `${a.type}::${a.details.slice(0,80)}`;
    if (seen.has(k)) return;
    seen.add(k);
    if (a.type.startsWith("net:")) networkLog.push(a);
    if (window.OctoLogger) try { OctoLogger.log(a.type, a.details, a.severity); } catch {}
  }

  // (Network hooks moved to inject.js Main World hook)

  // ── Shadow DOM inspection ───────────────────────────────────────────────────
  function inspectShadow(root, host) {
    if (!root || knownShadowRoots.has(root)) return;
    knownShadowRoots.add(root);
    const id = host ? (host.id ? `#${host.id}` : host.tagName.toLowerCase()) : "?";

    for (const s of root.querySelectorAll("script")) {
      const src = s.getAttribute("src")||"", c = s.innerHTML;
      if (MINER_KW.some(k => src.includes(k)||c.includes(k)))
        emit(alert("Shadow DOM Cryptominer", `Miner in shadow root of <${id}>`, "critical"));
      if (c.length > 5000 && DYNA_CALLS.filter(t => c.includes(t)).length >= 2)
        emit(alert("Shadow DOM Obfuscated Script", `Obfuscated script (${c.length}ch) in <${id}>`, "high"));
    }

    const hidden = [...root.querySelectorAll("iframe")].filter(f => {
      const s = getComputedStyle(f);
      return s.display==="none"||s.visibility==="hidden"||+s.opacity===0||f.offsetWidth<=2||f.offsetHeight<=2;
    });
    if (hidden.length) emit(alert("Shadow DOM Hidden Iframe", `${hidden.length} hidden iframe(s) in <${id}>`, "high"));

    if (root.querySelector('input[type="password"]'))
      emit(alert("Shadow DOM Login Form", `Password input in shadow root of <${id}>`, "high"));

    if (root.mode === "closed")
      emit(alert("Closed Shadow Root", `Uninspectable closed root on <${id}>`, "medium"));

    for (const el of root.querySelectorAll("*")) if (el.shadowRoot) inspectShadow(el.shadowRoot, el);
  }

  // (attachShadow hook removed because it's blind to Main World; Scans.shadows() handles it)

  // ── Attribute mutation analysis ─────────────────────────────────────────────
  function analyzeAttr(tag, attr, oldVal, newVal, el) {
    const out = [];
    if (["src","href","action","data"].includes(attr) && newVal) {
      if (newVal.startsWith("data:"))
        out.push(alert("Data URI Injection", `<${tag}> ${attr} set to data: URI`, "high"));
      else if (xhost(newVal)) {
        try {
          const u = new URL(newVal, location.href);
          out.push(alert("Suspicious Attribute Mutation", `<${tag}> ${attr} → ${u.href}${oldVal?` (was:${oldVal})`:""}`, BAD_TLDS.includes(tld(u.hostname))?"high":"medium"));
        } catch {}
      }
    }
    if (tag==="script" && attr==="type" && oldVal && newVal!==oldVal)
      out.push(alert("Script Type Mutation", `<script> type: "${oldVal}" → "${newVal}"`, "medium"));
    if (tag==="meta" && attr==="http-equiv" && /refresh/i.test(newVal))
      out.push(alert("Meta Refresh Injection", `<meta http-equiv="refresh"> set`, "high"));
    if (tag==="meta" && attr==="content" && el.getAttribute("http-equiv")==="refresh")
      out.push(alert("Meta Refresh Content Changed", `refresh content → "${newVal}"`, "medium"));
    if (tag==="base" && attr==="href" && newVal)
      out.push(alert("Base URL Hijack", `<base href> → "${newVal}"`, "critical"));
    if (attr==="formaction" && newVal && xhost(newVal))
      try { out.push(alert("Form Action Hijack", `formaction → ${new URL(newVal,location.href).hostname}`, "critical")); } catch {}
    if (attr==="integrity" && oldVal && !newVal)
      out.push(alert("SRI Integrity Removed", `<${tag}> integrity attribute removed`, "high"));
    return out;
  }

  // ── Structural threat scans ─────────────────────────────────────────────────
  const Scans = {// script detection
    scripts() {
      const out = [];
      for (const s of document.scripts) {
        const src = s.getAttribute("src")||"", c = s.innerHTML;
        if (MINER_KW.some(k => src.toLowerCase().includes(k.toLowerCase())||c.includes(k)))//cryptominer signature
          out.push(alert("Cryptominer Script", `Miner signature: ${src||"inline"}`, "critical"));
        if (c.length > 8000 && DYNA_CALLS.filter(t => c.includes(t)).length >= 2)//  obfuscation heuristic
          out.push(alert("Obfuscated Javascript", `Large script (${c.length}ch) with dynamic exec`, "high"));
        if (src) try { const u=new URL(src,location.href); if(BAD_TLDS.includes(tld(u.hostname))) out.push(alert("Suspicious External Script",`Script from suspicious TLD: ${src}`,"medium")); } catch {}
      }//external script TLD check
      return out;
    },
    iframes() {// hidden iframe detection
      const hidden = [...document.getElementsByTagName("iframe")].filter(f => {
        const s = getComputedStyle(f);
        return s.display==="none"||s.visibility==="hidden"||+s.opacity===0||f.offsetWidth<=2||f.offsetHeight<=2||parseFloat(s.left)<-500||parseFloat(s.top)<-500;
      });
      if (!hidden.length) return [];
      return [alert(hidden.length>=3?"Excessive Hidden Iframes":"Hidden Iframe Detected", `${hidden.length} invisible iframe(s): ${hidden.slice(0,3).map(f=>f.src||"about:blank").join(", ")}`, hidden.length>=3?"high":"medium")];
    },
    overlays() {// clickjacking overlay detection
      for (const el of document.querySelectorAll("div,section,aside,span")) {
        const s = getComputedStyle(el), op = +s.opacity;
        if ((s.position==="fixed"||s.position==="absolute") && +s.zIndex>5000 && op>0 && op<0.3) {
          const r=el.getBoundingClientRect(), pct=r.width*r.height/(innerWidth*innerHeight);
          if (pct>0.6) return [alert("Clickjacking Overlay",`Semi-transparent overlay: ${(pct*100).toFixed(0)}% viewport (z:${s.zIndex} op:${s.opacity})`,"high")];
        }
      }
      return [];
    },
    forms() {// form validation
      const out = [];
      const pw = document.querySelectorAll('input[type="password"]');
      if (!pw.length) return out;
      if (location.protocol==="http:") out.push(alert("Insecure Login Form",`Password field on HTTP (${location.hostname})`,"critical"));
      for (const f of document.forms) {
        const a = f.getAttribute("action"); if (!a) continue;
        try { const u=new URL(a,location.href); if(u.hostname!==location.hostname&&f.querySelector('[type="password"]')) out.push(alert("Credential Exfiltration Form",`Form POSTs to ${u.hostname}`,"critical")); } catch {}
      }
      const email = document.querySelector('input[type="email"],[name*="email"],[name*="user"],[placeholder*="email" i]');
      if (email && BAD_TLDS.includes(tld(location.hostname))) out.push(alert("Phishing Login Page",`Login form on suspicious TLD (.${tld(location.hostname)})`,"critical"));
      return out;
    },
    docWrite() {// dynamic page rewrite detection
      return [...document.scripts].filter(s=>s.innerHTML.includes("document.write")&&s.innerHTML.length>500)
        .map(s=>alert("Dynamic Page Rewrite",`document.write() in script (${s.innerHTML.length}ch)`,"medium"));
    },
    shadows() {// shadow DOM inspection
      for (const el of document.querySelectorAll("*")) if(el.shadowRoot) inspectShadow(el.shadowRoot,el);
      return [];
    }
  };

  const ThreatDetector = {
    runScan() {
      return [...Scans.scripts(),...Scans.iframes(),...Scans.overlays(),...Scans.forms(),...Scans.docWrite(),...Scans.shadows()]
        .filter(a=>{ const k=`${a.type}::${a.details.slice(0,80)}`; if(seen.has(k))return false; seen.add(k); return true; });
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
        }
      }
      if (m.type === "attributes") {
        const el=m.target, tag=el.tagName?.toLowerCase(), watched=WATCH_TAGS[tag];
        if (watched?.includes(m.attributeName))
          analyzeAttr(tag, m.attributeName, m.oldValue, el.getAttribute(m.attributeName), el).forEach(emit);
      }
    }
    if (scan) ThreatDetector.runScan().forEach(a => { if(window.OctoLogger) try{OctoLogger.log(a.type,a.details,a.severity);}catch{} });
  }).observe(document, {
    childList: true, subtree: true,
    attributes: true, attributeOldValue: true,
    attributeFilter: ["src","href","action","formaction","data","type","integrity","http-equiv","content","srcdoc","sandbox"],
  });

  window.OctoThreatDetector = ThreatDetector;
})();