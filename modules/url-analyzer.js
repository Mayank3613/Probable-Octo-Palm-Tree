// OctoPlamTree URL Analyzer v2.0 (ES6 module — used by background.js)

const SUSPICIOUS_WORDS = [
  "login", "verify", "secure", "update-password", "banking", "signin",
  "accounts", "wallet", "credential", "reset-pass", "verification",
  "support-portal", "billing-update", "confirm", "suspended", "alert",
  "unusual-activity", "restore", "unlock", "authenticate", "recovery",
  "helpdesk", "paymentupdate"
];

const TARGET_BRANDS = [
  "google", "paypal", "microsoft", "apple", "netflix", "amazon",
  "facebook", "github", "chase", "bankofamerica", "wellsfargo",
  "binance", "coinbase", "instagram", "twitter", "linkedin",
  "dropbox", "icloud", "outlook", "yahoo", "steam", "discord",
  "whatsapp", "telegram"
];

const SUSPICIOUS_TLDS = new Set([
  "tk","ml","ga","cf","gq","xyz","top","buzz","club","work",
  "icu","cam","rest","gdn","cyou","bond","cfd","sbs","monster"
]);

const TRUSTED_TLDS = new Set(["gov", "edu", "mil"]);

const KNOWN_SAFE_DOMAINS = new Set([
  "google.com","youtube.com","microsoft.com","apple.com","amazon.com",
  "facebook.com","twitter.com","linkedin.com","github.com",
  "stackoverflow.com","wikipedia.org","reddit.com","netflix.com",
  "adobe.com","dropbox.com","mozilla.org","cloudflare.com",
  "akamai.com","fastly.com"
]);

const MALICIOUS_JS_PATTERNS = [
  { pattern: /eval\s*\(/g,                             label: "eval()",               weight: 15 },
  { pattern: /document\.write\s*\(/g,                  label: "document.write()",     weight: 10 },
  { pattern: /unescape\s*\(/g,                         label: "unescape()",           weight: 12 },
  { pattern: /String\.fromCharCode\s*\(/g,             label: "String.fromCharCode",  weight: 12 },
  { pattern: /atob\s*\(/g,                             label: "atob()",               weight: 10 },
  { pattern: /setTimeout\s*\(\s*atob/g,                label: "setTimeout(atob)",     weight: 18 },
  { pattern: /Function\s*\(\s*['"`]/g,                 label: "Function() ctor",      weight: 15 },
  { pattern: /decodeURIComponent\s*\(/g,               label: "decodeURIComponent",   weight:  8 },
  { pattern: /\bexec\s*\(/g,                           label: "exec()",               weight:  8 },
  { pattern: /window\s*\[\s*['"`]location/g,           label: "window['location']",   weight: 12 },
  { pattern: /crypto(?:night|loot|\.mine)/gi,          label: "cryptominer API",      weight: 40 },
  { pattern: /coinhive|webminerpool|minero\.cc/gi,     label: "known miner",          weight: 40 },
  { pattern: /addEventListener\s*\(\s*['"`]keydown/g,  label: "keydown listener",     weight: 10 },
  { pattern: /\.value\s*\+?=.*XMLHttpRequest/g,        label: "value exfil via XHR",  weight: 20 },
  { pattern: /window\.location\s*=\s*atob/g,           label: "obfuscated redirect",  weight: 25 },
  { pattern: /top\.location\s*=/g,                     label: "top.location redirect",weight: 15 },
];

const RDAP_SERVERS = {
  com:  "https://rdap.verisign.com/com/v1/",
  net:  "https://rdap.verisign.com/net/v1/",
  org:  "https://rdap.publicinterestregistry.org/rdap/",
  io:   "https://rdap.nic.io/",
  co:   "https://rdap.nic.co/",
  uk:   "https://rdap.nominet.uk/uk/",
  de:   "https://rdap.denic.de/",
  info: "https://rdap.afilias.net/rdap/info/",
  biz:  "https://rdap.nic.biz/",
  xyz:  "https://rdap.nic.xyz/",
};

// ── Utilities ────────────────────────────────────────────────────────────────

function levenshtein(a, b) {
  const m = [];
  for (let i = 0; i <= b.length; i++) m[i] = [i];
  for (let j = 0; j <= a.length; j++) m[0][j] = j;
  for (let i = 1; i <= b.length; i++)
    for (let j = 1; j <= a.length; j++)
      m[i][j] = b[i-1] === a[j-1]
        ? m[i-1][j-1]
        : Math.min(m[i-1][j-1]+1, m[i][j-1]+1, m[i-1][j]+1);
  return m[b.length][a.length];
}

function entropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return Object.values(freq).reduce((e, f) => {
    const p = f / len; return e - p * Math.log2(p);
  }, 0);
}

const clamp  = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const sig    = (label, delta, conf, cat) => ({ label, delta, conf, cat, weighted: delta * conf });
const toRaw  = signals => signals.reduce((a, s) => a + s.weighted, 0);

function normalizeScore(raw) {
  if (raw <= 0) return 0;
  return Math.round(clamp(100 * (1 - Math.exp(-raw / 80)), 0, 99));
}

function buildResult(signals, raw, url, extras = {}) {
  const score    = normalizeScore(raw);
  const severity = score >= 70 ? "critical" : score >= 50 ? "high" : score >= 35 ? "medium" : "safe";
  const byCategory = {};
  for (const s of signals) (byCategory[s.cat] = byCategory[s.cat] || []).push(s.label);
  const reason = signals
    .filter(s => s.weighted > 0)
    .sort((a, b) => b.weighted - a.weighted)
    .map(s => s.label).join("; ");
  return { isSuspicious: score >= 35, score, rawScore: Math.round(raw), severity, reason, signals, byCategory, url, ...extras };
}

// ── Sync checks (all offline) ────────────────────────────────────────────────

function runSyncChecks(urlString) {
  let url, hostname, pathname, fullUrl;
  try {
    url = new URL(urlString);
    hostname = url.hostname.toLowerCase();
    pathname = url.pathname.toLowerCase();
    fullUrl  = url.href.toLowerCase();
  } catch (_) {
    return { signals: [], rawScore: 0, error: "Invalid URL" };
  }

  if (["localhost","127.0.0.1"].includes(hostname) ||
      ["chrome-extension:","chrome:","about:","moz-extension:"].includes(url.protocol))
    return { signals: [], rawScore: 0, internal: true };

  const signals = [];
  const parts   = hostname.split(".");
  const tld     = parts[parts.length - 1] || "";
  const primary = parts.length >= 2 ? parts[parts.length - 2] : hostname;
  const apex    = parts.slice(-2).join(".");

  // Negative (safe) signals
  if (KNOWN_SAFE_DOMAINS.has(apex))  signals.push(sig("Known-safe domain",    -30, 0.90, "safe"));
  if (TRUSTED_TLDS.has(tld))         signals.push(sig(`Trusted TLD .${tld}`,  -25, 0.85, "safe"));
  if (url.protocol === "https:")      signals.push(sig("HTTPS",                 -5, 0.60, "safe"));

  // 1. Phishing keywords
  for (const w of SUSPICIOUS_WORDS) {
    if (hostname.includes(w)) signals.push(sig(`Keyword '${w}' in domain`, 30, 0.85, "keywords"));
    else if (pathname.includes(w)) signals.push(sig(`Keyword '${w}' in path`, 12, 0.60, "keywords"));
  }

  // 2. Brand typosquatting
  for (const brand of TARGET_BRANDS) {
    if (hostname.includes(brand)) {
      const official = ["com","org","net","io"].some(t =>
        hostname === `${brand}.${t}` || hostname.endsWith(`.${brand}.${t}`) || hostname === `www.${brand}.com`
      );
      if (!official) signals.push(sig(`Brand impersonation: '${brand}'`, 50, 0.90, "brands"));
    } else {
      const d = levenshtein(primary, brand);
      if (d === 1) signals.push(sig(`Typosquat '${brand}' (dist 1)`, 50, 0.90, "brands"));
      else if (d === 2 && primary.length >= 5) signals.push(sig(`Typosquat '${brand}' (dist 2)`, 35, 0.70, "brands"));
    }
  }

  // 3. Domain entropy
  const domNoTLD = parts.slice(0, -1).join(".");
  if (entropy(domNoTLD) > 4.0 && domNoTLD.length > 10)
    signals.push(sig(`High entropy (${entropy(domNoTLD).toFixed(2)}) — likely DGA`, 25, 0.75, "entropy"));

  // 4–10. Structural signals
  if (parts.length - 2 > 3)
    signals.push(sig(`${parts.length - 2} subdomains`, 20, 0.70, "structure"));
  if (/^[0-9.]+$/.test(hostname) || /^\[.*\]$/.test(hostname))
    signals.push(sig("Raw IP hostname", 25, 0.80, "structure"));
  if (SUSPICIOUS_TLDS.has(tld))
    signals.push(sig(`Suspicious TLD .${tld}`, 15, 0.65, "tld"));
  if (hostname.startsWith("xn--"))
    signals.push(sig("Punycode/IDN homoglyph", 30, 0.85, "tld"));
  if (url.protocol === "data:")
    signals.push(sig("data: URI scheme", 40, 0.95, "tld"));
  if (pathname.split("/").filter(Boolean).length > 6)
    signals.push(sig(`Deep path (${pathname.split("/").filter(Boolean).length} segments)`, 10, 0.55, "structure"));
  if (fullUrl.includes("@") && !url.protocol.startsWith("mailto"))
    signals.push(sig("'@' in URL", 30, 0.90, "structure"));

  // 11. URL shorteners
  const shorteners = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","rebrand.ly","cutt.ly","short.link"];
  if (shorteners.some(s => hostname === s || hostname.endsWith("." + s)))
    signals.push(sig("URL shortener", 15, 0.65, "structure"));

  // 12. Digit-heavy domain
  const digits = (primary.match(/\d/g) || []).length;
  if (primary.length > 6 && digits / primary.length > 0.5)
    signals.push(sig(`High digit ratio (${Math.round(digits/primary.length*100)}%)`, 15, 0.65, "entropy"));

  // 13. Double-dash
  if (hostname.includes("--"))
    signals.push(sig("Double-dash in hostname", 20, 0.70, "structure"));

  return { signals, rawScore: toRaw(signals) };
}

// ── Domain age (RDAP → crt.sh fallback) ─────────────────────────────────────

async function fetchDomainAgeSignals(hostname) {
  const parts = hostname.split(".");
  const tld   = parts[parts.length - 1];
  const apex  = parts.slice(-2).join(".");
  let regDate = null;

  if (RDAP_SERVERS[tld]) {
    try {
      const r = await fetch(`${RDAP_SERVERS[tld]}domain/${apex}`, { signal: AbortSignal.timeout(4000) });
      if (r.ok) {
        const d = await r.json();
        const e = (d.events || []).find(e => e.eventAction === "registration");
        if (e?.eventDate) regDate = new Date(e.eventDate);
      }
    } catch (_) {}
  }

  if (!regDate) {
    try {
      const r = await fetch(`https://crt.sh/?q=${encodeURIComponent(apex)}&output=json`, { signal: AbortSignal.timeout(4000) });
      if (r.ok) {
        const certs = await r.json();
        const dates = (Array.isArray(certs) ? certs : []).map(c => new Date(c.not_before)).filter(d => !isNaN(d));
        if (dates.length) regDate = new Date(Math.min(...dates.map(d => d.getTime())));
      }
    } catch (_) {}
  }

  if (!regDate || isNaN(regDate.getTime())) return [];

  const ageDays = (Date.now() - regDate.getTime()) / 86_400_000;
  if (ageDays < 30)  return [sig(`Domain ${Math.round(ageDays)}d old`,     35, 0.80, "domain_age")];
  if (ageDays < 90)  return [sig(`Domain ${Math.round(ageDays)}d old`,     20, 0.65, "domain_age")];
  if (ageDays > 730) return [sig(`Domain ${Math.round(ageDays/365)}yr old`,-20, 0.70, "domain_age")];
  return [];
}

// ── Threat intelligence (VT · URLScan · GSB) ─────────────────────────────────

async function loadTIKeys() {
  return new Promise(resolve => {
    try { chrome.storage.local.get(["tiKeys"], r => resolve(r?.tiKeys || {})); }
    catch (_) { resolve({}); }
  });
}

async function checkVT(url, key) {
  if (!key) return null;
  try {
    const r = await fetch(`https://www.virustotal.com/api/v3/urls/${btoa(url).replace(/=/g,"")}`,
      { headers: { "x-apikey": key }, signal: AbortSignal.timeout(5000) });
    if (!r.ok) return null;
    const s = (await r.json())?.data?.attributes?.last_analysis_stats || {};
    const total = Object.values(s).reduce((a,b) => a+b, 0);
    return total ? { malicious: s.malicious||0, suspicious: s.suspicious||0, total } : null;
  } catch (_) { return null; }
}

async function checkURLScan(url, key) {
  if (!key) return null;
  try {
    const sub = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: { "API-Key": key, "Content-Type": "application/json" },
      body: JSON.stringify({ url, visibility: "unlisted" }),
      signal: AbortSignal.timeout(5000)
    });
    if (!sub.ok) return null;
    const { uuid } = await sub.json();
    for (let i = 0; i < 4; i++) {
      await new Promise(r => setTimeout(r, 3000));
      const r = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`, { signal: AbortSignal.timeout(5000) });
      if (r.status === 404) continue;
      if (!r.ok) return null;
      const v = (await r.json())?.verdicts?.overall || {};
      return { malicious: v.malicious || false, score: v.score || 0 };
    }
  } catch (_) {}
  return null;
}

async function checkGSB(url, key) {
  if (!key) return null;
  try {
    const r = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "octoplamtree", clientVersion: "2.0" },
        threatInfo: {
          threatTypes: ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      }),
      signal: AbortSignal.timeout(5000)
    });
    if (!r.ok) return null;
    const d = await r.json();
    return { matched: !!(d.matches?.length), types: (d.matches||[]).map(m => m.threatType) };
  } catch (_) { return null; }
}

async function fetchTISignals(urlString) {
  const keys = await loadTIKeys();
  const [vt, us, gsb] = await Promise.allSettled([
    checkVT(urlString, keys.vtApiKey),
    checkURLScan(urlString, keys.urlscanApiKey),
    checkGSB(urlString, keys.gsbApiKey)
  ]);
  const signals = [];
  if (vt.status === "fulfilled" && vt.value) {
    const { malicious, suspicious, total } = vt.value;
    const ratio = (malicious + suspicious) / total;
    if (malicious > 0)   signals.push(sig(`VT: ${malicious}/${total} malicious`, 50, clamp(0.70 + ratio*0.25, 0.70, 0.95), "threat_intel"));
    else if (suspicious) signals.push(sig(`VT: ${suspicious}/${total} suspicious`, 25, 0.75, "threat_intel"));
    else                 signals.push(sig(`VT: clean (${total} engines)`, -15, 0.80, "threat_intel"));
  }
  if (us.status === "fulfilled" && us.value) {
    const { malicious, score } = us.value;
    if (malicious)      signals.push(sig(`URLScan malicious (score ${score})`, 45, 0.90, "threat_intel"));
    else if (score > 50) signals.push(sig(`URLScan elevated score: ${score}`,  20, 0.70, "threat_intel"));
  }
  if (gsb.status === "fulfilled" && gsb.value?.matched)
    signals.push(sig(`GSB: ${gsb.value.types.join(", ")}`, 60, 0.98, "threat_intel"));
  return signals;
}

// ── Redirect chain tracking ──────────────────────────────────────────────────

async function fetchRedirectSignals(urlString) {
  const chain = [];
  let current = urlString;
  for (let i = 0; i < 8; i++) {
    try {
      const r = await fetch(current, { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(3000) });
      chain.push(current);
      if (![301,302,303,307,308].includes(r.status)) break;
      const loc = r.headers.get("location");
      if (!loc) break;
      current = new URL(loc, current).href;
    } catch (_) { break; }
  }
  if (chain.length < 2) return [];

  const signals    = [];
  const originHost = new URL(chain[0]).hostname;
  const finalHost  = new URL(chain[chain.length-1]).hostname;
  const crossDomain = chain.some((u, i) => i > 0 && new URL(u).hostname !== originHost);

  if (chain.length - 1 > 3)
    signals.push(sig(`${chain.length-1} redirect hops`, 15, 0.70, "redirects"));
  if (crossDomain)
    signals.push(sig(`Cross-domain redirect → ${finalHost}`, 20, 0.75, "redirects"));
  if (normalizeScore(toRaw(runSyncChecks(chain[chain.length-1]).signals)) > 40)
    signals.push(sig(`Suspicious redirect destination: ${finalHost}`, 25, 0.80, "redirects"));

  return signals;
}

// ── HTML/JS content analyzer ─────────────────────────────────────────────────

export function analyzeHTMLContent(html, pageUrl = "") {
  if (!html) return [];
  const signals = [];

  // Malicious JS patterns
  let jsWeight = 0; const jsHits = [];
  for (const { pattern, label, weight } of MALICIOUS_JS_PATTERNS) {
    const m = html.match(pattern);
    if (m) { jsWeight += weight * m.length; jsHits.push(`${label}×${m.length}`); }
  }
  if (jsHits.length) signals.push(sig(`Malicious JS: [${jsHits.join(", ")}]`, clamp(jsWeight,0,60), 0.80, "html_js"));

  // Hidden iframes
  const hidden = (html.match(/<iframe[^>]*>/gi)||[])
    .filter(t => /display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*[01]|height\s*:\s*[01]/i.test(t));
  if (hidden.length >= 3) signals.push(sig(`${hidden.length} hidden iframes`, 20, 0.75, "html_js"));
  else if (hidden.length) signals.push(sig(`${hidden.length} hidden iframe`, 10, 0.60, "html_js"));

  // Password on HTTP
  if (/<input[^>]+type\s*=\s*['"]?password/i.test(html) && pageUrl.startsWith("http:"))
    signals.push(sig("Password field on HTTP", 40, 0.95, "html_js"));

  // Cross-domain form action
  if (/<input[^>]+type\s*=\s*['"]?password/i.test(html)) {
    for (const [, action] of html.matchAll(/action\s*=\s*['"]([^'"]+)['"]/gi)) {
      try {
        const ah = new URL(action, pageUrl).hostname;
        const ph = pageUrl ? new URL(pageUrl).hostname : "";
        if (ph && ah && ah !== ph) signals.push(sig(`Form posts to external: ${ah}`, 35, 0.90, "html_js"));
      } catch (_) {}
    }
  }

  // External script domain count
  const scriptHosts = new Set([...html.matchAll(/<script[^>]+src\s*=\s*['"]([^'"]+)['"]/gi)]
    .map(([,s]) => { try { return new URL(s, pageUrl).hostname; } catch (_) { return null; } }).filter(Boolean));
  if (scriptHosts.size > 10)
    signals.push(sig(`Scripts from ${scriptHosts.size} domains`, 15, 0.60, "html_js"));

  // Meta refresh
  if (/<meta[^>]+http-equiv\s*=\s*['"]refresh['"]/i.test(html))
    signals.push(sig("Meta-refresh redirect", 15, 0.65, "html_js"));

  // Favicon brand mismatch
  const faviconMatch = html.match(/<link[^>]+(?:rel\s*=\s*['"](?:shortcut )?icon['"][^>]*href\s*=\s*['"]([^'"]+)['"]|href\s*=\s*['"]([^'"]+)['"][^>]*rel\s*=\s*['"](?:shortcut )?icon['"])/i);
  if (faviconMatch) {
    const fsrc = faviconMatch[1] || faviconMatch[2];
    for (const brand of TARGET_BRANDS) {
      if (fsrc.toLowerCase().includes(brand)) {
        try {
          const fh = new URL(fsrc, pageUrl).hostname;
          const ph = pageUrl ? new URL(pageUrl).hostname : "";
          if (ph && !ph.includes(brand)) { signals.push(sig(`Favicon impersonates '${brand}'`, 30, 0.80, "html_js")); break; }
        } catch (_) {}
      }
    }
  }

  return signals;
}

// ── Public API ────────────────────────────────────────────────────────────────

export function analyzeURL(urlString) {
  try {
    const { signals, rawScore, internal, error } = runSyncChecks(urlString);
    if (error)    return { isSuspicious: false, score: 0, reason: error };
    if (internal) return { isSuspicious: false, score: 0, reason: "" };
    return buildResult(signals, rawScore, urlString);
  } catch (e) {
    return { isSuspicious: false, score: 0, reason: "Error: " + e.message };
  }
}

export async function analyzeURLAsync(urlString, options = {}) {
  try {
    const { signals: sync, rawScore, internal, error } = runSyncChecks(urlString);
    if (error)    return { isSuspicious: false, score: 0, reason: error };
    if (internal) return { isSuspicious: false, score: 0, reason: "" };

    const htmlSignals = options.htmlContent
      ? analyzeHTMLContent(options.htmlContent, options.pageUrl || urlString) : [];

    const [domainAgeSignals, tiSignals, redirectSignals] = await Promise.all([
      options.skipDomainAge   ? [] : fetchDomainAgeSignals(new URL(urlString).hostname),
      options.skipThreatIntel ? [] : fetchTISignals(urlString),
      options.skipRedirects   ? [] : fetchRedirectSignals(urlString)
    ]);

    const all = [...sync, ...htmlSignals, ...domainAgeSignals, ...tiSignals, ...redirectSignals];
    return buildResult(all, toRaw(all), urlString, { enriched: true, domainAgeSignals, tiSignals, redirectSignals, htmlSignals });
  } catch (e) {
    return { ...analyzeURL(urlString), enriched: false, asyncError: e.message };
  }
}