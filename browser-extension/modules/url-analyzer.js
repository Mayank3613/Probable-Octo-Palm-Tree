// OctoPlamTree URL Analyzer Module (ES6 module used by background.js)
// Comprehensive URL threat scoring engine with trusted domain whitelist

// ============================================================
// TRUSTED DOMAINS — Never flag these as suspicious
// ============================================================
const TRUSTED_DOMAINS = new Set([
  // Google ecosystem
  "google.com", "google.co.in", "google.co.uk", "google.co.jp", "google.de",
  "google.fr", "google.com.br", "google.ca", "google.com.au",
  "googleapis.com", "googleusercontent.com", "googlevideo.com",
  "googleadservices.com", "googletagmanager.com", "googlesyndication.com",
  "gstatic.com", "gvt1.com", "gvt2.com",
  "youtube.com", "youtu.be", "ytimg.com", "yt.be",
  "gmail.com", "accounts.google.com",
  "android.com", "chromium.org", "chrome.google.com",
  "blogger.com", "blogspot.com",
  "firebase.google.com", "firebaseio.com",
  "withgoogle.com", "google.org",

  // Microsoft ecosystem
  "microsoft.com", "microsoftonline.com", "live.com", "outlook.com",
  "office.com", "office365.com", "windows.com", "windowsupdate.com",
  "msn.com", "bing.com", "azure.com", "azurewebsites.net",
  "sharepoint.com", "onedrive.com", "onenote.com",
  "skype.com", "teams.microsoft.com",
  "visualstudio.com", "github.com", "github.io", "githubusercontent.com",
  "linkedin.com", "linkedin-ei.com",

  // Apple ecosystem
  "apple.com", "icloud.com", "icloud-content.com", "mzstatic.com",
  "apple-dns.net", "cdn-apple.com", "itunes.apple.com",

  // Meta / Facebook
  "facebook.com", "fb.com", "fbcdn.net", "instagram.com",
  "whatsapp.com", "whatsapp.net", "messenger.com",
  "meta.com", "oculus.com",

  // Amazon ecosystem
  "amazon.com", "amazon.co.uk", "amazon.in", "amazon.de", "amazon.co.jp",
  "amazonaws.com", "amazonws.com", "cloudfront.net",
  "primevideo.com", "twitch.tv",

  // Other major platforms
  "twitter.com", "x.com", "twimg.com",
  "netflix.com", "nflxvideo.net", "nflxext.com",
  "paypal.com", "paypalobjects.com",
  "yahoo.com", "yahoo.co.jp", "yimg.com",
  "reddit.com", "redd.it", "redditstatic.com",
  "wikipedia.org", "wikimedia.org",
  "stackoverflow.com", "stackexchange.com",
  "discord.com", "discordapp.com", "discord.gg",
  "telegram.org", "t.me",
  "zoom.us", "zoomgov.com",
  "spotify.com", "scdn.co",
  "dropbox.com", "dropboxusercontent.com",
  "steam-chat.com", "steamcommunity.com", "steampowered.com", "steamstatic.com",

  // Banking / Finance (major)
  "chase.com", "bankofamerica.com", "wellsfargo.com",
  "citibank.com", "capitalone.com", "usbank.com",
  "coinbase.com", "binance.com", "kraken.com",

  // CDNs & Infrastructure
  "cloudflare.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
  "unpkg.com", "fastly.net", "akamaihd.net", "akamai.net",
  "bootstrapcdn.com", "fontawesome.com",

  // Dev tools
  "npmjs.com", "pypi.org", "crates.io",
  "vercel.app", "netlify.app", "pages.dev",
  "heroku.com", "render.com",
  "codepen.io", "jsfiddle.net", "replit.com"
]);

// ============================================================
// SUSPICIOUS KEYWORDS — only flag on NON-trusted domains
// ============================================================
const SUSPICIOUS_WORDS = [
  "update-password", "banking", "credential", "reset-pass",
  "billing-update", "suspended", "unusual-activity",
  "paymentupdate", "helpdesk", "support-portal"
];

// Keywords that are ONLY suspicious in the DOMAIN part (not paths)
// "login", "verify", "signin", "accounts" are normal in paths of trusted sites
const DOMAIN_ONLY_SUSPICIOUS = [
  "login", "verify", "signin", "accounts", "secure",
  "verification", "confirm", "restore", "unlock",
  "authenticate", "recovery", "wallet"
];

const TARGET_BRANDS = [
  "google", "paypal", "microsoft", "apple", "netflix", "amazon",
  "facebook", "github", "chase", "bankofamerica", "wellsfargo",
  "binance", "coinbase", "instagram", "twitter", "linkedin",
  "dropbox", "icloud", "outlook", "yahoo", "steam", "discord",
  "whatsapp", "telegram"
];

// Official TLDs for each brand (extended)
const BRAND_OFFICIAL_TLDS = {
  "google": ["com", "org", "co.in", "co.uk", "co.jp", "de", "fr", "com.br", "ca", "com.au"],
  "youtube": ["com"],
  "microsoft": ["com"],
  "apple": ["com"],
  "amazon": ["com", "co.uk", "in", "de", "co.jp", "com.br", "com.au"],
  "facebook": ["com"],
  "instagram": ["com"],
  "twitter": ["com"],
  "linkedin": ["com"],
  "paypal": ["com"],
  "netflix": ["com"],
  "github": ["com", "io"],
  "discord": ["com", "gg"],
  "steam": ["com"],
  "chase": ["com"],
  "bankofamerica": ["com"],
  "wellsfargo": ["com"],
  "binance": ["com"],
  "coinbase": ["com"],
  "dropbox": ["com"],
  "icloud": ["com"],
  "outlook": ["com"],
  "yahoo": ["com", "co.jp"],
  "whatsapp": ["com", "net"],
  "telegram": ["org"]
};

// ============================================================
// HELPER FUNCTIONS
// ============================================================

function getLevenshteinDistance(a, b) {
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Check if hostname belongs to a trusted domain
function isTrustedDomain(hostname) {
  // Direct match
  if (TRUSTED_DOMAINS.has(hostname)) return true;
  // Subdomain match: check if hostname ends with .trustedDomain
  for (const trusted of TRUSTED_DOMAINS) {
    if (hostname.endsWith("." + trusted)) return true;
  }
  return false;
}

// Check if hostname is an official brand domain
function isOfficialBrandDomain(hostname, brand) {
  const tlds = BRAND_OFFICIAL_TLDS[brand] || ["com"];
  for (const tld of tlds) {
    if (hostname === `${brand}.${tld}` || hostname.endsWith(`.${brand}.${tld}`)) {
      return true;
    }
  }
  // Also check if it's a subdomain like www.brand.com
  if (hostname === `www.${brand}.com` || hostname.endsWith(`.${brand}.com`)) {
    return true;
  }
  return false;
}

// ============================================================
// MAIN ANALYSIS FUNCTION
// ============================================================

export function analyzeURL(urlString) {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname.toLowerCase();
    const pathname = url.pathname.toLowerCase();
    const fullUrl = url.href.toLowerCase();

    // Skip browser-internal URLs
    if (hostname === "localhost" || hostname === "127.0.0.1" ||
        url.protocol === "chrome-extension:" || url.protocol === "chrome:" ||
        url.protocol === "about:" || url.protocol === "moz-extension:" ||
        url.protocol === "edge:") {
      return { isSuspicious: false, score: 0, reason: "" };
    }

    // WHITELIST CHECK: If the domain is trusted, skip all heuristics
    if (isTrustedDomain(hostname)) {
      return { isSuspicious: false, score: 0, reason: "" };
    }

    let score = 0;
    let reasons = [];
    const domainParts = hostname.split('.');
    const primaryDomain = domainParts.length >= 2 ? domainParts[domainParts.length - 2] : hostname;
    const tld = domainParts.length >= 2 ? domainParts[domainParts.length - 1] : "";

    // ---- 1. Suspicious keywords in DOMAIN (high confidence) ----
    SUSPICIOUS_WORDS.forEach(word => {
      if (hostname.includes(word)) {
        score += 30;
        reasons.push(`Suspicious keyword '${word}' in domain`);
      }
    });

    // Domain-only keywords (don't flag in paths — sites like Google use /accounts, /signin, /verify)
    DOMAIN_ONLY_SUSPICIOUS.forEach(word => {
      if (hostname.includes(word)) {
        score += 25;
        reasons.push(`Suspicious keyword '${word}' in domain name`);
      }
    });

    // Path keywords — only the high-confidence ones
    SUSPICIOUS_WORDS.forEach(word => {
      if (pathname.includes(word)) {
        score += 10;
        reasons.push(`Suspicious keyword '${word}' in path`);
      }
    });

    // ---- 2. Brand typosquatting ----
    TARGET_BRANDS.forEach(brand => {
      if (hostname.includes(brand)) {
        if (!isOfficialBrandDomain(hostname, brand)) {
          score += 50;
          reasons.push(`Potential brand impersonation targeting '${brand}'`);
        }
      } else {
        const distance = getLevenshteinDistance(primaryDomain, brand);
        if (distance === 1) {
          score += 50;
          reasons.push(`Typosquatting targeting '${brand}' (Levenshtein distance: 1)`);
        } else if (distance === 2 && primaryDomain.length >= 5) {
          score += 30;
          reasons.push(`Possible typosquatting targeting '${brand}' (distance: 2)`);
        }
      }
    });

    // ---- 3. Domain entropy (DGA detection) ----
    const domainWithoutTLD = domainParts.slice(0, -1).join('.');
    const entropy = calculateEntropy(domainWithoutTLD);
    if (entropy > 4.2 && domainWithoutTLD.length > 12) {
      score += 20;
      reasons.push(`High domain entropy (${entropy.toFixed(2)}) — possible DGA domain`);
    }

    // ---- 4. Excessive subdomains ----
    const subdomainCount = domainParts.length - 2;
    if (subdomainCount > 4) {
      score += 20;
      reasons.push(`${subdomainCount} subdomains detected (DNS tunnel / phishing indicator)`);
    }

    // ---- 5. Raw IP address hostname ----
    if (/^[0-9.]+$/.test(hostname) || /^\[.*\]$/.test(hostname)) {
      score += 25;
      reasons.push("Hostname is a raw IP address");
    }

    // ---- 6. Suspicious TLDs ----
    const suspiciousTLDs = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "club", "work", "icu", "cam", "rest"];
    if (suspiciousTLDs.includes(tld)) {
      score += 15;
      reasons.push(`Suspicious TLD '.${tld}' often used in phishing`);
    }

    // ---- 7. Punycode / IDN homoglyph ----
    if (hostname.startsWith("xn--") || domainParts.some(p => p.startsWith("xn--"))) {
      score += 30;
      reasons.push("Punycode/IDN domain — possible homoglyph attack");
    }

    // ---- 8. Data URI ----
    if (url.protocol === "data:") {
      score += 40;
      reasons.push("Data URI scheme — common phishing vector");
    }

    // ---- 9. Excessive path depth ----
    const pathSegments = pathname.split('/').filter(s => s.length > 0);
    if (pathSegments.length > 7) {
      score += 10;
      reasons.push(`Deep URL path (${pathSegments.length} segments)`);
    }

    // ---- 10. @ sign in URL ----
    if (fullUrl.includes("@") && !url.protocol.startsWith("mailto")) {
      score += 30;
      reasons.push("URL contains '@' — possible URL obfuscation");
    }

    const finalScore = Math.min(score, 100);

    return {
      isSuspicious: finalScore >= 35,
      score: finalScore,
      reason: reasons.join("; ")
    };
  } catch (e) {
    return { isSuspicious: false, score: 0, reason: "Invalid URL format" };
  }
}
