// OctoPlamTree URL Analyzer Module (ES6 module used by background.js)
// Comprehensive URL threat scoring engine

const SUSPICIOUS_WORDS = [
  "login", "verify", "secure", "update-password", "banking",
  "signin", "accounts", "wallet", "credential", "reset-pass",
  "verification", "support-portal", "billing-update", "confirm",
  "suspended", "alert", "unusual-activity", "restore", "unlock",
  "authenticate", "recovery", "helpdesk", "paymentupdate"
];

const TARGET_BRANDS = [
  "google", "paypal", "microsoft", "apple", "netflix", "amazon",
  "facebook", "github", "chase", "bankofamerica", "wellsfargo",
  "binance", "coinbase", "instagram", "twitter", "linkedin",
  "dropbox", "icloud", "outlook", "yahoo", "steam", "discord",
  "whatsapp", "telegram"
];

// Levenshtein distance for typosquatting detection
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

// Shannon entropy calculation — high entropy = randomized/DGA domain
function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function analyzeURL(urlString) {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname.toLowerCase();
    const pathname = url.pathname.toLowerCase();
    const fullUrl = url.href.toLowerCase();

    // Skip safe/internal URLs
    if (hostname === "localhost" || hostname === "127.0.0.1" ||
        url.protocol === "chrome-extension:" || url.protocol === "chrome:" ||
        url.protocol === "about:" || url.protocol === "moz-extension:") {
      return { isSuspicious: false, score: 0, reason: "" };
    }

    let score = 0;
    let reasons = [];

    // ---- 1. Phishing keyword checks ----
    SUSPICIOUS_WORDS.forEach(word => {
      if (hostname.includes(word)) {
        score += 30;
        reasons.push(`Suspicious keyword '${word}' in domain`);
      } else if (pathname.includes(word)) {
        score += 12;
        reasons.push(`Suspicious keyword '${word}' in path`);
      }
    });

    // ---- 2. Brand typosquatting ----
    const domainParts = hostname.split('.');
    const primaryDomain = domainParts.length >= 2 ? domainParts[domainParts.length - 2] : hostname;

    TARGET_BRANDS.forEach(brand => {
      if (hostname.includes(brand)) {
        const isOfficial = hostname === `${brand}.com` ||
                           hostname.endsWith(`.${brand}.com`) ||
                           hostname === `${brand}.org` ||
                           hostname.endsWith(`.${brand}.org`) ||
                           hostname === `${brand}.net` ||
                           hostname.endsWith(`.${brand}.net`) ||
                           hostname === `${brand}.io` ||
                           hostname.endsWith(`.${brand}.io`) ||
                           hostname === `www.${brand}.com`;
        if (!isOfficial) {
          score += 50;
          reasons.push(`Potential brand impersonation targeting '${brand}'`);
        }
      } else {
        const distance = getLevenshteinDistance(primaryDomain, brand);
        if (distance === 1) {
          score += 50;
          reasons.push(`Subtle typosquatting targeting '${brand}' (distance: 1)`);
        } else if (distance === 2 && primaryDomain.length >= 5) {
          score += 35;
          reasons.push(`Possible typosquatting targeting '${brand}' (distance: 2)`);
        }
      }
    });

    // ---- 3. Domain entropy analysis (DGA detection) ----
    const domainWithoutTLD = domainParts.slice(0, -1).join('.');
    const entropy = calculateEntropy(domainWithoutTLD);
    if (entropy > 4.0 && domainWithoutTLD.length > 10) {
      score += 25;
      reasons.push(`High domain entropy (${entropy.toFixed(2)}) — possible DGA/randomized domain`);
    }

    // ---- 4. Excessive subdomains ----
    const subdomainCount = domainParts.length - 2;
    if (subdomainCount > 3) {
      score += 20;
      reasons.push(`${subdomainCount} subdomains detected (phishing routing / DNS tunnel indicator)`);
    }

    // ---- 5. Raw IP address hostname ----
    if (/^[0-9.]+$/.test(hostname) || /^\[.*\]$/.test(hostname)) {
      score += 25;
      reasons.push("Hostname is a raw IP address");
    }

    // ---- 6. Non-standard TLDs often abused ----
    const suspiciousTLDs = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "club", "work", "icu", "cam", "rest"];
    const tld = domainParts.length >= 2 ? domainParts[domainParts.length - 1] : "";
    if (suspiciousTLDs.includes(tld)) {
      score += 15;
      reasons.push(`Suspicious TLD '.${tld}' frequently used in phishing campaigns`);
    }

    // ---- 7. Punycode / IDN homoglyph attacks ----
    if (hostname.startsWith("xn--")) {
      score += 30;
      reasons.push("Punycode/IDN domain detected — possible homoglyph attack");
    }

    // ---- 8. Data URI scheme detection ----
    if (url.protocol === "data:") {
      score += 40;
      reasons.push("Data URI scheme used — common phishing vector to embed pages inline");
    }

    // ---- 9. Excessive path depth ----
    const pathSegments = pathname.split('/').filter(s => s.length > 0);
    if (pathSegments.length > 6) {
      score += 10;
      reasons.push(`Deep URL path (${pathSegments.length} segments) — potential redirect obfuscation`);
    }

    // ---- 10. At-sign in URL (credential harvesting trick) ----
    if (fullUrl.includes("@") && !url.protocol.startsWith("mailto")) {
      score += 30;
      reasons.push("URL contains '@' character — possible credential harvesting or URL obfuscation");
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
