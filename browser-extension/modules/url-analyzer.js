// OctoPlamTree URL Analyzer Module (ES6 module used by background.js)

const SUSPICIOUS_WORDS = [
  "login",
  "verify",
  "secure",
  "update-password",
  "banking",
  "signin",
  "accounts",
  "wallet",
  "credential",
  "reset-pass",
  "verification",
  "support-portal",
  "billing-update"
];

const TARGET_BRANDS = [
  "google",
  "paypal",
  "microsoft",
  "apple",
  "netflix",
  "amazon",
  "facebook",
  "github",
  "chase",
  "bankofamerica",
  "wellsfargo",
  "binance",
  "coinbase"
];

// Helper to calculate Levenshtein distance for typosquatting detection
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
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

export function analyzeURL(urlString) {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname.toLowerCase();
    const pathname = url.pathname.toLowerCase();

    // Skip localhost and extension pages
    if (hostname === "localhost" || hostname === "127.0.0.1" || url.protocol === "chrome-extension:") {
      return { isSuspicious: false, score: 0, reason: "" };
    }

    let score = 0;
    let reasons = [];

    // 1. Phishing Keyword checks in domain & path
    SUSPICIOUS_WORDS.forEach(word => {
      if (hostname.includes(word)) {
        score += 35;
        reasons.push(`Suspicious keyword '${word}' in domain name`);
      } else if (pathname.includes(word)) {
        score += 15;
        reasons.push(`Suspicious keyword '${word}' in URL path`);
      }
    });

    // 2. Typosquatting checks (brand hijacking)
    TARGET_BRANDS.forEach(brand => {
      // If it contains the brand name but isn't the official brand domain
      // e.g. "paypal-security.com" or "login-microsoft.com"
      const domainParts = hostname.split('.');
      const primaryDomain = domainParts.length >= 2 ? domainParts[domainParts.length - 2] : hostname;

      if (hostname.includes(brand)) {
        // Check if it's the official brand domain (e.g. brand.com, brand.co.uk)
        const isOfficial = hostname.endsWith(`.${brand}.com`) || 
                           hostname === `${brand}.com` || 
                           hostname.endsWith(`.${brand}.org`) ||
                           hostname === `${brand}.org` ||
                           hostname.endsWith(`.${brand}.net`) ||
                           hostname === `${brand}.net`;

        if (!isOfficial) {
          score += 50;
          reasons.push(`Potential brand typosquatting targeting '${brand}'`);
        }
      } else {
        // Check Levenshtein distance on primary domain to spot subtle typos
        // e.g., "paypa1.com" or "g00gle.com"
        const distance = getLevenshteinDistance(primaryDomain, brand);
        if (distance === 1 || distance === 2) {
          score += 45;
          reasons.push(`Subtle typosquatting detected targeting brand '${brand}' (distance: ${distance})`);
        }
      }
    });

    // 3. Technical indicators of suspicious domain
    // Look for too many subdomains (e.g., bank.login.secure.update.domain.com)
    const dotsCount = (hostname.match(/\./g) || []).length;
    if (dotsCount > 4) {
      score += 20;
      reasons.push("Excessive subdomains in hostname (potential DNS tunnel / phishing routing)");
    }

    // Look for IP hostname (except localhost)
    const isIP = /^[0-9.]+$/.test(hostname);
    if (isIP) {
      score += 25;
      reasons.push("Hostname is a raw IP address");
    }

    // Limit score to 100
    const finalScore = Math.min(score, 100);

    return {
      isSuspicious: finalScore >= 40,
      score: finalScore,
      reason: reasons.join(", ")
    };
  } catch (e) {
    return { isSuspicious: false, score: 0, reason: "Invalid URL format" };
  }
}
