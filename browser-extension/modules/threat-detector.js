// Probable-Octo-Palm-Tree Threat Detector Module (runs in Content Script scope)
// Real-time DOM threat scanner with MutationObserver support

(function() {
  // Track already-reported threats to prevent duplicates
  const reportedThreats = new Set();

  // Trusted domains — skip fake login form and sensitive DOM checks on these
  const TRUSTED_ROOT_DOMAINS = new Set([
    "google.com", "google.co.in", "google.co.uk", "google.co.jp",
    "youtube.com", "gmail.com", "googleapis.com",
    "microsoft.com", "live.com", "outlook.com", "office.com",
    "microsoftonline.com", "bing.com", "azure.com",
    "github.com", "linkedin.com",
    "apple.com", "icloud.com",
    "facebook.com", "instagram.com", "whatsapp.com", "meta.com",
    "amazon.com", "amazonaws.com",
    "twitter.com", "x.com",
    "netflix.com", "paypal.com", "yahoo.com",
    "reddit.com", "wikipedia.org", "stackoverflow.com",
    "discord.com", "telegram.org", "zoom.us",
    "spotify.com", "dropbox.com",
    "steam-chat.com", "steampowered.com", "steamcommunity.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com",
    "coinbase.com", "binance.com",
    "cloudflare.com", "fastly.net", "akamai.net"
  ]);

  function getRootDomain(hostname) {
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    // Handle two-part TLDs like co.uk, co.in, co.jp, com.au, com.br
    const twoPartTLDs = ["co.uk", "co.in", "co.jp", "com.au", "com.br", "co.nz", "org.uk"];
    const lastTwo = parts.slice(-2).join('.');
    if (twoPartTLDs.includes(lastTwo)) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  function isOnTrustedDomain() {
    const root = getRootDomain(window.location.hostname);
    return TRUSTED_ROOT_DOMAINS.has(root);
  }

  function areSameOrganization(host1, host2) {
    return getRootDomain(host1) === getRootDomain(host2);
  }

  function hashThreat(type, detail) {
    return `${type}::${detail.substring(0, 80)}`;
  }

  const ThreatDetector = {

    // ---- 1. Script Analysis ----
    scanScripts: function() {
      const scripts = document.getElementsByTagName("script");
      const results = [];

      for (let script of scripts) {
        const content = script.innerHTML;
        const src = script.getAttribute("src") || "";

        // Cryptominer signatures
        const minerKeywords = [
          "coinhive", "cryptoloot", "deepminer", "jsecoin", "webminerPool",
          "CoinHive.Anonymous", "wmp.sandbox", "miner.start", "cryptonight"
        ];
        const hasMiner = minerKeywords.some(kw =>
          src.toLowerCase().includes(kw.toLowerCase()) || content.includes(kw)
        );
        if (hasMiner) {
          results.push({
            type: "Cryptominer Script",
            details: `Detected miner script signature: ${src || "Inline Script"}`,
            severity: "critical"
          });
        }

        // Obfuscated/malicious large scripts
        if (content.length > 8000) {
          const suspiciousCalls = [
            "eval", "unescape", "String.fromCharCode", "atob",
            "document.write", "Function(", "setTimeout(atob", "decodeURIComponent"
          ].filter(term => content.includes(term));

          if (suspiciousCalls.length >= 2) {
            results.push({
              type: "Obfuscated Javascript",
              details: `Large script (${content.length} chars) using dynamic execution: [${suspiciousCalls.join(", ")}]`,
              severity: "high"
            });
          }
        }

        // External script from suspicious TLD
        if (src) {
          try {
            const scriptUrl = new URL(src, window.location.href);
            const host = scriptUrl.hostname;
            const suspiciousTLDs = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz"];
            const tld = host.split('.').pop();
            if (suspiciousTLDs.includes(tld)) {
              results.push({
                type: "Suspicious External Script",
                details: `Script loaded from suspicious TLD: ${src}`,
                severity: "medium"
              });
            }
          } catch (e) { /* ignore invalid URLs */ }
        }
      }

      return results;
    },

    // ---- 2. Hidden Iframe Detection ----
    scanIframes: function() {
      const iframes = document.getElementsByTagName("iframe");
      const results = [];
      let hiddenCount = 0;
      const hiddenSources = [];

      for (let iframe of iframes) {
        const style = window.getComputedStyle(iframe);
        const isHidden =
          style.display === "none" ||
          style.visibility === "hidden" ||
          parseFloat(style.opacity) === 0 ||
          iframe.offsetWidth <= 2 ||
          iframe.offsetHeight <= 2 ||
          parseInt(style.left) < -500 ||
          parseInt(style.top) < -500;

        if (isHidden) {
          hiddenCount++;
          hiddenSources.push(iframe.src || "about:blank");
        }
      }

      if (hiddenCount >= 3) {
        results.push({
          type: "Excessive Hidden Iframes",
          details: `${hiddenCount} invisible iframes found (drive-by exploit/clickjacking vector). Sources: ${hiddenSources.slice(0, 3).join(", ")}`,
          severity: "high"
        });
      } else if (hiddenCount >= 1) {
        results.push({
          type: "Hidden Iframe Detected",
          details: `${hiddenCount} invisible iframe(s) found: ${hiddenSources.join(", ")}`,
          severity: "medium"
        });
      }

      return results;
    },

    // ---- 3. Clickjacking Overlay Detection ----
    scanOverlays: function() {
      const results = [];
      const allElements = document.querySelectorAll("div, section, aside, span");

      for (let el of allElements) {
        const style = window.getComputedStyle(el);

        if ((style.position === "fixed" || style.position === "absolute") &&
            parseInt(style.zIndex) > 5000 &&
            parseFloat(style.opacity) < 0.3 &&
            parseFloat(style.opacity) > 0.0) {

          const rect = el.getBoundingClientRect();
          const screenArea = window.innerWidth * window.innerHeight;
          const overlayArea = rect.width * rect.height;

          if (overlayArea > screenArea * 0.6) {
            results.push({
              type: "Clickjacking Overlay",
              details: `Semi-transparent layer spanning ${Math.round((overlayArea / screenArea) * 100)}% of viewport (z-index: ${style.zIndex}, opacity: ${style.opacity})`,
              severity: "high"
            });
            break;
          }
        }
      }

      return results;
    },

    // ---- 4. Fake Login Form Detection ----
    scanFakeLoginForms: function() {
      const results = [];

      // SKIP on trusted domains — Google, YouTube, Gmail, etc. all have legitimate login forms
      if (isOnTrustedDomain()) return results;

      const forms = document.querySelectorAll("form");
      const passwordInputs = document.querySelectorAll('input[type="password"]');

      if (passwordInputs.length === 0) return results;

      // Check if this page is NOT served over HTTPS
      if (window.location.protocol === "http:") {
        results.push({
          type: "Insecure Login Form",
          details: `Password field detected on non-HTTPS page (${window.location.hostname}). Credentials will be transmitted in cleartext.`,
          severity: "critical"
        });
      }

      // Check if form submits to a DIFFERENT organization's domain (credential exfiltration)
      for (let form of forms) {
        const action = form.getAttribute("action");
        if (!action) continue;

        try {
          const actionUrl = new URL(action, window.location.href);
          // Compare root domains — accounts.google.com submitting to google.com is fine
          if (!areSameOrganization(actionUrl.hostname, window.location.hostname)) {
            const hasPassword = form.querySelector('input[type="password"]');
            if (hasPassword) {
              results.push({
                type: "Credential Exfiltration Form",
                details: `Login form submits credentials to external domain: ${actionUrl.hostname} (current: ${window.location.hostname})`,
                severity: "critical"
              });
            }
          }
        } catch (e) { /* ignore malformed action URLs */ }
      }

      // Check for suspicious form on phishing TLD
      if (passwordInputs.length > 0 && forms.length > 0) {
        const emailInputs = document.querySelectorAll('input[type="email"], input[name*="email"], input[name*="user"], input[placeholder*="email"], input[placeholder*="Email"]');
        if (emailInputs.length > 0) {
          const hostname = window.location.hostname;
          const suspiciousTLDs = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "club", "icu"];
          const tld = hostname.split('.').pop();
          if (suspiciousTLDs.includes(tld)) {
            results.push({
              type: "Phishing Login Page",
              details: `Login form with email + password fields found on suspicious TLD (.${tld})`,
              severity: "critical"
            });
          }
        }
      }

      return results;
    },

    // ---- 5. Suspicious document.write usage ----
    scanDocumentWrite: function() {
      const results = [];
      const scripts = document.getElementsByTagName("script");
      for (let script of scripts) {
        const content = script.innerHTML;
        if (content.includes("document.write") && content.length > 500) {
          results.push({
            type: "Dynamic Page Rewrite",
            details: `Script uses document.write() to dynamically rewrite page content (${content.length} chars)`,
            severity: "medium"
          });
        }
      }
      return results;
    },

    // Aggregate all scans
    runScan: function() {
      const alerts = [
        ...this.scanScripts(),
        ...this.scanIframes(),
        ...this.scanOverlays(),
        ...this.scanFakeLoginForms(),
        ...this.scanDocumentWrite()
      ];

      // Deduplicate: only return alerts not already reported
      const newAlerts = alerts.filter(a => {
        const key = hashThreat(a.type, a.details);
        if (reportedThreats.has(key)) return false;
        reportedThreats.add(key);
        return true;
      });

      return newAlerts;
    }
  };

  // ---- MutationObserver: Real-time DOM change monitoring ----
  function setupMutationObserver() {
    const observer = new MutationObserver((mutations) => {
      let shouldScan = false;

      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;
          const tag = node.tagName ? node.tagName.toLowerCase() : "";
          // Trigger scan if new script, iframe, form, or input[type=password] is injected
          if (tag === "script" || tag === "iframe" || tag === "form" ||
              tag === "object" || tag === "embed" ||
              (tag === "input" && node.type === "password")) {
            shouldScan = true;
            break;
          }
          // Also check descendants
          if (node.querySelector && node.querySelector("script, iframe, form, input[type='password'], object, embed")) {
            shouldScan = true;
            break;
          }
        }
        if (shouldScan) break;
      }

      if (shouldScan && window.OctoLogger) {
        try {
          const alerts = ThreatDetector.runScan();
          alerts.forEach(alert => {
            window.OctoLogger.log(alert.type, alert.details, alert.severity);
          });
        } catch (e) {
          console.debug("MutationObserver scan error:", e);
        }
      }
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }

  // Start MutationObserver once DOM is available
  if (document.documentElement) {
    setupMutationObserver();
  } else {
    document.addEventListener("DOMContentLoaded", setupMutationObserver);
  }

  // Expose to content script scope
  window.OctoThreatDetector = ThreatDetector;
})();
