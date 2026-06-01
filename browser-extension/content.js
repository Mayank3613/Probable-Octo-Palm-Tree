// Probable-Octo-Palm-Tree Content Script
// Orchestrates DOM scanning, hooks MAIN world APIs, and reports to Background

(function() {
  // Trusted domains — skip DOM scanning entirely on these to save CPU
  const TRUSTED_SCAN_DOMAINS = [
    "google.com", "youtube.com", "gmail.com", "googleapis.com",
    "microsoft.com", "live.com", "outlook.com", "office.com", "bing.com",
    "github.com", "linkedin.com", "apple.com", "icloud.com",
    "facebook.com", "instagram.com", "whatsapp.com", "meta.com",
    "amazon.com", "amazonaws.com", "twitter.com", "x.com",
    "netflix.com", "paypal.com", "yahoo.com", "reddit.com",
    "discord.com", "spotify.com", "dropbox.com", "zoom.us",
    "wikipedia.org", "stackoverflow.com", "steampowered.com"
  ];

  function isOnTrustedDomain() {
    const hostname = window.location.hostname.toLowerCase();
    return TRUSTED_SCAN_DOMAINS.some(d => hostname === d || hostname.endsWith("." + d));
  }

  const onTrustedDomain = isOnTrustedDomain();

  // 1. Inject the page-level API hook script (inject.js) into the MAIN world
  function injectMainWorldScript() {
    try {
      const script = document.createElement("script");
      script.src = chrome.runtime.getURL("inject.js");
      script.onload = function() {
        this.remove();
      };
      (document.head || document.documentElement).appendChild(script);
    } catch (e) {
      console.debug("[Probable-Octo-Palm-Tree] Failed to inject main world hook:", e);
    }
  }

  injectMainWorldScript();

  // 2. Listen for security events from the MAIN world hook (inject.js)
  window.addEventListener("OctoSecurityEvent", function(event) {
    const { action, payload } = event.detail || {};

    if (action === "log_connection") {
      // Route connection logs through the Logger module
      if (window.OctoLogger) {
        window.OctoLogger.logConnection(payload.type, payload.url, payload.method);
      }
    } else if (action === "cookie_access") {
      // JWT scanning hook — if a cookie access event contains a JWT, scan it
      if (window.OctoSessionMonitor && payload.value) {
        window.OctoSessionMonitor.scanJWT(payload.value, "cookie_event");
      }
    }
  });

  // 3. DOM + Script threat scanning
  function runFullScan() {
    if (!window.OctoThreatDetector || !window.OctoLogger) return;

    try {
      const alerts = window.OctoThreatDetector.runScan();
      alerts.forEach(alert => {
        window.OctoLogger.log(alert.type, alert.details, alert.severity);
      });
    } catch (e) {
      console.debug("[Probable-Octo-Palm-Tree] Scan error:", e);
    }
  }

  // Only run DOM scanning on untrusted domains — saves CPU on Google, YouTube, etc.
  if (!onTrustedDomain) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => {
        runFullScan();
        setTimeout(runFullScan, 2500);
      });
    } else {
      runFullScan();
      setTimeout(runFullScan, 2500);
    }

    window.addEventListener("load", () => {
      setTimeout(runFullScan, 1000);
    });

    // Periodic scan only on untrusted domains, every 30s (MutationObserver handles real-time)
    setInterval(runFullScan, 30000);
  }
})();
