// Probable-Octo-Palm-Tree Content Script
// Orchestrates DOM scanning, hooks MAIN world APIs, and reports to Background.
// v2.1: SPA-aware — detects navigations via History API patches in inject.js,
//        popstate, and hashchange; triggers re-scans on each virtual page load.

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
      const { type, url, method, body } = payload || {};
      
      // Run threat analyses in content script context
      if (window.OctoThreatDetector && typeof window.OctoThreatDetector.analyzeReq === "function") {
        try {
          const reqAlerts = window.OctoThreatDetector.analyzeReq(url, method, body);
          if (Array.isArray(reqAlerts)) {
            reqAlerts.forEach(a => {
              if (window.OctoLogger) window.OctoLogger.log(a.type, a.details, a.severity);
            });
          }
        } catch (e) {
          console.debug("[Probable-Octo-Palm-Tree] analyzeReq error:", e);
        }
      }

      if (window.OctoApiInterceptor && typeof window.OctoApiInterceptor.assessUrl === "function") {
        try {
          const apiAlerts = window.OctoApiInterceptor.assessUrl(url, method);
          if (Array.isArray(apiAlerts)) {
            apiAlerts.forEach(([t, d, s]) => {
              if (window.OctoLogger) window.OctoLogger.log(t, d, s);
            });
          }
        } catch (e) {
          console.debug("[Probable-Octo-Palm-Tree] assessUrl error:", e);
        }

        if (body && typeof window.OctoApiInterceptor.inspectBody === "function") {
          try {
            window.OctoApiInterceptor.inspectBody(body, url, method);
          } catch (e) {
            console.debug("[Probable-Octo-Palm-Tree] inspectBody error:", e);
          }
        }
      }

      // Route connection logs through the Logger module
      if (window.OctoLogger) {
        window.OctoLogger.logConnection(type, url, method);
      }
    } else if (action === "log_connection_blocked") {
      const { type, url, method } = payload || {};
      if (window.OctoLogger) {
        window.OctoLogger.log(
          type === "fetch" ? "Fetch Blocked" : "XHR Blocked",
          `${type === "fetch" ? "Fetch" : "XHR"} ${method} to blacklisted domain ${url} was blocked`,
          "critical"
        );
      }
    } else if (action === "cookie_access") {
      // JWT scanning hook — if a cookie access event contains a JWT, scan it
      if (window.OctoSessionMonitor && payload.value) {
        window.OctoSessionMonitor.scanJWT(payload.value, "cookie_event");
      }
    } else if (action === "spa_navigation") {
      // History API navigation (pushState / replaceState) fired from inject.js.
      // Schedule a fresh scan after a short delay to allow the SPA framework
      // to finish rendering the new virtual page into the DOM.
      if (!onTrustedDomain) {
        scheduleSpaRescan("history_api:" + (payload.method || "unknown"));
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

  // 4. SPA Navigation Re-scan
  // When a SPA navigates, the DOM is mutated but no page load fires.
  // We debounce the re-scan so rapid consecutive pushState calls (e.g. router
  // scroll restoration) collapse into a single scan run.
  let _spaRescanTimer = null;
  const SPA_RESCAN_DELAY_MS = 400; // ms to wait after last navigation signal

  function scheduleSpaRescan(reason) {
    if (_spaRescanTimer) clearTimeout(_spaRescanTimer);
    _spaRescanTimer = setTimeout(function() {
      _spaRescanTimer = null;
      try {
        if (!window.OctoThreatDetector || !window.OctoLogger) return;
        // runSpaNavigationScan() clears the dedup cache so new-page content
        // that happens to match a seen key from the previous view is re-evaluated.
        const alerts = window.OctoThreatDetector.runSpaNavigationScan();
        alerts.forEach(function(a) {
          window.OctoLogger.log(a.type, a.details, a.severity);
        });
      } catch (e) {
        console.debug("[Probable-Octo-Palm-Tree] SPA rescan error:", e);
      }
    }, SPA_RESCAN_DELAY_MS);
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

    // 5. SPA: hashchange — covers hash-router SPAs (e.g. Vue Router in hash mode)
    window.addEventListener("hashchange", function() {
      scheduleSpaRescan("hashchange");
    });

    // 6. SPA: popstate — covers back/forward navigation in history-mode SPAs.
    //    Note: inject.js also fires a synthetic popstate on pushState/replaceState,
    //    so this listener catches those too as a belt-and-suspenders fallback.
    window.addEventListener("popstate", function() {
      scheduleSpaRescan("popstate");
    });

    // Periodic scan only on untrusted domains, every 30s (MutationObserver handles real-time)
    setInterval(runFullScan, 30000);
  }
})();
