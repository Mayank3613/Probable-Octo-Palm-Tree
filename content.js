// OctoPlamTree Content Script
// Orchestrates DOM scanning, hooks MAIN world APIs, and reports to Background

(function() {
  console.log("[OctoPlamTree] Content script initializing on:", window.location.href);

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
      console.debug("[OctoPlamTree] Failed to inject main world hook:", e);
    }
  }

  injectMainWorldScript();

  // 2. Listen for security events from the MAIN world hook (inject.js)
  window.addEventListener("OctoSecurityEvent", function(event) {
    const { action, payload } = event.detail || {};

    if (action === "log_connection") {
      if (window.OctoApiInterceptor) {
        window.OctoApiInterceptor.processConnection(payload.type, payload.url, payload.method);
      } else if (window.OctoLogger) {
        // Fallback: log directly if interceptor isn't available yet
        window.OctoLogger.logConnection(payload.type, payload.url, payload.method);
      }
    } else if (action === "cookie_access") {
      if (window.OctoSessionMonitor) {
        window.OctoSessionMonitor.processCookieAccess(payload.type, payload.value);
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
      console.debug("[OctoPlamTree] Scan error:", e);
    }
  }

  // Run scans when DOM content is loaded and shortly after
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      runFullScan();
      setTimeout(runFullScan, 2500);
    });
  } else {
    runFullScan();
    setTimeout(runFullScan, 2500);
  }

  // Also scan after full page load (images, iframes, etc.)
  window.addEventListener("load", () => {
    setTimeout(runFullScan, 1000);
  });

  // Periodic fallback scan every 15s (MutationObserver in threat-detector handles real-time)
  setInterval(runFullScan, 15000);
})();
