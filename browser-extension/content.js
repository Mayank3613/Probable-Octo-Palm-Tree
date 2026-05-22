// OctoPlamTree Content Script
// Orchestrates DOM scanning, hooks MAIN world APIs, and reports to Background

(function() {
  console.log("[OctoPlamTree] Content script initializing...");

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
      console.debug("Failed to inject main world hook script:", e);
    }
  }

  // Inject immediately on document start
  injectMainWorldScript();

  // 2. Listen for custom events dispatched by the MAIN world hook script (inject.js)
  window.addEventListener("OctoSecurityEvent", function(event) {
    const { action, payload } = event.detail || {};

    if (action === "log_connection") {
      // Pass to content-script interceptor to check against blacklists
      if (window.OctoApiInterceptor) {
        window.OctoApiInterceptor.processConnection(payload.type, payload.url, payload.method);
      }
    } else if (action === "cookie_access") {
      if (window.OctoSessionMonitor) {
        window.OctoSessionMonitor.processCookieAccess(payload.type, payload.value);
      }
    }
  });

  // 3. Set up periodic DOM/Script scanning
  function runDOMThreatScanning() {
    if (!window.OctoThreatDetector || !window.OctoLogger) return;

    try {
      const alerts = window.OctoThreatDetector.runScan();
      alerts.forEach(alert => {
        window.OctoLogger.log(alert.type, alert.details, alert.severity);
      });
    } catch (e) {
      console.debug("Error during DOM threat scanning:", e);
    }
  }

  // Scan once DOM content is loaded
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      runDOMThreatScanning();
      // Schedule follow-up scan in case scripts load late
      setTimeout(runDOMThreatScanning, 3000);
    });
  } else {
    runDOMThreatScanning();
    setTimeout(runDOMThreatScanning, 3000);
  }

  // Periodically re-scan (every 10s) to catch dynamically injected elements
  setInterval(runDOMThreatScanning, 10000);
})();
