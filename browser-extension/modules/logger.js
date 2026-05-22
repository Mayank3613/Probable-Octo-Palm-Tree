// OctoPlamTree Logger Module (runs in Content Script scope)
// Communicates with background worker to store security events

(function() {
  const logger = {
    log: function(type, details, severity = "medium") {
      console.warn(`[OctoPlamTree Alert] [${severity.toUpperCase()}] ${type}: ${details}`);
      chrome.runtime.sendMessage({
        action: "log_threat",
        payload: {
          timestamp: new Date().toISOString(),
          threat_type: type,
          details: details,
          severity: severity,
          url: window.location.href
        }
      }).catch(err => console.debug("Logger messaging error:", err));
    },

    logConnection: function(type, url, method = "") {
      chrome.runtime.sendMessage({
        action: "log_connection",
        payload: {
          timestamp: new Date().toISOString(),
          type: type, // "fetch", "xhr", "websocket"
          url: url,
          method: method,
          pageUrl: window.location.href
        }
      }).catch(err => console.debug("Logger messaging error:", err));
    }
  };

  // Expose to content scripts
  window.OctoLogger = logger;
})();
