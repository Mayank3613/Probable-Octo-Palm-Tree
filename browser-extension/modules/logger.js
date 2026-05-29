// Probable-Octo-Palm-Tree Logger Module (runs in Content Script scope)
// Communicates with background worker to store security events

(function() {
  // Rate limiting: max 10 messages per second (sliding window)
  const RATE_LIMIT_MAX = 10;
  const RATE_LIMIT_WINDOW_MS = 1000;
  let messageTimestamps = [];

  function isRateLimited() {
    const now = Date.now();
    messageTimestamps = messageTimestamps.filter(t => (now - t) < RATE_LIMIT_WINDOW_MS);
    if (messageTimestamps.length >= RATE_LIMIT_MAX) {
      return true;
    }
    messageTimestamps.push(now);
    return false;
  }

  function safeSendMessage(msg) {
    if (isRateLimited()) return;
    try {
      chrome.runtime.sendMessage(msg).catch(() => {
        // Extension context invalidated or message port closed; silently ignore
      });
    } catch (e) {
      // chrome.runtime may be unavailable if extension was updated/reloaded; silently ignore
    }
  }

  const logger = {
    log: function(type, details, severity = "medium") {
      // Only show critical threats in console — don't spam DevTools for everyday users
      if (severity === "critical") {
        console.warn(`[Probable-Octo-Palm-Tree] 🔴 ${type}: ${details}`);
      }
      safeSendMessage({
        action: "log_threat",
        payload: {
          timestamp: new Date().toISOString(),
          threat_type: type,
          details: details,
          severity: severity,
          url: window.location.href
        }
      });
    },

    logConnection: function(type, url, method = "") {
      safeSendMessage({
        action: "log_connection",
        payload: {
          timestamp: new Date().toISOString(),
          type: type,
          url: url,
          method: method,
          pageUrl: window.location.href
        }
      });
    }
  };

  // Expose to content scripts
  window.OctoLogger = logger;
})();
