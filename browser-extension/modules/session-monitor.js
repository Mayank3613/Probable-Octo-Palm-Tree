// OctoPlamTree Session Monitor Module (runs in Content Script scope)
// Evaluates cookie modification alerts and session security practices

(function() {
  // Track sensitive cookie keys already reported this page load to avoid duplicate alerts
  const reportedSensitiveKeys = new Set();

  const SessionMonitor = {
    // Check if critical security attributes are missing on cookies
    checkSecurityAttributes: function(cookieString) {
      const parts = cookieString.split(';').map(p => p.trim().toLowerCase());
      const hasSecure = parts.includes("secure");
      const hasHttpOnly = parts.includes("httponly");
      const hasSameSite = parts.some(p => p.startsWith("samesite="));

      const warnings = [];
      if (!hasSecure) warnings.push("Secure");
      if (!hasHttpOnly) warnings.push("HttpOnly");
      if (!hasSameSite) warnings.push("SameSite");

      return warnings;
    },

    // Process intercepted cookie accesses
    processCookieAccess: function(type, cookieValue) {
      if (!cookieValue) return;

      const keys = cookieValue.split(';').map(c => c.split('=')[0].trim());

      // List of common sensitive session/auth keys
      const sensitiveKeys = [
        "session", "sess", "sid", "token", "jwt", "auth",
        "authtoken", "userid", "user_session", "oauth"
      ];

      const foundSensitive = keys.filter(k =>
        sensitiveKeys.some(sk => k.toLowerCase().includes(sk))
      );

      if (foundSensitive.length > 0) {
        // Rate limit: only report each sensitive key once per page load
        const unreported = foundSensitive.filter(k => !reportedSensitiveKeys.has(k.toLowerCase()));
        if (unreported.length === 0) return;

        unreported.forEach(k => reportedSensitiveKeys.add(k.toLowerCase()));

        // Guard against OctoLogger not being loaded yet
        if (window.OctoLogger) {
          window.OctoLogger.log(
            "Sensitive Cookie Read/Write",
            `Script access to auth token/session cookie: [${unreported.join(", ")}]`,
            "medium"
          );
        }
      }
    }
  };

  // Expose to content script scope
  window.OctoSessionMonitor = SessionMonitor;
})();
