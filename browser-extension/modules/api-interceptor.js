// Probable-Octo-Palm-Tree API Interceptor (runs in Content Script scope)
// Evaluates intercepted API connections against threat lists

(function() {
  const BLOCKED_DOMAINS = [
    "malicious-api-example.com",
    "phishing-backend.net",
    "coinhive.com",
    "cryptoloot.pro",
    "minero.cc",
    "coin-hive.com",
    "jsecoin.com",
    "crypto-loot.com",
    "webmine.pro",
    "authedmine.com",
    "ppoi.org",
    "crypma.com",
    "keylogger-cdn.net",
    "data-exfil.xyz",
    "stealer-api.ru"
  ];

  const ApiInterceptor = {
    isBlocked: function(urlString) {
      try {
        // Use window.location.href as base to resolve relative URLs like "/api/data"
        const url = new URL(urlString, window.location.href);
        const host = url.hostname.toLowerCase();
        return BLOCKED_DOMAINS.some(domain => host === domain || host.endsWith("." + domain));
      } catch (e) {
        return false;
      }
    },

    processConnection: function(type, url, method = "") {
      if (this.isBlocked(url)) {
        if (window.OctoLogger) {
          window.OctoLogger.log(
            "Blocked Connection",
            `Intercepted ${type.toUpperCase()} request to blacklisted malicious server: ${url}`,
            "critical"
          );
        }
        return true;
      }

      // Log connection standard stats
      if (window.OctoLogger) {
        window.OctoLogger.logConnection(type, url, method);
      }
      return false;
    }
  };

  window.OctoApiInterceptor = ApiInterceptor;
})();
