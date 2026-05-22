// OctoPlamTree API Interceptor (runs in Content Script scope)
// Evaluates intercepted API connections against threat lists

(function() {
  const BLOCKED_DOMAINS = [
    "malicious-api-example.com",
    "phishing-backend.net",
    "coinhive.com",
    "cryptoloot.pro"
  ];

  const ApiInterceptor = {
    isBlocked: function(urlString) {
      try {
        const url = new URL(urlString);
        const host = url.hostname.toLowerCase();
        return BLOCKED_DOMAINS.some(domain => host === domain || host.endsWith("." + domain));
      } catch (e) {
        return false;
      }
    },

    processConnection: function(type, url, method = "") {
      if (this.isBlocked(url)) {
        window.OctoLogger.log(
          "Blocked Connection", 
          `Intercepted ${type.toUpperCase()} request to blacklisted malicious server: ${url}`,
          "critical"
        );
        return true;
      }
      
      // Log connection standard stats
      window.OctoLogger.logConnection(type, url, method);
      return false;
    }
  };

  window.OctoApiInterceptor = ApiInterceptor;
})();
