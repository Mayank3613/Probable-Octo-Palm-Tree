// Probable-Octo-Palm-Tree Hook Injection Script (Runs in the page context / MAIN world)
// Direct interceptor for APIs (Fetch, XHR, WebSocket, History) and document.cookie.

(function() {
  // Prevent duplicate injection
  if (window.__octo_injected) return;
  window.__octo_injected = true;

  const BLOCKED_DOMAINS = new Set([
    "malicious-api-example.com", "phishing-backend.net", "coinhive.com", "cryptoloot.pro",
    "minero.cc", "coin-hive.com", "jsecoin.com", "crypto-loot.com", "webmine.pro",
    "authedmine.com", "ppoi.org", "crypma.com", "keylogger-cdn.net", "data-exfil.xyz", "stealer-api.ru"
  ]);

  const hostOf = url => {
    try {
      return new URL(url, location.href).hostname.toLowerCase();
    } catch {
      return "";
    }
  };

  function isBlocked(url) {
    const host = hostOf(url);
    if (!host) return false;
    return BLOCKED_DOMAINS.has(host) || [...BLOCKED_DOMAINS].some(d => host.endsWith("." + d));
  }

  function serializeBody(body) {
    if (!body) return null;
    try {
      if (typeof body === "string") return body;
      if (body instanceof URLSearchParams) return body.toString();
      if (body instanceof FormData) {
        return [...body.entries()].map(([k, v]) => `${k}=${v}`).join("&");
      }
      return JSON.stringify(body);
    } catch {
      return String(body);
    }
  }

  // Helper to send events to content.js (wrapped in try-catch for destroyed contexts)
  function dispatchSecurityEvent(action, payload) {
    try {
      const event = new CustomEvent("OctoSecurityEvent", {
        detail: { action, payload }
      });
      window.dispatchEvent(event);
    } catch (e) {
      // Content script context may already be destroyed; silently ignore
    }
  }

  // --- 1. Intercept Fetch ---
  const originalFetch = window.fetch;
  window.fetch = async function(...args) {
    const input = args[0];
    const options = args[1] || {};

    if (input) {
      try {
        let resolvedUrl = "";
        let method = "GET";

        if (typeof input === "string") {
          resolvedUrl = input;
          method = options.method || "GET";
        } else if (input instanceof Request) {
          resolvedUrl = input.url;
          method = input.method || options.method || "GET";
        } else {
          resolvedUrl = input.toString();
          method = options.method || "GET";
        }

        method = method.toUpperCase();

        if (isBlocked(resolvedUrl)) {
          dispatchSecurityEvent("log_connection_blocked", {
            type: "fetch",
            url: resolvedUrl,
            method: method
          });
          return Promise.reject(new Error(`[OctoPlamTree] Blocked request to: ${resolvedUrl}`));
        }

        const bodyPayload = serializeBody(options.body);

        dispatchSecurityEvent("log_connection", {
          type: "fetch",
          url: resolvedUrl,
          method: method,
          body: bodyPayload
        });
      } catch (e) {
        // Silently ignore logging errors to avoid breaking page functionality
      }
    }

    return originalFetch.apply(this, args);
  };

  // --- 2. Intercept XMLHttpRequest ---
  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    this._url = url;
    this._method = method;
    return originalOpen.apply(this, [method, url, ...args]);
  };

  const originalSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function(body) {
    const url = this._url;
    const method = (this._method || "GET").toUpperCase();

    if (url) {
      try {
        const urlStr = url.toString();
        if (isBlocked(urlStr)) {
          dispatchSecurityEvent("log_connection_blocked", {
            type: "xhr",
            url: urlStr,
            method: method
          });
          this.abort();
          return;
        }

        dispatchSecurityEvent("log_connection", {
          type: "xhr",
          url: urlStr,
          method: method,
          body: serializeBody(body)
        });
      } catch (e) {
        // Silently ignore logging errors
      }
    }
    return originalSend.apply(this, arguments);
  };

  // --- 3. Intercept WebSockets ---
  // Use a Proxy to properly handle the `new` keyword, instanceof checks, and static properties
  const OriginalWebSocket = window.WebSocket;
  window.WebSocket = new Proxy(OriginalWebSocket, {
    construct(target, args) {
      const [url, protocols] = args;

      dispatchSecurityEvent("log_connection", {
        type: "websocket",
        url: url,
        method: "WS"
      });

      // Properly construct the real WebSocket using Reflect.construct
      return Reflect.construct(target, args);
    },
    get(target, prop, receiver) {
      // Forward static property access (e.g., WebSocket.OPEN, WebSocket.CLOSED) to the original
      return Reflect.get(target, prop, receiver);
    }
  });

  // --- 4. Intercept Document.Cookie Getter/Setter ---
  try {
    const cookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, "cookie") ||
                             Object.getOwnPropertyDescriptor(HTMLDocument.prototype, "cookie");

    if (cookieDescriptor && cookieDescriptor.configurable) {
      // Debounce cookie read events: fire at most once every 2 seconds
      let lastCookieReadDispatch = 0;
      const COOKIE_READ_DEBOUNCE_MS = 2000;

      Object.defineProperty(document, "cookie", {
        get: function() {
          const val = cookieDescriptor.get.call(document);
          const now = Date.now();
          if ((now - lastCookieReadDispatch) >= COOKIE_READ_DEBOUNCE_MS) {
            lastCookieReadDispatch = now;
            dispatchSecurityEvent("cookie_access", { type: "read", value: val });
          }
          return val;
        },
        set: function(val) {
          // Always dispatch cookie writes (they are infrequent and security-relevant)
          dispatchSecurityEvent("cookie_access", { type: "write", value: val });
          cookieDescriptor.set.call(document, val);
        },
        configurable: true,
        enumerable: true
      });
    }
  } catch (e) {
    // Failed to hook document.cookie descriptor; non-fatal
  }

  // --- 5. Intercept History API for SPA Navigation Detection ---
  // SPAs mutate the URL via pushState/replaceState without triggering a page reload.
  // We patch these methods to emit an OctoSpaNavigated event that content.js listens
  // for and uses to re-run threat scans on the freshly rendered view.
  (function patchHistoryApi() {
    function wrapHistoryMethod(methodName) {
      const original = history[methodName];
      history[methodName] = function(state, title, url) {
        const result = original.apply(this, arguments);
        try {
          // Dispatch to content.js so it can trigger a re-scan
          dispatchSecurityEvent("spa_navigation", {
            method: methodName,
            url: url ? String(url) : location.href
          });
          // Also fire a native-style event so other listeners (e.g. analytics) still work
          window.dispatchEvent(new PopStateEvent("popstate", { state }));
        } catch (e) {
          // Non-fatal; never break the page's own navigation
        }
        return result;
      };
    }

    wrapHistoryMethod("pushState");
    wrapHistoryMethod("replaceState");
  })();
})();
