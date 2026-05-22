// OctoPlamTree Hook Injection Script (Runs in the page context / MAIN world)
// Direct interceptor for APIs (Fetch, XHR, WebSocket) and document.cookie.

(function() {
  // Prevent duplicate injection
  if (window.__octo_injected) return;
  window.__octo_injected = true;

  console.log("[OctoPlamTree] Security API hooks injected successfully.");

  // Helper to send events to content.js
  function dispatchSecurityEvent(action, payload) {
    const event = new CustomEvent("OctoSecurityEvent", {
      detail: { action, payload }
    });
    window.dispatchEvent(event);
  }

  // --- 1. Intercept Fetch ---
  const originalFetch = window.fetch;
  window.fetch = async function(...args) {
    const url = args[0];
    const options = args[1] || {};
    const method = options.method || "GET";

    if (url) {
      let resolvedUrl = "";
      try {
        resolvedUrl = typeof url === "string" ? url : (url.url || url.toString());
        dispatchSecurityEvent("log_connection", {
          type: "fetch",
          url: resolvedUrl,
          method: method
        });
      } catch (e) {
        console.debug("Error logging fetch URL", e);
      }
    }

    return originalFetch.apply(this, args);
  };

  // --- 2. Intercept XMLHttpRequest ---
  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    this._url = url;
    this._method = method;
    
    if (url) {
      dispatchSecurityEvent("log_connection", {
        type: "xhr",
        url: url.toString(),
        method: method
      });
    }
    return originalOpen.apply(this, [method, url, ...args]);
  };

  // --- 3. Intercept WebSockets ---
  const OriginalWebSocket = window.WebSocket;
  window.WebSocket = function(url, protocols) {
    let wsInstance;
    if (protocols) {
      wsInstance = new OriginalWebSocket(url, protocols);
    } else {
      wsInstance = new OriginalWebSocket(url);
    }

    dispatchSecurityEvent("log_connection", {
      type: "websocket",
      url: url,
      method: "WS"
    });

    return wsInstance;
  };
  // Maintain prototype properties
  window.WebSocket.prototype = OriginalWebSocket.prototype;

  // --- 4. Intercept Document.Cookie Getter/Setter ---
  try {
    const cookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, "cookie") || 
                             Object.getOwnPropertyDescriptor(HTMLDocument.prototype, "cookie");

    if (cookieDescriptor && cookieDescriptor.configurable) {
      Object.defineProperty(document, "cookie", {
        get: function() {
          const val = cookieDescriptor.get.call(document);
          dispatchSecurityEvent("cookie_access", { type: "read", value: val });
          return val;
        },
        set: function(val) {
          dispatchSecurityEvent("cookie_access", { type: "write", value: val });
          cookieDescriptor.set.call(document, val);
        },
        configurable: true,
        enumerable: true
      });
    }
  } catch (e) {
    console.debug("Failed to hook document.cookie descriptor:", e);
  }
})();
