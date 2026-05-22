// OctoPlamTree Threat Detector Module (runs in Content Script scope)
// Evaluates DOM nodes, hidden components, and inline script behaviors

(function() {
  const ThreatDetector = {
    // 1. Analyze page scripts
    scanScripts: function() {
      const scripts = document.getElementsByTagName("script");
      const results = [];

      for (let script of scripts) {
        const content = script.innerHTML;
        const src = script.getAttribute("src") || "";

        // Check cryptominer keywords in URL or content
        if (src.includes("coinhive") || src.includes("cryptoloot") || src.includes("deepminer") ||
            content.includes("CoinHive.Anonymous") || content.includes("wmp.sandbox") || content.includes("miner.start")) {
          results.push({
            type: "Cryptominer Script",
            details: `Detected miner script signature: ${src || "Inline Script"}`,
            severity: "critical"
          });
        }

        // Check obfuscated/malicious scripts
        if (content.length > 8000) {
          // Calculate entropy or check suspicious functions
          const suspiciousCalls = ["eval", "unescape", "String.fromCharCode", "atob", "document.write"].filter(term => content.includes(term));
          
          if (suspiciousCalls.length >= 2) {
            results.push({
              type: "Obfuscated Javascript",
              details: `Large script (${content.length} chars) using dynamic execution methods: [${suspiciousCalls.join(", ")}]`,
              severity: "high"
            });
          }
        }
      }

      return results;
    },

    // 2. Scan for hidden iframes
    scanIframes: function() {
      const iframes = document.getElementsByTagName("iframe");
      const results = [];
      let hiddenCount = 0;

      for (let iframe of iframes) {
        const style = window.getComputedStyle(iframe);
        const isHidden = 
          style.display === "none" ||
          style.visibility === "hidden" ||
          parseFloat(style.opacity) === 0 ||
          iframe.offsetWidth <= 2 ||
          iframe.offsetHeight <= 2 ||
          parseInt(style.left) < -500 ||
          parseInt(style.top) < -500;

        if (isHidden) {
          hiddenCount++;
        }
      }

      if (hiddenCount >= 3) {
        results.push({
          type: "Excessive Hidden Iframes",
          details: `Detected ${hiddenCount} invisible iframes (frequent vector for drive-by downloads/clickjacking)`,
          severity: "high"
        });
      }

      return results;
    },

    // 3. Scan for clickjacking and phishing overlay panels
    scanOverlays: function() {
      const results = [];
      const divs = document.getElementsByTagName("div");
      
      for (let div of divs) {
        const style = window.getComputedStyle(div);
        
        // Look for fixed/absolute fullscreen layers with high z-indices
        if ((style.position === "fixed" || style.position === "absolute") &&
            parseInt(style.zIndex) > 5000 &&
            parseFloat(style.opacity) < 0.2 && 
            parseFloat(style.opacity) > 0.0) {
          
          // Verify if it covers a significant portion of screen
          const rect = div.getBoundingClientRect();
          const screenArea = window.innerWidth * window.innerHeight;
          const overlayArea = rect.width * rect.height;
          
          if (overlayArea > screenArea * 0.7) {
            results.push({
              type: "Clickjacking Overlay",
              details: `Suspicious semi-transparent layer detected spanning ${Math.round((overlayArea/screenArea)*100)}% of the viewport (z-index: ${style.zIndex})`,
              severity: "high"
            });
            break; // Single detection is enough
          }
        }
      }

      return results;
    },

    // Run all scans and return alerts
    runScan: function() {
      const alerts = [
        ...this.scanScripts(),
        ...this.scanIframes(),
        ...this.scanOverlays()
      ];
      return alerts;
    }
  };

  // Expose to content script scope
  window.OctoThreatDetector = ThreatDetector;
})();
