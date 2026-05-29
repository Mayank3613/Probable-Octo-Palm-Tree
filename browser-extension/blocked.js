// Probable-Octo-Palm-Tree Threat Quarantine Controller

document.addEventListener("DOMContentLoaded", () => {
  const urlEl = document.getElementById("threat-url");
  const reasonEl = document.getElementById("threat-reason");
  const severityTag = document.getElementById("severity-tag");
  const backBtn = document.getElementById("btn-back");
  const ignoreBtn = document.getElementById("btn-ignore");
  const trustBtn = document.getElementById("btn-trust");

  // Parse query parameters
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("url") || "Unknown URL";
  const reason = params.get("reason") || "Suspicious structural anomalies detected by the Threat Analysis Engine.";
  const severity = params.get("severity") || "critical";

  urlEl.textContent = targetUrl;
  reasonEl.textContent = reason;

  // Update severity display
  severityTag.textContent = severity.toUpperCase();
  severityTag.className = `severity-tag ${severity}`;

  // Extract domain from URL for whitelist
  let targetDomain = "";
  try {
    targetDomain = new URL(targetUrl).hostname;
  } catch (e) {
    targetDomain = targetUrl;
  }

  // Go back to safety
  backBtn.addEventListener("click", () => {
    if (window.history.length > 2) {
      window.history.go(-2);
    } else {
      window.location.href = "https://www.google.com";
    }
  });

  // Trust this site — add to user whitelist permanently
  if (trustBtn) {
    trustBtn.addEventListener("click", () => {
      if (confirm(`Add "${targetDomain}" to your trusted domains? This site will no longer be flagged.`)) {
        chrome.runtime.sendMessage({ action: "add_to_whitelist", domain: targetDomain }, (response) => {
          if (chrome.runtime.lastError) {
            alert("Could not add to whitelist. Please add it manually in the extension settings.");
            return;
          }
          // Navigate back to the original URL
          window.location.href = targetUrl;
        });
      }
    });
  }

  // Bypass warning — navigate to original URL (one-time only)
  ignoreBtn.addEventListener("click", () => {
    if (confirm("WARNING: You are about to visit a page flagged as dangerous. Proceed at your own risk?")) {
      window.location.href = targetUrl;
    }
  });
});
