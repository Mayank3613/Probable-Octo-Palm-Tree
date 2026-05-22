// OctoPlamTree Threat Quarantine Controller

document.addEventListener("DOMContentLoaded", () => {
  const urlEl = document.getElementById("threat-url");
  const reasonEl = document.getElementById("threat-reason");
  const severityTag = document.getElementById("severity-tag");
  const backBtn = document.getElementById("btn-back");
  const ignoreBtn = document.getElementById("btn-ignore");

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

  // Go back to safety
  backBtn.addEventListener("click", () => {
    if (window.history.length > 2) {
      window.history.go(-2); // Go past the blocked URL
    } else {
      window.location.href = "https://www.google.com";
    }
  });

  // Bypass warning — navigate to original URL
  ignoreBtn.addEventListener("click", () => {
    if (confirm("WARNING: You are about to visit a page flagged as dangerous. OctoPlamTree detected active threats on this URL. Proceed at your own risk?")) {
      window.location.href = targetUrl;
    }
  });
});
