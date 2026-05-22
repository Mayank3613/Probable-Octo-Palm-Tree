// OctoPlamTree Threat Isolation Warning Controller

document.addEventListener("DOMContentLoaded", () => {
  const urlEl = document.getElementById("threat-url");
  const reasonEl = document.getElementById("threat-reason");
  const backBtn = document.getElementById("btn-back");
  const ignoreBtn = document.getElementById("btn-ignore");

  // Parse query parameters
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("url") || "Unknown Source URL";
  const reason = params.get("reason") || "Suspicious structural anomalies detected by Threat Analyzer Layer.";

  urlEl.textContent = targetUrl;
  reasonEl.textContent = reason;

  // Safe action: go back in history, or redirect to home page, or close tab
  backBtn.addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "https://www.google.com";
    }
  });

  // Bypass option: redirect to the actual target URL
  ignoreBtn.addEventListener("click", () => {
    // Disable extension scanning for this tab session temporarily by navigating directly
    // and appending an ignore query parameter
    let bypassUrl = targetUrl;
    try {
      const parsed = new URL(bypassUrl);
      parsed.searchParams.set("octo_bypass", "true");
      bypassUrl = parsed.toString();
    } catch (e) {}
    
    window.location.href = bypassUrl;
  });
});
