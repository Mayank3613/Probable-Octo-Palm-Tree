// OctoPlamTree Background Service Worker (ES6 Module)
// Orchestrates URL scanning, download monitoring, redirect tracking,
// self-healing, badge updates, and telemetry sync.

import { analyzeURL } from './modules/url-analyzer.js';
import { scanDownload } from './modules/download-scanner.js';

console.log("[OctoPlamTree] Background service worker online.");

const TELEMETRY_ENDPOINT = "http://localhost:8000/telemetry/upload";
const TELEMETRY_SYNC_INTERVAL = 30000;
let telemetryQueue = [];

// Redirect chain tracker — tabId -> [url1, url2, ...]
const redirectChains = new Map();
const REDIRECT_CHAIN_MAX = 5; // alert after this many rapid redirects
const REDIRECT_WINDOW_MS = 8000; // within 8 seconds

// ========== INITIALIZATION ==========

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["threatLogs", "connections", "settings", "stats"], (result) => {
    if (!result.threatLogs) chrome.storage.local.set({ threatLogs: [] });
    if (!result.connections) chrome.storage.local.set({ connections: [] });
    if (!result.stats) chrome.storage.local.set({ stats: { critical: 0, high: 0, medium: 0, total: 0, sessionsBlocked: 0 } });
    if (!result.settings) {
      chrome.storage.local.set({
        settings: {
          enableUrlMonitoring: true,
          enableDomMonitoring: true,
          enableDownloadScanning: true,
          enableSelfHealing: true,
          enableTelemetry: true
        }
      });
    }
  });
  updateBadge();
});

// ========== BADGE ICON UPDATES ==========

function updateBadge() {
  chrome.storage.local.get(["threatLogs"], (result) => {
    const logs = result.threatLogs || [];
    const criticalCount = logs.filter(l => l.severity === "critical" || l.severity === "high").length;

    if (criticalCount > 0) {
      chrome.action.setBadgeText({ text: String(criticalCount) });
      chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
    } else if (logs.length > 0) {
      chrome.action.setBadgeText({ text: String(logs.length) });
      chrome.action.setBadgeBackgroundColor({ color: "#f59e0b" });
    } else {
      chrome.action.setBadgeText({ text: "" });
    }
  });
}

// ========== THREAT LOGGING ==========

function saveThreatLog(logEntry) {
  chrome.storage.local.get(["threatLogs", "settings", "stats"], (result) => {
    const logs = result.threatLogs || [];
    const settings = result.settings || {};
    const stats = result.stats || { critical: 0, high: 0, medium: 0, total: 0, sessionsBlocked: 0 };

    // Deduplicate within 5s window
    const isDuplicate = logs.some(l =>
      l.threat_type === logEntry.threat_type &&
      l.url === logEntry.url &&
      (new Date(logEntry.timestamp) - new Date(l.timestamp)) < 5000
    );
    if (isDuplicate) return;

    logs.unshift(logEntry);
    if (logs.length > 300) logs.length = 300;

    // Update severity stats
    if (logEntry.severity === "critical") stats.critical++;
    else if (logEntry.severity === "high") stats.high++;
    else stats.medium++;
    stats.total++;

    chrome.storage.local.set({ threatLogs: logs, stats: stats });

    // Update badge immediately
    updateBadge();

    // Queue telemetry
    if (settings.enableTelemetry !== false) {
      telemetryQueue.push(logEntry);
    }

    // Self-healing for critical/high threats
    if (settings.enableSelfHealing !== false && (logEntry.severity === "critical" || logEntry.severity === "high")) {
      quarantineThreat(logEntry);
    }
  });
}

// ========== CONNECTION LOGGING ==========

function saveConnectionLog(connEntry) {
  chrome.storage.local.get(["connections"], (result) => {
    const conns = result.connections || [];
    conns.unshift(connEntry);
    if (conns.length > 150) conns.length = 150;
    chrome.storage.local.set({ connections: conns });
  });
}

// ========== SELF-HEALING ENGINE ==========

function quarantineThreat(logEntry) {
  const targetUrl = logEntry.url;
  try {
    const parsedUrl = new URL(targetUrl);
    const domain = parsedUrl.hostname;

    // 1. Purge all cookies for the malicious domain
    chrome.cookies.getAll({ domain: domain }, (cookies) => {
      if (chrome.runtime.lastError) {
        console.warn("[Self-Healing] Cookie access error:", chrome.runtime.lastError.message);
        return;
      }
      if (cookies) {
        cookies.forEach(cookie => {
          const protocol = cookie.secure ? "https:" : "http:";
          const cookieUrl = `${protocol}//${cookie.domain}${cookie.path}`;
          chrome.cookies.remove({ url: cookieUrl, name: cookie.name });
        });
        console.log(`[Self-Healing] Purged ${cookies.length} cookies for ${domain}`);
      }
    });

    // 2. Clear localStorage and sessionStorage for quarantined domain via scripting
    chrome.tabs.query({}, (tabs) => {
      tabs.forEach(tab => {
        if (tab.url && tab.url.includes(domain) && tab.id) {
          // Inject session invalidation script before redirecting
          chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: () => {
              try { localStorage.clear(); } catch (e) {}
              try { sessionStorage.clear(); } catch (e) {}
            }
          }).catch(() => {});

          // Redirect to quarantine page
          const blockUrl = chrome.runtime.getURL(
            `blocked.html?url=${encodeURIComponent(tab.url)}&reason=${encodeURIComponent(logEntry.details)}&severity=${logEntry.severity}`
          );
          chrome.tabs.update(tab.id, { url: blockUrl });
          console.warn(`[Self-Healing] Quarantined tab: ${tab.url}`);
        }
      });
    });

    // Track session block count
    chrome.storage.local.get(["stats"], (result) => {
      const stats = result.stats || { critical: 0, high: 0, medium: 0, total: 0, sessionsBlocked: 0 };
      stats.sessionsBlocked++;
      chrome.storage.local.set({ stats });
    });

  } catch (e) {
    console.error("[Self-Healing] Quarantine error:", e);
  }
}

// ========== TELEMETRY SYNC ==========

async function syncTelemetry() {
  if (telemetryQueue.length === 0) return;

  chrome.storage.local.get(["settings"], async (result) => {
    const settings = result.settings || {};
    if (settings.enableTelemetry === false) {
      telemetryQueue = [];
      return;
    }

    const payload = [...telemetryQueue];
    telemetryQueue = [];

    try {
      console.log(`[Telemetry] Syncing ${payload.length} events...`);
      const response = await fetch(TELEMETRY_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ events: payload })
      });
      if (!response.ok) throw new Error(`Status ${response.status}`);
      console.log("[Telemetry] Sync complete.");
    } catch (err) {
      console.warn("[Telemetry] Sync failed, re-queuing:", err.message);
      telemetryQueue = [...payload, ...telemetryQueue].slice(0, 500);
    }
  });
}

setInterval(syncTelemetry, TELEMETRY_SYNC_INTERVAL);

// ========== MESSAGE BRIDGE ==========

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "log_threat") {
    saveThreatLog(message.payload);
  } else if (message.action === "log_connection") {
    saveConnectionLog(message.payload);
  } else if (message.action === "get_stats") {
    chrome.storage.local.get(["stats"], (result) => {
      sendResponse(result.stats || {});
    });
    return true; // async response
  } else if (message.action === "scan_current_url") {
    // On-demand URL scan from popup
    const analysis = analyzeURL(message.url);
    sendResponse(analysis);
    return true;
  }
  return true;
});

// ========== MODULE 1: URL MONITORING ==========

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.type !== "main_frame" && details.type !== "sub_frame") return;

    chrome.storage.local.get(["settings"], (result) => {
      const settings = result.settings || {};
      if (settings.enableUrlMonitoring === false) return;

      const analysis = analyzeURL(details.url);
      if (analysis.isSuspicious) {
        saveThreatLog({
          timestamp: new Date().toISOString(),
          threat_type: "Phishing/Malicious URL",
          details: analysis.reason,
          severity: analysis.score >= 70 ? "critical" : "high",
          url: details.url,
          risk_score: analysis.score
        });
      }
    });
  },
  { urls: ["<all_urls>"] }
);

// ========== REDIRECT CHAIN DETECTION ==========

chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    if (details.type !== "main_frame") return;

    const tabId = details.tabId;
    const now = Date.now();

    if (!redirectChains.has(tabId)) {
      redirectChains.set(tabId, []);
    }

    const chain = redirectChains.get(tabId);
    // Remove old entries outside the time window
    while (chain.length > 0 && (now - chain[0].time) > REDIRECT_WINDOW_MS) {
      chain.shift();
    }

    chain.push({ url: details.redirectUrl, time: now });

    if (chain.length >= REDIRECT_CHAIN_MAX) {
      const urls = chain.map(c => c.url);
      saveThreatLog({
        timestamp: new Date().toISOString(),
        threat_type: "Suspicious Redirect Chain",
        details: `${chain.length} rapid redirects in ${REDIRECT_WINDOW_MS / 1000}s: ${urls.slice(-3).join(" → ")}`,
        severity: "high",
        url: details.url,
        risk_score: 75
      });
      // Clear the chain after alerting
      redirectChains.set(tabId, []);
    }
  },
  { urls: ["<all_urls>"] }
);

// Clean up redirect chains when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  redirectChains.delete(tabId);
});

// ========== MODULE 6: DOWNLOAD MONITORING ==========

chrome.downloads.onCreated.addListener((downloadItem) => {
  chrome.storage.local.get(["settings"], (result) => {
    const settings = result.settings || {};
    if (settings.enableDownloadScanning === false) return;

    const analysis = scanDownload(downloadItem);
    if (analysis.isSuspicious) {
      saveThreatLog({
        timestamp: new Date().toISOString(),
        threat_type: "Malicious Download",
        details: analysis.reason,
        severity: analysis.score >= 80 ? "critical" : "medium",
        url: downloadItem.url,
        risk_score: analysis.score
      });
    }
  });
});
