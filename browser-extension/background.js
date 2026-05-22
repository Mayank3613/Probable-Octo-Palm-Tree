// OctoPlamTree Background Service Worker (ES6 Module)
import { analyzeURL } from './modules/url-analyzer.js';
import { scanDownload } from './modules/download-scanner.js';

console.log("[OctoPlamTree] Background service worker online.");

const TELEMETRY_ENDPOINT = "http://localhost:8000/telemetry/upload";
const TELEMETRY_SYNC_INTERVAL = 30000; // Sync every 30 seconds
let telemetryQueue = [];

// Initialize configuration in storage
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["threatLogs", "connections", "settings"], (result) => {
    if (!result.threatLogs) chrome.storage.local.set({ threatLogs: [] });
    if (!result.connections) chrome.storage.local.set({ connections: [] });
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
});

// --- HELPER: Save Threat Log ---
function saveThreatLog(logEntry) {
  chrome.storage.local.get(["threatLogs", "settings"], (result) => {
    const logs = result.threatLogs || [];
    const settings = result.settings || {};

    // Prevent duplicate logs within short periods
    const isDuplicate = logs.some(l => 
      l.threat_type === logEntry.threat_type && 
      l.url === logEntry.url && 
      (new Date(logEntry.timestamp) - new Date(l.timestamp)) < 5000
    );

    if (isDuplicate) return;

    logs.unshift(logEntry);
    
    // Cap at 200 logs
    if (logs.length > 200) logs.pop();
    
    chrome.storage.local.set({ threatLogs: logs });

    // Queue for telemetry if enabled
    if (settings.enableTelemetry !== false) {
      telemetryQueue.push(logEntry);
    }

    // Trigger Self-Healing (Tab quarantine/isolation and Cookie cleanup) if critical
    if (settings.enableSelfHealing !== false && (logEntry.severity === "critical" || logEntry.severity === "high")) {
      quarantineThreat(logEntry);
    }
  });
}

// --- HELPER: Save Connection Log ---
function saveConnectionLog(connEntry) {
  chrome.storage.local.get(["connections"], (result) => {
    const conns = result.connections || [];
    conns.unshift(connEntry);
    // Cap at 100 connections
    if (conns.length > 100) conns.pop();
    chrome.storage.local.set({ connections: conns });
  });
}

// --- SELF HEALING: Quarantine & Isolator ---
function quarantineThreat(logEntry) {
  const targetUrl = logEntry.url;
  try {
    const domain = new URL(targetUrl).hostname;

    // 1. Purge cookies associated with the malicious domain
    chrome.cookies.getAll({ domain: domain }, (cookies) => {
      if (cookies) {
        cookies.forEach(cookie => {
          const protocol = cookie.secure ? "https:" : "http:";
          const cookieUrl = `${protocol}//${cookie.domain}${cookie.path}`;
          chrome.cookies.remove({ url: cookieUrl, name: cookie.name }, (details) => {
            console.log(`[Self-Healing] Deleted cookie ${cookie.name} for ${domain}`);
          });
        });
      }
    });

    // 2. Redirect malicious tab to block/warning quarantine page
    chrome.tabs.query({}, (tabs) => {
      tabs.forEach(tab => {
        if (tab.url && tab.url.includes(domain) && tab.id) {
          const blockUrl = chrome.runtime.getURL(`blocked.html?url=${encodeURIComponent(tab.url)}&reason=${encodeURIComponent(logEntry.details)}`);
          chrome.tabs.update(tab.id, { url: blockUrl });
          console.warn(`[Self-Healing] Isolated malicious tab: ${tab.url} -> Redirected to safety warning.`);
        }
      });
    });
  } catch (e) {
    console.error("Error executing self-healing sequence:", e);
  }
}

// --- TELEMETRY: Background Sync Loop ---
async function syncTelemetry() {
  if (telemetryQueue.length === 0) return;

  chrome.storage.local.get(["settings"], async (result) => {
    const settings = result.settings || {};
    if (settings.enableTelemetry === false) {
      telemetryQueue = [];
      return;
    }

    const payload = [...telemetryQueue];
    telemetryQueue = []; // Clear queue

    try {
      console.log(`[Telemetry] Sending ${payload.length} events to Central Threat Intelligence API...`);
      const response = await fetch(TELEMETRY_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ events: payload })
      });

      if (!response.ok) {
        throw new Error(`Server returned status ${response.status}`);
      }
      console.log("[Telemetry] Sync successfully completed.");
    } catch (err) {
      console.warn("[Telemetry] Sync failed. Restoring queue entries.", err.message);
      // Restore queued entries to retry next cycle
      telemetryQueue = [...payload, ...telemetryQueue].slice(0, 500);
    }
  });
}

// Start telemetry clock
setInterval(syncTelemetry, TELEMETRY_SYNC_INTERVAL);

// --- LISTENERS: Messaging Bridge ---
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "log_threat") {
    saveThreatLog(message.payload);
  } else if (message.action === "log_connection") {
    saveConnectionLog(message.payload);
  }
  return true;
});

// --- MODULE 1: URL MONITORING ---
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.type !== "main_frame") return; // Only scan main navigation frames

    chrome.storage.local.get(["settings"], (result) => {
      const settings = result.settings || {};
      if (settings.enableUrlMonitoring === false) return;

      const analysis = analyzeURL(details.url);
      if (analysis.isSuspicious) {
        saveThreatLog({
          timestamp: new Date().toISOString(),
          threat_type: "Phishing/Malicious Domain",
          details: analysis.reason,
          severity: analysis.score >= 70 ? "critical" : "high",
          url: details.url
        });
      }
    });
  },
  { urls: ["<all_urls>"] }
);

// --- MODULE 6: DOWNLOAD MONITORING ---
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
        url: downloadItem.url
      });
    }
  });
});
