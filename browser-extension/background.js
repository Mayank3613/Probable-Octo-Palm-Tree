// Probable-Octo-Palm-Tree Background Service Worker (ES6 Module)
// Orchestrates URL scanning, download monitoring, redirect tracking,
// self-healing, badge updates, notifications, and telemetry sync.

import { analyzeURL } from './modules/url-analyzer.js';
import { scanDownload } from './modules/download-scanner.js';

const TELEMETRY_ENDPOINT = "http://localhost:8000/telemetry/upload";
const TELEMETRY_ALARM_NAME = "probable_octo_telemetry_sync";
const BADGE_DECAY_ALARM_NAME = "probable_octo_badge_decay";
const TELEMETRY_SYNC_PERIOD_MINUTES = 1; // 1 minute
const BADGE_DECAY_PERIOD_MINUTES = 60;   // Reset badge counts every hour
let telemetryQueue = [];
let telemetryBackoff = 0; // Exponential backoff counter for failed syncs
const TELEMETRY_MAX_BACKOFF = 5; // Max 5 consecutive failures before silencing

// Redirect chain tracker — tabId -> [url1, url2, ...]
const redirectChains = new Map();
const REDIRECT_CHAIN_MAX = 5;
const REDIRECT_WINDOW_MS = 8000;

// Rate limiting for saveThreatLog: max 20 threats in a 10-second window
const THREAT_LOG_RATE_LIMIT = 20;
const THREAT_LOG_RATE_WINDOW_MS = 10000;
let threatLogTimestamps = [];

// Notification throttle: max 1 notification per 30 seconds
let lastNotificationTime = 0;
const NOTIFICATION_COOLDOWN_MS = 30000;

// ========== INITIALIZATION ==========

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["threatLogs", "connections", "settings", "stats", "userWhitelist"], (result) => {
    if (!result.threatLogs) chrome.storage.local.set({ threatLogs: [] });
    if (!result.connections) chrome.storage.local.set({ connections: [] });
    if (!result.stats) chrome.storage.local.set({ stats: { critical: 0, high: 0, medium: 0, total: 0, sessionsBlocked: 0 } });
    if (!result.userWhitelist) chrome.storage.local.set({ userWhitelist: [] });
    if (!result.settings) {
      chrome.storage.local.set({
        settings: {
          enableUrlMonitoring: true,
          enableDomMonitoring: true,
          enableDownloadScanning: true,
          enableSelfHealing: true,
          enableTelemetry: true,
          enableNotifications: true
        }
      });
    }
  });
  updateBadge();

  // Telemetry sync alarm
  chrome.alarms.create(TELEMETRY_ALARM_NAME, {
    delayInMinutes: TELEMETRY_SYNC_PERIOD_MINUTES,
    periodInMinutes: TELEMETRY_SYNC_PERIOD_MINUTES
  });

  // Badge decay alarm — auto-resets badge after 1 hour of no new threats
  chrome.alarms.create(BADGE_DECAY_ALARM_NAME, {
    delayInMinutes: BADGE_DECAY_PERIOD_MINUTES,
    periodInMinutes: BADGE_DECAY_PERIOD_MINUTES
  });
});

// Persist badge across browser restarts
chrome.runtime.onStartup.addListener(() => {
  updateBadge();
});

// ========== BADGE ICON UPDATES ==========

function updateBadge() {
  chrome.storage.local.get(["threatLogs"], (result) => {
    const logs = result.threatLogs || [];

    // Only count recent threats (last 1 hour) for badge
    const oneHourAgo = new Date(Date.now() - 3600000).toISOString();
    const recentLogs = logs.filter(l => l.timestamp > oneHourAgo);
    const criticalCount = recentLogs.filter(l => l.severity === "critical" || l.severity === "high").length;

    if (criticalCount > 0) {
      chrome.action.setBadgeText({ text: String(criticalCount) });
      chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
    } else if (recentLogs.length > 0) {
      chrome.action.setBadgeText({ text: String(recentLogs.length) });
      chrome.action.setBadgeBackgroundColor({ color: "#f59e0b" });
    } else {
      chrome.action.setBadgeText({ text: "" });
    }
  });
}

// ========== DESKTOP NOTIFICATIONS ==========

function showThreatNotification(logEntry) {
  const now = Date.now();
  if ((now - lastNotificationTime) < NOTIFICATION_COOLDOWN_MS) return;
  lastNotificationTime = now;

  chrome.storage.local.get(["settings"], (result) => {
    const settings = result.settings || {};
    if (settings.enableNotifications === false) return;

    const severityEmoji = logEntry.severity === "critical" ? "🔴" : logEntry.severity === "high" ? "🟡" : "🔵";
    const title = `${severityEmoji} ${logEntry.severity.toUpperCase()} Threat Detected`;

    try {
      chrome.notifications.create(`probable-octo-threat-${now}`, {
        type: "basic",
        iconUrl: "assets/icon128.png",
        title: title,
        message: `${logEntry.threat_type}\n${logEntry.details}`.substring(0, 200),
        priority: logEntry.severity === "critical" ? 2 : 1,
        requireInteraction: logEntry.severity === "critical"
      });
    } catch (e) {
      // Notifications may fail silently — non-critical
    }
  });
}

// ========== USER WHITELIST ==========

function isUserWhitelisted(url) {
  return new Promise((resolve) => {
    chrome.storage.local.get(["userWhitelist"], (result) => {
      const whitelist = result.userWhitelist || [];
      try {
        const hostname = new URL(url).hostname.toLowerCase();
        const isWhitelisted = whitelist.some(d => {
          const domain = d.toLowerCase();
          return hostname === domain || hostname.endsWith("." + domain);
        });
        resolve(isWhitelisted);
      } catch (e) {
        resolve(false);
      }
    });
  });
}

// ========== THREAT LOGGING ==========

function saveThreatLog(logEntry) {
  // Rate limiting
  const now = Date.now();
  threatLogTimestamps = threatLogTimestamps.filter(t => (now - t) < THREAT_LOG_RATE_WINDOW_MS);
  if (threatLogTimestamps.length >= THREAT_LOG_RATE_LIMIT) return;
  threatLogTimestamps.push(now);

  chrome.storage.local.get(["threatLogs", "settings", "stats"], (result) => {
    const logs = result.threatLogs || [];
    const settings = result.settings || {};
    const stats = result.stats || { critical: 0, high: 0, medium: 0, total: 0, sessionsBlocked: 0 };

    // Deduplicate within 10s window (increased from 5s for better dedup)
    const isDuplicate = logs.some(l =>
      l.threat_type === logEntry.threat_type &&
      l.url === logEntry.url &&
      (new Date(logEntry.timestamp) - new Date(l.timestamp)) < 10000
    );
    if (isDuplicate) return;

    logs.unshift(logEntry);
    
    // 7-day log retention policy (everyday customer use improvement)
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const filteredLogs = logs.filter(l => l.timestamp >= sevenDaysAgo);
    
    // Hard limit fallback
    if (filteredLogs.length > 500) filteredLogs.length = 500;

    // Update severity stats
    if (logEntry.severity === "critical") stats.critical++;
    else if (logEntry.severity === "high") stats.high++;
    else stats.medium++;
    stats.total++;

    chrome.storage.local.set({ threatLogs: filteredLogs, stats: stats });
    updateBadge();

    // Desktop notification for critical/high threats
    if (logEntry.severity === "critical" || logEntry.severity === "high") {
      showThreatNotification(logEntry);
    }

    // Queue telemetry
    if (settings.enableTelemetry !== false) {
      telemetryQueue.push(logEntry);
    }

    // Self-healing ONLY for critical threats (not high — too aggressive for daily use)
    if (settings.enableSelfHealing !== false && logEntry.severity === "critical") {
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

    // 1. Purge cookies for malicious domain
    chrome.cookies.getAll({ domain: domain }, (cookies) => {
      if (chrome.runtime.lastError) return;
      if (cookies) {
        cookies.forEach(cookie => {
          const protocol = cookie.secure ? "https:" : "http:";
          const cookieUrl = `${protocol}//${cookie.domain}${cookie.path}`;
          chrome.cookies.remove({ url: cookieUrl, name: cookie.name });
        });
      }
    });

    // 2. Clear storage, then redirect to quarantine
    chrome.tabs.query({}, (tabs) => {
      tabs.forEach(tab => {
        if (tab.url && tab.url.includes(domain) && tab.id) {
          const blockUrl = chrome.runtime.getURL(
            `blocked.html?url=${encodeURIComponent(tab.url)}&reason=${encodeURIComponent(logEntry.details)}&severity=${logEntry.severity}`
          );
          chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: () => {
              try { localStorage.clear(); } catch (e) {}
              try { sessionStorage.clear(); } catch (e) {}
            }
          }).then(() => {
            chrome.tabs.update(tab.id, { url: blockUrl });
          }).catch(() => {
            chrome.tabs.update(tab.id, { url: blockUrl });
          });
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
    // Quarantine error — non-fatal
  }
}

// ========== TELEMETRY SYNC ==========

async function syncTelemetry() {
  if (telemetryQueue.length === 0) return;

  // Exponential backoff: skip sync if backend is consistently down
  if (telemetryBackoff >= TELEMETRY_MAX_BACKOFF) {
    // Try once every 5th alarm to see if backend came back
    telemetryBackoff++;
    if (telemetryBackoff % 5 !== 0) return;
  }

  chrome.storage.local.get(["settings"], async (result) => {
    const settings = result.settings || {};
    if (settings.enableTelemetry === false) {
      telemetryQueue = [];
      telemetryBackoff = 0;
      return;
    }

    const payload = [...telemetryQueue];
    telemetryQueue = [];

    try {
      const response = await fetch(TELEMETRY_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ events: payload })
      });
      if (!response.ok) throw new Error(`Status ${response.status}`);
      telemetryBackoff = 0; // Reset backoff on success
    } catch (err) {
      // Re-queue on failure, cap at 500 events
      telemetryQueue = [...payload, ...telemetryQueue].slice(0, 500);
      telemetryBackoff++;
      // Only warn on first failure, not every 30s
      if (telemetryBackoff <= 1) {
        console.warn("[Probable-Octo-Palm-Tree] Telemetry sync failed — backend may be offline. Will retry with backoff.");
      }
    }
  });
}

// Alarm handler
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === TELEMETRY_ALARM_NAME) {
    syncTelemetry();
  } else if (alarm.name === BADGE_DECAY_ALARM_NAME) {
    updateBadge(); // Refresh badge — old threats will age out
  }
});

// ========== MESSAGE BRIDGE ==========

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "log_threat") {
    saveThreatLog(message.payload);
  } else if (message.action === "log_connection") {
    saveConnectionLog(message.payload);
  } else if (message.action === "batch") {
    // Handle batched messages from the logger module
    const items = message.items || [];
    for (const item of items) {
      if (item.action === "log_threat") {
        saveThreatLog(item.payload);
      } else if (item.action === "log_connection") {
        saveConnectionLog(item.payload);
      }
    }
  } else if (message.action === "get_stats") {
    chrome.storage.local.get(["stats"], (result) => {
      sendResponse(result.stats || {});
    });
    return true;
  } else if (message.action === "scan_current_url") {
    const analysis = analyzeURL(message.url);
    sendResponse(analysis);
    return true;
  } else if (message.action === "update_badge") {
    updateBadge();
  } else if (message.action === "add_to_whitelist") {
    chrome.storage.local.get(["userWhitelist"], (result) => {
      const whitelist = result.userWhitelist || [];
      const domain = message.domain.toLowerCase();
      if (!whitelist.includes(domain)) {
        whitelist.push(domain);
        chrome.storage.local.set({ userWhitelist: whitelist });
      }
      sendResponse({ success: true, whitelist: whitelist });
    });
    return true;
  } else if (message.action === "remove_from_whitelist") {
    chrome.storage.local.get(["userWhitelist"], (result) => {
      let whitelist = result.userWhitelist || [];
      whitelist = whitelist.filter(d => d !== message.domain.toLowerCase());
      chrome.storage.local.set({ userWhitelist: whitelist });
      sendResponse({ success: true, whitelist: whitelist });
    });
    return true;
  } else if (message.action === "get_whitelist") {
    chrome.storage.local.get(["userWhitelist"], (result) => {
      sendResponse(result.userWhitelist || []);
    });
    return true;
  }
  return true;
});

// ========== MODULE 1: URL MONITORING ==========

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.type !== "main_frame" && details.type !== "sub_frame") return;

    chrome.storage.local.get(["settings"], async (result) => {
      const settings = result.settings || {};
      if (settings.enableUrlMonitoring === false) return;

      // Check user whitelist before analyzing
      const whitelisted = await isUserWhitelisted(details.url);
      if (whitelisted) return;

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
      redirectChains.set(tabId, []);
    }
  },
  { urls: ["<all_urls>"] }
);

chrome.tabs.onRemoved.addListener((tabId) => {
  redirectChains.delete(tabId);
});

// ========== MODULE 6: DOWNLOAD MONITORING ==========

chrome.downloads.onCreated.addListener((downloadItem) => {
  chrome.storage.local.get(["settings"], async (result) => {
    const settings = result.settings || {};
    if (settings.enableDownloadScanning === false) return;

    const analysis = await scanDownload(downloadItem);
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

// Handle notification clicks — open popup
chrome.notifications.onClicked.addListener((notificationId) => {
  chrome.notifications.clear(notificationId);
});
