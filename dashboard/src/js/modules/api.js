

const API_BASE = "http://127.0.0.1:8000";

const API_TIMEOUT = 3000;


/* =========================================================================
   GENERIC FETCH WRAPPER
========================================================================= */

async function safeFetch(url) {

  try {

    const response = await fetch(url, {
      signal: AbortSignal.timeout(API_TIMEOUT)
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    return await response.json();

  } catch (err) {

    console.warn(
      `[OCTO-PALM API] Request failed: ${url}`,
      err
    );

    return null;
  }
}


/* =========================================================================
   FETCH LIVE TELEMETRY
========================================================================= */

export async function fetchLiveTelemetry(limit = 50) {

  const data = await safeFetch(
    `${API_BASE}/telemetry/live?limit=${limit}`
  );

  if (!data || !data.events) {
  return [];
}

  return data.events;
}


/* =========================================================================
   FETCH DASHBOARD STATS
========================================================================= */

export async function fetchDashboardStats() {

  const data = await safeFetch(
    `${API_BASE}/telemetry/stats`
  );

  if (!data || !data.stats) {
  return {
    total: 0,
    critical: 0,
    high: 0,
    recent_24h: 0,
    blocked_today: 0,
    top_domains: []
  };
}

  return data.stats;
}


/* =========================================================================
   FETCH CRITICAL EVENTS
========================================================================= */

export async function fetchCriticalThreats(limit = 20) {

  const data = await safeFetch(
    `${API_BASE}/telemetry/critical?limit=${limit}`
  );

  if (!data || !data.events) {
    return [];
  }

  return data.events;
}


/* =========================================================================
   MAIN DASHBOARD FETCH
========================================================================= */

export async function fetchFromAPI() {

  try {

    const [
      stats,
      threats,
      critical
    ] = await Promise.all([

      fetchDashboardStats(),

      fetchLiveTelemetry(),

      fetchCriticalThreats()
    ]);

    return {
      stats,
      threats,
      critical
    };

  } catch (err) {

    console.error(
      "[OCTO-PALM API] Full dashboard fetch failed",
      err
    );

    return {
      stats: {},
threats: [],
critical: []
    };
  }
}


/* =========================================================================
   HEALTH CHECK
========================================================================= */

export async function checkBackendHealth() {

  try {

    const response = await fetch(API_BASE, {
      signal: AbortSignal.timeout(1500)
    });

    return response.ok;

  } catch {

    return false;
  }
}


/* =========================================================================
   AUTO REFRESH HELPER
========================================================================= */

export function startLivePolling(callback, interval = 3000) {

  // Initial fetch
  callback();

  // Repeating fetch
  return setInterval(async () => {

    try {
      await callback();
    } catch (err) {

      console.warn(
        "[OCTO-PALM API] Polling error",
        err
      );
    }

  }, interval);
}

