// OctoPlamTree Logger Module (runs in Content Script scope)
// v2.0 — Event batching, deduplication, queue system, token bucket, priority queues

(function() {

  // ─────────────────────────────────────────────
  // 1. TOKEN BUCKET RATE LIMITER
  //    Replaces the old sliding-window approach.
  //    Bucket holds up to CAPACITY tokens; refills
  //    at REFILL_RATE tokens/sec continuously.
  //    Each send consumes 1 token.
  // ─────────────────────────────────────────────
  const TokenBucket = (function() {
    const CAPACITY    = 20;   // max burst
    const REFILL_RATE = 8;    // tokens added per second

    let tokens        = CAPACITY;
    let lastRefill    = Date.now();

    function refill() {
      const now     = Date.now();
      const elapsed = (now - lastRefill) / 1000;
      tokens        = Math.min(CAPACITY, tokens + elapsed * REFILL_RATE);
      lastRefill    = now;
    }

    return {
      consume(cost = 1) {
        refill();
        if (tokens >= cost) {
          tokens -= cost;
          return true;
        }
        return false;
      },
      // Peek without consuming — used by the flush scheduler
      available() {
        refill();
        return tokens;
      }
    };
  })();


  // ─────────────────────────────────────────────
  // 2. DEDUPLICATION CACHE
  //    Fingerprints each event as "type::details[:50]".
  //    Same fingerprint within TTL_MS is suppressed.
  //    Cache auto-expires entries to avoid unbounded growth.
  // ─────────────────────────────────────────────
  const DedupeCache = (function() {
    const TTL_MS    = 15000;  // 15 s dedup window
    const MAX_SIZE  = 200;    // hard cap on cache entries

    const cache = new Map();  // fingerprint → expiry timestamp

    function fingerprint(action, payload) {
      if (action === "log_threat") {
        return `${payload.threat_type}::${(payload.details || "").substring(0, 60)}`;
      }
      if (action === "log_connection") {
        // Connections: dedupe same URL+method within TTL
        return `conn::${payload.type}::${payload.url}::${payload.method}`;
      }
      return `${action}::${JSON.stringify(payload).substring(0, 80)}`;
    }

    function evictExpired() {
      const now = Date.now();
      for (const [key, expiry] of cache) {
        if (now >= expiry) cache.delete(key);
      }
    }

    return {
      isDuplicate(action, payload) {
        const key = fingerprint(action, payload);
        const now = Date.now();
        if (cache.has(key) && cache.get(key) > now) return true;

        // Admit: record expiry
        evictExpired();
        if (cache.size >= MAX_SIZE) {
          // Evict oldest entry
          cache.delete(cache.keys().next().value);
        }
        cache.set(key, now + TTL_MS);
        return false;
      }
    };
  })();


  // ─────────────────────────────────────────────
  // 3. PRIORITY QUEUES
  //    Three lanes: critical, high, normal.
  //    Flush always drains critical first, then high,
  //    then normal — so important alerts are never
  //    starved behind a flood of connection telemetry.
  // ─────────────────────────────────────────────
  const PRIORITY = { critical: 0, high: 1, normal: 2 };

  const queues = {
    critical: [],  // threat_type severity critical / high
    high:     [],  // threat_type severity medium
    normal:   []   // log_connection telemetry
  };

  const QUEUE_CAP = {
    critical: 50,
    high:     100,
    normal:   300   // connections are high-volume; cap tighter
  };

  function lane(action, payload) {
    if (action === "log_threat") {
      const s = (payload.severity || "").toLowerCase();
      if (s === "critical") return "critical";
      if (s === "high")     return "high";
      return "high";  // all threats at least "high" lane
    }
    return "normal";
  }

  function enqueue(action, payload) {
    const l = lane(action, payload);
    const q = queues[l];
    if (q.length >= QUEUE_CAP[l]) {
      // Drop oldest normal/high items; never drop critical
      if (l !== "critical") {
        q.shift();
      } else {
        return; // critical queue full — extremely unlikely
      }
    }
    q.push({ action, payload });
  }


  // ─────────────────────────────────────────────
  // 4. BATCH SENDER
  //    Drains queues in priority order, bundles up to
  //    BATCH_SIZE messages per chrome.runtime.sendMessage
  //    call, and respects the token bucket.
  //    Batches are sent as action:"batch" with an
  //    `items` array so the background only needs one
  //    round-trip per flush cycle.
  // ─────────────────────────────────────────────
  const BATCH_SIZE      = 10;   // max items per batch message
  const FLUSH_INTERVAL  = 400;  // ms between flush attempts

  function drainInOrder(maxItems) {
    const out = [];
    for (const l of ["critical", "high", "normal"]) {
      while (queues[l].length > 0 && out.length < maxItems) {
        out.push(queues[l].shift());
      }
      if (out.length >= maxItems) break;
    }
    return out;
  }

  function safeSendBatch(items) {
    // Each batch costs 1 token regardless of item count —
    // the bucket governs message frequency, not item count.
    if (!TokenBucket.consume(1)) return false;
    try {
      chrome.runtime.sendMessage({ action: "batch", items }).catch(() => {});
    } catch (e) {
      // Extension context invalidated; silently ignore
    }
    return true;
  }

  function flush() {
    // How many batches can we send right now?
    const availableTokens = Math.floor(TokenBucket.available());
    const maxBatches      = Math.max(1, availableTokens);

    let sent = 0;
    while (sent < maxBatches) {
      const items = drainInOrder(BATCH_SIZE);
      if (items.length === 0) break;
      if (!safeSendBatch(items)) break;  // bucket empty mid-flush
      sent++;
    }
  }

  // Start the flush loop
  setInterval(flush, FLUSH_INTERVAL);

  // Also flush immediately on page-unload (best-effort)
  window.addEventListener("pagehide", flush, { once: true });


  // ─────────────────────────────────────────────
  // 5. PUBLIC LOGGER API
  //    Same surface as v1 — drop-in replacement.
  //    Internally routes through dedupe → enqueue.
  // ─────────────────────────────────────────────
  const logger = {

    log(type, details, severity = "medium") {
      console.warn(`[OctoPlamTree Alert] [${severity.toUpperCase()}] ${type}: ${details}`);

      let riskScore = 0;
      if (severity === "critical") riskScore = 90;
      else if (severity === "high") riskScore = 75;
      else if (severity === "medium") riskScore = 40;
      else if (severity === "low") riskScore = 15;

      const payload = {
        timestamp:   new Date().toISOString(),
        threat_type: type,
        details:     details,
        severity:    severity,
        url:         window.location.href,
        risk_score:  riskScore
      };

      if (DedupeCache.isDuplicate("log_threat", payload)) {
        console.debug(`[OctoPlamTree] Deduplicated: ${type}`);
        return;
      }

      enqueue("log_threat", payload);
    },

    logConnection(type, url, method = "") {
      const payload = {
        timestamp: new Date().toISOString(),
        type:      type,
        url:       url,
        method:    method,
        pageUrl:   window.location.href
      };

      // Deduplicate connections aggressively — very high volume
      if (DedupeCache.isDuplicate("log_connection", payload)) return;

      enqueue("log_connection", payload);
    },

    // Diagnostic helper — exposes internal state for testing
    _debug() {
      return {
        queues: {
          critical: queues.critical.length,
          high:     queues.high.length,
          normal:   queues.normal.length
        },
        tokenBucket: TokenBucket.available().toFixed(2)
      };
    }
  };

  window.OctoLogger = logger;

})();