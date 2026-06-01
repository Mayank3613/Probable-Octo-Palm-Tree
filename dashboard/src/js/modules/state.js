/* ─── APPLICATION STATE ──────────────────────────────────────────────────────
   Single mutable state object.  All modules read from and write to this.
   Never import state from individual view files — always use this module.
─────────────────────────────────────────────────────────────────────────── */

const AppState = {
  /** @type {Array}  Current threat list */
  threats: [],

  /** @type {object|null} Latest stats payload */
  stats: null,

  /** @type {Array}  URL scan history (most-recent first) */
  scanHistory: [],

  /** @type {string} Active feed filter: 'all' | 'critical' | 'high' | 'medium' */
  activeFilter: 'all',

  /** @type {string} Feed sort mode: 'time' | 'score' */
  sortMode: 'time',

  /** @type {string} Active IOC tab: 'ip' | 'domain' | 'hash' */
  curIocTab: 'ip',
};
