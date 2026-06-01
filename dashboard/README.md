This is a [Next.js](https://nextjs.org) project bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

# OCTO-PALM Threat Intelligence Dashboard

A browser-based cybersecurity dashboard that monitors live threats, IOCs, CVEs, and infrastructure health. Works fully offline using mock data when the local API is unavailable.

---

## Project Structure

```
octo-palm-dashboard/
├── index.html                        ← App shell — imports CSS + JS, no inline code
│
├── src/
│   ├── css/
│   │   ├── variables.css             ← Design tokens (colours, fonts, shadows)
│   │   ├── base.css                  ← Resets, body, animations, scrollbars
│   │   ├── layout.css                ← Shell, sidebar, main area, grids, responsive
│   │   ├── components.css            ← All reusable UI components (KPI, buttons, etc.)
│   │   └── views.css                 ← View-specific layout overrides
│   │
│   └── js/
│       ├── data/
│       │   ├── mock.js               ← Mock stats + threats (demo / offline fallback)
│       │   ├── ioc.js                ← IOC seed data (IPs, domains, file hashes)
│       │   ├── cve.js                ← CVE seed data
│       │   └── geo.js                ← Geo threat origin data
│       │
│       ├── modules/
│       │   ├── api.js                ← HTTP layer — fetches from API, falls back to mock
│       │   ├── state.js              ← Single source of truth (AppState object)
│       │   ├── toast.js              ← Toast notification helper
│       │   ├── router.js             ← View switching / SPA navigation
│       │   └── clock.js              ← Live clock updater
│       │
│       ├── charts/
│       │   ├── telemetry-charts.js   ← Bar chart (24h) + Doughnut (threat types)
│       │   └── stats-charts.js       ← Line chart (weekly) + Doughnut (severity)
│       │
│       ├── views/
│       │   ├── sidebar.js            ← Sidebar HTML renderer
│       │   ├── telemetry.js          ← Live Telemetry view (KPIs, feed, ring, geo…)
│       │   ├── intelligence.js       ← Threat Intelligence view (IOC + CVE)
│       │   ├── scanner.js            ← URL Scanner view
│       │   ├── infrastructure.js     ← Infrastructure view
│       │   ├── stats.js              ← Statistics view
│       │   └── settings.js           ← Settings view
│       │
│       └── main.js                   ← Bootstrap — wires everything together
│
└── README.md
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                        index.html                        │
│   App shell — loads CSS cascade + JS modules in order   │
└─────────────────────┬────────────────────────────────────┘
                      │
        ┌─────────────▼──────────────┐
        │         main.js            │  Bootstrap
        │  render → route → fetch    │
        └──┬──────────┬──────────────┘
           │          │
    ┌──────▼──┐  ┌────▼────────────────────────────────────┐
    │ router  │  │             fetchData()                  │
    │ .js     │  │  api.js → AppState → view renderers      │
    └──┬──────┘  └────────────────────────────────────────-┘
       │
       ▼  switchView(name)
  ┌────────────────────────────────────────┐
  │             views/                     │
  │  telemetry · intelligence · scanner   │
  │  infrastructure · stats · settings    │
  └────────────────────────────────────────┘
           │ read
           ▼
  ┌────────────────┐     ┌────────────────┐
  │  state.js      │     │  data/         │
  │  AppState {}   │     │  mock · ioc    │
  │  threats       │     │  cve  · geo    │
  │  stats         │     └────────────────┘
  │  scanHistory   │
  │  activeFilter  │
  └────────────────┘
```

### Key Design Decisions

| Concern            | Solution                                                                 |
|--------------------|--------------------------------------------------------------------------|
| **State**          | Single `AppState` object in `state.js` — no frameworks, no magic        |
| **Routing**        | `switchView()` shows/hides DOM views; no URL hash needed                 |
| **Data**           | `api.js` tries real endpoints; transparent mock fallback on any failure  |
| **CSS**            | Layered cascade: tokens → base → layout → components → view overrides   |
| **Charts**         | Chart.js instances guarded against double-init across view switches      |
| **Polling**        | `setInterval(fetchData, 5000)` — simple, no WebSocket dependency        |

---

## Getting Started

Open `index.html` directly in a browser — no build step required.

To connect to a live backend, implement these two endpoints on `http://127.0.0.1:8000`:

```
GET /alerts/stats  → { total, critical, high, recent_24h, blocked_today, top_domains[] }
GET /alerts/live   → { data: Threat[] }
```

If either endpoint is unreachable the dashboard falls back to mock data automatically.
