/* ─── STATS CHARTS ───────────────────────────────────────────────────────────
   Line chart:  weekly threat trend (Threats vs Blocked)
   Doughnut:    severity distribution

   Called by the router when the Statistics view is activated.
─────────────────────────────────────────────────────────────────────────── */

let chartWeekly = null;
let chartSev    = null;

function initStatsCharts() {
  // Small delay to ensure the canvas is visible before Chart.js measures it
  setTimeout(() => {
    // ── Weekly Threat Trend (line) ──────────────────────────────────────────
    const wCtx = document.getElementById('chart-weekly');
    if (wCtx && !chartWeekly) {
      chartWeekly = new Chart(wCtx, {
        type: 'line',
        data: {
          labels:   ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
          datasets: [
            {
              label:           'Threats',
              data:            [18, 25, 32, 14, 42, 28, 35],
              borderColor:     'rgba(16,185,129,.8)',
              backgroundColor: 'rgba(16,185,129,.08)',
              tension:         0.4,
              fill:            true,
              pointRadius:     3,
            },
            {
              label:           'Blocked',
              data:            [15, 22, 28, 12, 38, 24, 31],
              borderColor:     'rgba(59,130,246,.7)',
              backgroundColor: 'rgba(59,130,246,.05)',
              tension:         0.4,
              fill:            true,
              pointRadius:     3,
            },
          ],
        },
        options: {
          responsive:          true,
          maintainAspectRatio: false,
          plugins: { legend: { labels: { color: '#9ca3af', font: { family: 'monospace', size: 10 } } } },
          scales: {
            x: { grid: { color: 'rgba(255,255,255,.04)' }, ticks: { color: '#6b7280', font: { family: 'monospace', size: 10 } } },
            y: { grid: { color: 'rgba(255,255,255,.04)' }, ticks: { color: '#6b7280', font: { family: 'monospace', size: 10 } } },
          },
        },
      });
    }

    // ── Severity Distribution (doughnut) ────────────────────────────────────
    const sCtx = document.getElementById('chart-sev');
    if (sCtx && !chartSev) {
      chartSev = new Chart(sCtx, {
        type: 'doughnut',
        data: {
          labels:   ['Critical', 'High', 'Medium'],
          datasets: [{
            data:            [8, 34, 85],
            backgroundColor: ['rgba(239,68,68,.7)', 'rgba(245,158,11,.7)', 'rgba(16,185,129,.6)'],
            borderColor:     ['rgba(239,68,68,1)',   'rgba(245,158,11,1)',  'rgba(16,185,129,1)'],
            borderWidth:     1,
          }],
        },
        options: {
          responsive:          true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: { color: '#9ca3af', font: { family: 'monospace', size: 10 }, boxWidth: 10 },
            },
          },
          cutout: '60%',
        },
      });
    }
  }, 200);
}
