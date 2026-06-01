/* ─── TELEMETRY CHARTS ───────────────────────────────────────────────────────
   Bar chart: threats-over-time (24 h)
   Doughnut:  threat-type breakdown

   Guards prevent re-initialisation if the canvas already has a Chart instance.
─────────────────────────────────────────────────────────────────────────── */

let chartTime  = null;
let chartTypes = null;

function initCharts() {
  // ── Threats Over Time (bar) ───────────────────────────────────────────────
  const ctCtx = document.getElementById('chart-time');
  if (ctCtx && !chartTime) {
    const labels = ['00','02','04','06','08','10','12','14','16','18','20','22'];
    const data   = [2, 1, 4, 8, 3, 12, 18, 14, 9, 22, 16, 11];

    chartTime = new Chart(ctCtx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label:           'Threats',
          data,
          backgroundColor: 'rgba(16,185,129,.35)',
          borderColor:     'rgba(16,185,129,.7)',
          borderWidth:     1,
          borderRadius:    3,
        }],
      },
      options: {
        responsive:          true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: 'rgba(255,255,255,.04)' }, ticks: { color: '#6b7280', font: { family: 'monospace', size: 10 } } },
          y: { grid: { color: 'rgba(255,255,255,.04)' }, ticks: { color: '#6b7280', font: { family: 'monospace', size: 10 } } },
        },
      },
    });
  }

  // ── Threat Type Breakdown (doughnut) ─────────────────────────────────────
  const cpCtx = document.getElementById('chart-types');
  if (cpCtx && !chartTypes) {
    chartTypes = new Chart(cpCtx, {
      type: 'doughnut',
      data: {
        labels:   ['Phishing', 'Malware', 'Tracking', 'Credential', 'Drive-by'],
        datasets: [{
          data:            [38, 24, 18, 12, 8],
          backgroundColor: [
            'rgba(239,68,68,.7)', 'rgba(139,92,246,.7)',
            'rgba(245,158,11,.7)','rgba(59,130,246,.7)',
            'rgba(16,185,129,.7)',
          ],
          borderColor: [
            'rgba(239,68,68,1)','rgba(139,92,246,1)',
            'rgba(245,158,11,1)','rgba(59,130,246,1)',
            'rgba(16,185,129,1)',
          ],
          borderWidth: 1,
        }],
      },
      options: {
        responsive:          true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#9ca3af', font: { family: 'monospace', size: 10 }, boxWidth: 10, padding: 8 },
          },
        },
        cutout: '65%',
      },
    });
  }
}
