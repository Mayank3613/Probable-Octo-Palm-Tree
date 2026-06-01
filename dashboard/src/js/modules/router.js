/* ─── ROUTER MODULE ──────────────────────────────────────────────────────────
   Handles single-page navigation between named views.
   Views are DOM elements with id="view-<name>".
─────────────────────────────────────────────────────────────────────────── */

const VIEWS = ['telemetry', 'intelligence', 'scan', 'infrastructure', 'stats', 'settings'];

/**
 * Switch to a named view and activate the corresponding sidebar button.
 * @param {string}          viewName
 * @param {HTMLElement|null} btn       – the sidebar button that triggered the switch
 */
function switchView(viewName, btn) {
  // Hide all views
  VIEWS.forEach(id => {
    const el = document.getElementById(`view-${id}`);
    if (el) el.style.display = 'none';
  });

  // Show the target view
  const target = document.getElementById(`view-${viewName}`);
  if (target) target.style.display = '';

  // Update active state on sidebar items
  document.querySelectorAll('.sb-item').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');

  // Trigger view-specific init
  if (viewName === 'intelligence') {
    renderIOC('ip');
    renderCVEs();
  }
  if (viewName === 'stats')          initStatsCharts();
  if (viewName === 'infrastructure') renderEndpoints();
}
