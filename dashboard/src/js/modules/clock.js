/* ─── CLOCK MODULE ───────────────────────────────────────────────────────────
   Updates the live timestamp shown in the alert banner.
─────────────────────────────────────────────────────────────────────────── */

function updateClock() {
  const el = document.getElementById('alert-clock');
  if (el) {
    el.textContent = new Date().toLocaleTimeString([], {
      hour:   '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  }
}
