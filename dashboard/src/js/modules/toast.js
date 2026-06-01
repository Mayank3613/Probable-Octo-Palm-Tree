/* ─── TOAST MODULE ───────────────────────────────────────────────────────────
   Displays a transient notification at the bottom-right of the screen.
   Auto-dismisses after 3 seconds.
─────────────────────────────────────────────────────────────────────────── */

let _toastTimer = null;

/**
 * Show a toast message.
 * @param {string} msg
 */
function toast(msg) {
  const el = document.getElementById('toast-msg');
  if (!el) return;

  el.textContent = msg;
  el.classList.remove('hidden');

  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.add('hidden'), 3000);
}
