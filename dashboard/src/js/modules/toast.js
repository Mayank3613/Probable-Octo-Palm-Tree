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

function showToast(title, message, type = "info") {
    const t = document.createElement("div");
    t.className = `toast-custom toast-${type}`;
    t.innerHTML = `
      <strong>${title}</strong>
      <span style="display:block;margin-top:2px;font-size:12px;opacity:0.8">${message}</span>`;

    let container = document.getElementById("toast-container");
    if (!container) {
        container = document.createElement("div");
        container.id = "toast-container";
        document.body.appendChild(container);
    }
    container.appendChild(t);

    setTimeout(() => t.classList.add("toast-visible"),   10);
    setTimeout(() => t.classList.remove("toast-visible"), 4000);
    setTimeout(() => t.remove(),                          4400);
}
