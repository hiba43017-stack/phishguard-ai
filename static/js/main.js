/**
 * PhishGuard AI — Main JavaScript
 * Global utilities used across all pages:
 *   - Live clock
 *   - Toast notifications
 *   - Loading overlay controller
 */

// ================================================================
// LIVE CLOCK
// ================================================================
function updateClock() {
  const el = document.getElementById('live-clock');
  if (!el) return;
  const now = new Date();
  el.textContent = now.toLocaleTimeString('en-IN', {
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
}
updateClock();
setInterval(updateClock, 1000);


// ================================================================
// TOAST NOTIFICATIONS
// ================================================================
/**
 * Show a toast notification.
 * @param {string} message - Message text
 * @param {'success'|'error'|'info'} type - Toast type
 * @param {number} duration - Auto-dismiss duration in ms (default 4000)
 */
function showToast(message, type = 'info', duration = 4000) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const icons = { success: '✅', error: '❌', info: 'ℹ️' };
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <span style="font-size:1rem;flex-shrink:0;">${icons[type] || 'ℹ️'}</span>
    <span style="flex:1;">${escapeHtml(message)}</span>
    <button onclick="this.parentElement.remove()"
            style="background:none;border:none;cursor:pointer;padding:0 4px;
                   color:var(--text-muted);font-size:1rem;">✕</button>
  `;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), duration);
}

/**
 * Escape HTML special characters to prevent XSS.
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  const d = document.createElement('div');
  d.textContent = String(str);
  return d.innerHTML;
}


// ================================================================
// LOADING OVERLAY
// ================================================================
const LOADING_STEPS = [
  'Initializing detection engine...',
  'Running rule-based checks...',
  'Checking URLs and patterns...',
  'Analyzing urgency language...',
  'Sending to AI model (Ollama)...',
  'Waiting for AI response...',
  'Calculating risk score...',
  'Saving to database...',
];

let _loadingInterval = null;
let _loadingStepIndex = 0;

function showLoading() {
  const overlay = document.getElementById('loading-overlay');
  if (!overlay) return;
  overlay.classList.add('active');
  _loadingStepIndex = 0;
  _updateLoadingStep();
  _loadingInterval = setInterval(() => {
    _loadingStepIndex = (_loadingStepIndex + 1) % LOADING_STEPS.length;
    _updateLoadingStep();
  }, 2500);
}

function hideLoading() {
  const overlay = document.getElementById('loading-overlay');
  if (!overlay) return;
  overlay.classList.remove('active');
  if (_loadingInterval) {
    clearInterval(_loadingInterval);
    _loadingInterval = null;
  }
}

function _updateLoadingStep() {
  const el = document.getElementById('loading-step-text');
  if (el) el.textContent = LOADING_STEPS[_loadingStepIndex];
}


// ================================================================
// ACCORDION
// ================================================================
document.addEventListener('click', (e) => {
  const header = e.target.closest('.accordion-header');
  if (!header) return;
  const content = header.nextElementSibling;
  if (!content || !content.classList.contains('accordion-content')) return;
  const chevron = header.querySelector('.accordion-chevron');
  content.classList.toggle('open');
  if (chevron) chevron.textContent = content.classList.contains('open') ? '▲' : '▼';
});


// ================================================================
// ANIMATE NUMBERS (counter animation for stat cards)
// ================================================================
function animateNumber(el, target, duration = 800) {
  if (!el) return;
  const start = 0;
  const startTime = performance.now();
  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    // Ease out
    const value = Math.round(start + (target - start) * (1 - Math.pow(1 - progress, 3)));
    el.textContent = value;
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

// Animate stat cards on page load
window.addEventListener('load', () => {
  ['stat-total', 'stat-safe', 'stat-suspicious', 'stat-malicious'].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      const target = parseInt(el.textContent, 10);
      if (!isNaN(target) && target > 0) animateNumber(el, target);
    }
  });
});
