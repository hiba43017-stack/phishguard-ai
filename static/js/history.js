/**
 * PhishGuard AI — History Page JavaScript
 * Handles:
 *   - Individual scan deletion
 *   - Clear all history with confirmation
 *   - Live row removal animation
 */

// ================================================================
// DELETE INDIVIDUAL SCAN
// ================================================================
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('.btn-delete');
  if (!btn) return;

  const scanId = btn.dataset.id;
  if (!scanId) return;

  // Confirm
  if (!confirm(`Are you sure you want to delete scan #${scanId}? This cannot be undone.`)) return;

  btn.disabled = true;
  btn.textContent = '⏳';

  try {
    const res = await fetch(`/api/history/${scanId}`, { method: 'DELETE' });
    const data = await res.json();

    if (data.success) {
      const row = document.getElementById(`row-${scanId}`);
      if (row) {
        row.style.transition = 'opacity 0.3s, transform 0.3s';
        row.style.opacity = '0';
        row.style.transform = 'translateX(20px)';
        setTimeout(() => row.remove(), 300);
      }
      showToast(data.message, 'success');
      _updateRowCount(-1);
    } else {
      showToast(data.error || 'Failed to delete scan.', 'error');
      btn.disabled = false;
      btn.textContent = '🗑️';
    }
  } catch (err) {
    showToast('Network error while deleting.', 'error');
    btn.disabled = false;
    btn.textContent = '🗑️';
  }
});


// ================================================================
// CLEAR ALL HISTORY
// ================================================================
document.getElementById('btn-clear-all')?.addEventListener('click', async () => {
  const rowCount = document.querySelectorAll('#history-table tbody tr').length;
  if (rowCount === 0) {
    showToast('History is already empty.', 'info');
    return;
  }

  const confirmed = confirm(
    `Are you absolutely sure you want to delete ALL ${rowCount} scan record(s)?\n\nThis action CANNOT be undone.`
  );
  if (!confirmed) return;

  const btn = document.getElementById('btn-clear-all');
  btn.disabled = true;
  btn.textContent = '⏳ Clearing...';

  try {
    const res = await fetch('/api/history', { method: 'DELETE' });
    const data = await res.json();

    if (data.success) {
      // Fade out all rows
      const rows = document.querySelectorAll('#history-table tbody tr');
      rows.forEach((row, i) => {
        setTimeout(() => {
          row.style.transition = 'opacity 0.3s';
          row.style.opacity = '0';
          setTimeout(() => row.remove(), 300);
        }, i * 50);
      });

      setTimeout(() => {
        // Show empty state
        const tableContainer = document.querySelector('.table-responsive');
        if (tableContainer) {
          tableContainer.innerHTML = `
            <div class="empty-state">
              <div class="empty-state-icon">📭</div>
              <h3>History Cleared</h3>
              <p>All scan records have been deleted.</p>
              <a href="/analyze" class="btn btn-primary">Analyze New Email</a>
            </div>
          `;
        }
        showToast(data.message, 'success');
        _updateRowCount(0, true);
      }, rows.length * 50 + 400);

    } else {
      showToast(data.error || 'Failed to clear history.', 'error');
    }
  } catch (err) {
    showToast('Network error while clearing history.', 'error');
  } finally {
    btn.textContent = '🗑️ Clear All History';
    // btn stays disabled since there's nothing left to clear
  }
});


// ================================================================
// HELPER: Update row count display
// ================================================================
function _updateRowCount(delta, reset = false) {
  const countEl = document.querySelector('[data-count]') ||
    document.evaluate(
      "//span[contains(text(),'record')]",
      document,
      null,
      XPathResult.FIRST_ORDERED_NODE_TYPE,
      null
    ).singleNodeValue;

  if (!countEl) return;
  if (reset) {
    countEl.textContent = '0 record(s) found';
    return;
  }
  const match = countEl.textContent.match(/\d+/);
  if (match) {
    const current = parseInt(match[0], 10);
    const newCount = Math.max(0, current + delta);
    countEl.textContent = `${newCount} record(s) found`;
  }
}


// ================================================================
// LIVE SEARCH (debounced)
// ================================================================
let _searchTimeout = null;
const searchInput = document.getElementById('search-input');
searchInput?.addEventListener('input', () => {
  clearTimeout(_searchTimeout);
  _searchTimeout = setTimeout(() => {
    document.getElementById('search-form')?.submit();
  }, 600);
});
