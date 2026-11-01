/**
 * PhishGuard AI — Analyze Page JavaScript
 * Handles:
 *   - Real-time form validation
 *   - Character counter
 *   - Sample email loading
 *   - AJAX form submission to /api/analyze
 *   - Result redirect
 */

// ================================================================
// ELEMENTS
// ================================================================
const form       = document.getElementById('analyze-form');
const senderEl   = document.getElementById('sender');
const subjectEl  = document.getElementById('subject');
const bodyEl     = document.getElementById('body');
const charCount  = document.getElementById('char-count');
const analyzeBtn = document.getElementById('btn-analyze');
const btnText    = document.getElementById('analyze-btn-text');
const btnIcon    = document.getElementById('analyze-btn-icon');
const errorPanel = document.getElementById('error-panel');
const errorMsg   = document.getElementById('error-message');

// Sample phishing email (same as Flask default, kept in JS for Clear action)
const SAMPLE_EMAIL = {
  sender: 'security-alert@paypa1-support.com',
  subject: 'URGENT: Your PayPal account has been suspended!',
  body: `Dear Customer,

We have detected UNAUTHORIZED ACCESS to your PayPal account. Your account has been temporarily suspended for your protection.

To restore your account, you must verify your information IMMEDIATELY by clicking the link below:

http://paypal-verify.xyz/restore?token=abc123

Failure to verify within 24 hours will result in PERMANENT account closure.

Enter your password and banking details to confirm your identity.

PayPal Security Team`
};

// ================================================================
// CHARACTER COUNTER
// ================================================================
function updateCharCount() {
  if (charCount && bodyEl) {
    const len = bodyEl.value.length;
    charCount.textContent = len.toLocaleString();
    charCount.style.color = len > 45000
      ? 'var(--high-color)'
      : len > 49000
        ? 'var(--critical-color)'
        : '';
  }
}

bodyEl?.addEventListener('input', updateCharCount);
updateCharCount(); // Run on page load to handle pre-filled sample

// ================================================================
// FORM FIELD VALIDATION
// ================================================================
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/i;
const DISPLAY_EMAIL_RE = /^.+<[^@\s]+@[^@\s]+\.[^@\s]+>\s*$/i;

function showFieldError(fieldId, message) {
  const field = document.getElementById(fieldId);
  const errorEl = document.getElementById(`${fieldId}-error`);
  if (field) field.classList.add('error');
  if (errorEl) {
    errorEl.textContent = message;
    errorEl.style.display = 'block';
  }
}

function clearFieldError(fieldId) {
  const field = document.getElementById(fieldId);
  const errorEl = document.getElementById(`${fieldId}-error`);
  if (field) field.classList.remove('error');
  if (errorEl) {
    errorEl.textContent = '';
    errorEl.style.display = 'none';
  }
}

function clearAllErrors() {
  ['sender', 'subject', 'body'].forEach(clearFieldError);
  if (errorPanel) errorPanel.classList.add('hidden');
}

function validateForm() {
  clearAllErrors();
  let valid = true;
  const sender  = senderEl?.value.trim() || '';
  const subject = subjectEl?.value.trim() || '';
  const body    = bodyEl?.value.trim() || '';

  if (!sender) {
    showFieldError('sender', 'Sender email address is required.');
    valid = false;
  } else if (!EMAIL_RE.test(sender) && !DISPLAY_EMAIL_RE.test(sender)) {
    showFieldError('sender', 'Please enter a valid email address (or "Name <email@domain.com>" format).');
    valid = false;
  }

  if (!subject) {
    showFieldError('subject', 'Email subject is required.');
    valid = false;
  }

  if (!body) {
    showFieldError('body', 'Email body is required.');
    valid = false;
  } else if (body.length < 5) {
    showFieldError('body', 'Email body is too short.');
    valid = false;
  } else if (body.length > 50000) {
    showFieldError('body', `Body is too long (${body.length.toLocaleString()} chars). Max: 50,000.`);
    valid = false;
  }

  return valid;
}

// Live validation on blur
senderEl?.addEventListener('blur', () => {
  const v = senderEl.value.trim();
  if (v && !EMAIL_RE.test(v) && !DISPLAY_EMAIL_RE.test(v)) {
    showFieldError('sender', 'Please enter a valid email address.');
  } else {
    clearFieldError('sender');
  }
});

subjectEl?.addEventListener('blur', () => {
  if (!subjectEl.value.trim()) {
    showFieldError('subject', 'Subject is required.');
  } else {
    clearFieldError('subject');
  }
});

// ================================================================
// SAMPLE EMAIL LOADER
// ================================================================
document.getElementById('btn-load-sample')?.addEventListener('click', () => {
  if (senderEl)  senderEl.value  = SAMPLE_EMAIL.sender;
  if (subjectEl) subjectEl.value = SAMPLE_EMAIL.subject;
  if (bodyEl)    bodyEl.value    = SAMPLE_EMAIL.body;
  updateCharCount();
  clearAllErrors();
  showToast('Sample phishing email loaded!', 'info');
});

// ================================================================
// CLEAR BUTTON
// ================================================================
document.getElementById('btn-clear')?.addEventListener('click', () => {
  if (senderEl)  senderEl.value  = '';
  if (subjectEl) subjectEl.value = '';
  if (bodyEl)    bodyEl.value    = '';
  updateCharCount();
  clearAllErrors();
});

// ================================================================
// FORM SUBMISSION (AJAX)
// ================================================================
form?.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!validateForm()) return;

  // Disable button + show loading
  analyzeBtn.disabled = true;
  btnText.textContent = 'Analyzing...';
  btnIcon.textContent = '⏳';
  showLoading();

  const payload = {
    sender:  senderEl.value.trim(),
    subject: subjectEl.value.trim(),
    body:    bodyEl.value.trim(),
  };

  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const data = await response.json();

    if (!response.ok || !data.success) {
      // Show validation errors inline
      if (data.errors && Array.isArray(data.errors)) {
        hideLoading();
        data.errors.forEach(err => {
          if (err.toLowerCase().includes('sender')) showFieldError('sender', err);
          else if (err.toLowerCase().includes('subject')) showFieldError('subject', err);
          else if (err.toLowerCase().includes('body')) showFieldError('body', err);
        });
        showGlobalError(data.errors.join(' '));
      } else {
        hideLoading();
        showGlobalError(data.error || 'Analysis failed. Please try again.');
      }
      return;
    }

    const result = data.result;

    // Show AI warning if Ollama was unavailable
    if (result.ai_error) {
      showToast(
        `AI analysis unavailable: ${result.ai_error}. Score is rule-based only.`,
        'info',
        6000
      );
    }

    hideLoading();

    // Redirect to results page
    if (result.scan_id) {
      window.location.href = `/results/${result.scan_id}`;
    } else {
      showGlobalError('Analysis completed but could not save result. Check server logs.');
    }

  } catch (err) {
    hideLoading();
    showGlobalError('Network error: Could not reach the server. Is the Flask app running?');
    console.error('Analysis error:', err);
  } finally {
    analyzeBtn.disabled = false;
    btnText.textContent = 'Analyze Email';
    btnIcon.textContent = '🚀';
  }
});

function showGlobalError(message) {
  if (errorPanel && errorMsg) {
    errorMsg.textContent = message;
    errorPanel.classList.remove('hidden');
    errorPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}
