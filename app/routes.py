"""
PhishGuard AI - Flask Routes
All HTTP endpoints for the web application.
"""
import logging
from flask import (
    Blueprint, render_template, request, jsonify,
    current_app, redirect, url_for, abort
)

from .database import (
    get_dashboard_stats, get_all_scans, get_scan_by_id,
    save_scan, delete_scan, clear_all_scans, search_scans
)
from .services.validation import validate_email_input, sanitize_text
from .services.phishing_detector import analyze_email
from .services.ollama_service import analyze_with_ollama, check_ollama_status
from .services.scoring import calculate_score

logger = logging.getLogger(__name__)
main_bp = Blueprint('main', __name__)


# -------------------------------------------------------------------
# Helper: get DB path from current app config
# -------------------------------------------------------------------
def _db() -> str:
    return current_app.config['DATABASE_PATH']


def _ollama_cfg() -> dict:
    return {
        'base_url': current_app.config['OLLAMA_BASE_URL'],
        'model': current_app.config['OLLAMA_MODEL'],
        'timeout': current_app.config['OLLAMA_TIMEOUT'],
    }


# ===================================================================
# PAGE ROUTES
# ===================================================================

@main_bp.route('/')
def dashboard():
    """Main dashboard with live statistics from the database."""
    stats = get_dashboard_stats(_db())
    ollama_cfg = _ollama_cfg()
    ollama_status = check_ollama_status(ollama_cfg['base_url'], timeout=3)
    return render_template(
        'dashboard.html',
        stats=stats,
        ollama_status=ollama_status,
        ollama_model=ollama_cfg['model'],
        active_page='dashboard'
    )


@main_bp.route('/analyze', methods=['GET'])
def analyze():
    """Email analysis input page."""
    # Pre-fill with a sample phishing email for demonstration
    sample = {
        'sender': 'security-alert@paypa1-support.com',
        'subject': 'URGENT: Your PayPal account has been suspended!',
        'body': (
            "Dear Customer,\n\n"
            "We have detected UNAUTHORIZED ACCESS to your PayPal account. "
            "Your account has been temporarily suspended for your protection.\n\n"
            "To restore your account, you must verify your information IMMEDIATELY "
            "by clicking the link below:\n\n"
            "http://paypal-verify.xyz/restore?token=abc123\n\n"
            "Failure to verify within 24 hours will result in PERMANENT account closure.\n\n"
            "Enter your password and banking details to confirm your identity.\n\n"
            "PayPal Security Team"
        )
    }
    return render_template('analyze.html', sample=sample, active_page='analyze')


@main_bp.route('/results/<int:scan_id>')
def results(scan_id: int):
    """Display results for a specific scan by its database ID."""
    scan = get_scan_by_id(_db(), scan_id)
    if not scan:
        abort(404)
    return render_template('results.html', scan=scan, active_page='analyze')


@main_bp.route('/history')
def history():
    """Scan history page with search and filter."""
    query = request.args.get('q', '').strip()
    risk_level = request.args.get('level', '').strip().upper()

    if query or risk_level:
        scans = search_scans(_db(), query=query, risk_level=risk_level)
    else:
        scans = get_all_scans(_db(), limit=200)

    return render_template(
        'history.html',
        scans=scans,
        query=query,
        risk_level=risk_level,
        active_page='history'
    )


@main_bp.route('/about')
def about():
    """About page with project information."""
    return render_template('about.html', active_page='about')


@main_bp.route('/settings')
def settings():
    """Settings page."""
    cfg = _ollama_cfg()
    ollama_status = check_ollama_status(cfg['base_url'], timeout=3)
    stats = get_dashboard_stats(_db())
    return render_template(
        'settings.html',
        ollama_status=ollama_status,
        ollama_cfg=cfg,
        stats=stats,
        active_page='settings'
    )


# ===================================================================
# API ROUTES
# ===================================================================

@main_bp.route('/api/analyze', methods=['POST'])
def api_analyze():
    """
    AJAX endpoint for email analysis.
    Expects JSON body: {sender, subject, body}
    Returns JSON with analysis results or error.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'success': False, 'error': 'Invalid request format.'}), 400

    sender  = sanitize_text(data.get('sender', ''), 254)
    subject = sanitize_text(data.get('subject', ''), 998)
    body    = sanitize_text(data.get('body', ''), 50_000)

    # --- Step 1: Validate inputs ---
    is_valid, errors = validate_email_input(sender, subject, body)
    if not is_valid:
        return jsonify({'success': False, 'errors': errors}), 422

    # --- Step 2: Rule-based detection ---
    try:
        rule_result_obj = analyze_email(sender, subject, body)
        rule_result = rule_result_obj.to_dict()
    except Exception as e:
        logger.error("Rule engine error: %s", e)
        return jsonify({'success': False, 'error': 'Detection engine error.'}), 500

    # --- Step 3: AI Analysis (Ollama) ---
    cfg = _ollama_cfg()
    try:
        ai_result = analyze_with_ollama(
            sender=sender,
            subject=subject,
            body=body,
            base_url=cfg['base_url'],
            model=cfg['model'],
            timeout=cfg['timeout']
        )
    except Exception as e:
        logger.warning("Ollama call failed unexpectedly: %s", e)
        ai_result = {'success': False, 'data': None, 'error': str(e)}

    # --- Step 4: Calculate combined score ---
    try:
        score_result = calculate_score(rule_result, ai_result)
    except Exception as e:
        logger.error("Scoring error: %s", e)
        return jsonify({'success': False, 'error': 'Scoring engine error.'}), 500

    # --- Step 5: Save to database ---
    scan_data = {
        'sender': sender,
        'subject': subject,
        'body': body[:5000],        # Store truncated body
        'risk_score': score_result.final_score,
        'risk_level': score_result.risk_level,
        'verdict': score_result.verdict,
        'ai_verdict': score_result.ai_verdict,
        'ai_confidence': score_result.ai_confidence,
        'rule_score': score_result.rule_score,
        'ai_score': score_result.ai_score,
        'indicators': score_result.indicators,
        'evidence': score_result.evidence,
        'reasons': score_result.reasons,
        'recommended_actions': score_result.recommended_actions,
        'ai_explanation': score_result.explanation,
        'ollama_used': score_result.ollama_used,
    }

    try:
        scan_id = save_scan(_db(), scan_data)
    except Exception as e:
        logger.error("Database save error: %s", e)
        scan_id = None

    # Build response
    result_dict = score_result.to_dict()
    result_dict['scan_id'] = scan_id
    result_dict['ai_error'] = ai_result.get('error') if not ai_result.get('success') else None

    return jsonify({'success': True, 'result': result_dict})


@main_bp.route('/api/ollama-status')
def api_ollama_status():
    """Real-time Ollama connection check (used by settings page)."""
    cfg = _ollama_cfg()
    status = check_ollama_status(cfg['base_url'], timeout=5)
    return jsonify(status)


@main_bp.route('/api/history/<int:scan_id>', methods=['DELETE'])
def api_delete_scan(scan_id: int):
    """Delete a single scan record."""
    deleted = delete_scan(_db(), scan_id)
    if deleted:
        return jsonify({'success': True, 'message': f'Scan #{scan_id} deleted.'})
    return jsonify({'success': False, 'error': 'Scan not found.'}), 404


@main_bp.route('/api/history', methods=['DELETE'])
def api_clear_history():
    """Clear all scan history."""
    count = clear_all_scans(_db())
    return jsonify({'success': True, 'message': f'{count} scan(s) deleted.'})


@main_bp.route('/api/stats')
def api_stats():
    """Dashboard statistics (used by dashboard charts)."""
    stats = get_dashboard_stats(_db())
    return jsonify(stats)


# ===================================================================
# Error Handlers
# ===================================================================

@main_bp.app_errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


@main_bp.app_errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500
