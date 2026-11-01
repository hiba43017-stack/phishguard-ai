"""
PhishGuard AI — Regression Tests for Results Page and End-to-End Analysis
Verifies submitting an email, saving to database, and rendering /results/<id>
without any 'TypeError: int object is not iterable' or template errors.
"""
import pytest
import tempfile
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.database import init_db, save_scan, get_scan_by_id


@pytest.fixture
def test_app():
    """Create a Flask test application with an isolated temporary SQLite database."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        db_path = tmp.name

    init_db(db_path)

    test_config = {
        'TESTING': True,
        'DATABASE_PATH': db_path,
        'OLLAMA_BASE_URL': 'http://localhost:11434',
        'OLLAMA_MODEL': 'llama3.2:3b',
        'OLLAMA_TIMEOUT': 5,
        'SECRET_KEY': 'test-secret',
    }

    app = create_app(test_config)
    yield app

    # Cleanup temp database
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass


@pytest.fixture
def client(test_app):
    """Test client fixture."""
    return test_app.test_client()


class TestResultsPageRegression:

    def test_sample_email_submit_and_view_results(self, client):
        """
        Regression test:
        1. Submit the sample phishing email via POST /api/analyze.
        2. Ensure a scan_id is returned.
        3. Request GET /results/<scan_id>.
        4. Ensure HTTP 200 and no 'TypeError: int object is not iterable'.
        """
        sample_payload = {
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

        # Step 1: Submit email
        response = client.post('/api/analyze', json=sample_payload)
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        scan_id = data['result']['scan_id']
        assert scan_id is not None
        assert isinstance(scan_id, int)

        # Step 2: Open the results page
        res_page = client.get(f'/results/{scan_id}')
        assert res_page.status_code == 200
        html = res_page.get_data(as_text=True)

        # Verify page content renders properly
        assert "Analysis Results" in html
        assert "Score Breakdown" in html
        assert "Rule Engine" in html
        assert "Final Score" in html
        assert "security-alert@paypa1-support.com" in html
        assert "URGENT: Your PayPal account has been suspended!" in html
        assert "Detected Indicators" in html

        # Verify no Jinja traceback or error keywords
        assert "TypeError" not in html
        assert "not iterable" not in html

    def test_safe_email_results_page(self, client):
        """Test submitting a legitimate email and viewing its results page."""
        safe_payload = {
            'sender': 'team@company.com',
            'subject': 'Team Standup at 10 AM',
            'body': 'Hi everyone, just a reminder that our daily standup is at 10 AM today in Room 3.'
        }

        response = client.post('/api/analyze', json=safe_payload)
        assert response.status_code == 200
        scan_id = response.get_json()['result']['scan_id']

        res_page = client.get(f'/results/{scan_id}')
        assert res_page.status_code == 200
        html = res_page.get_data(as_text=True)
        assert "Analysis Results" in html
        assert "Safe" in html

    def test_results_page_with_direct_db_insert(self, test_app, client):
        """
        Test rendering a results page with various integer edge cases directly
        inserted into SQLite (e.g. legacy scans where rule_score/ai_score might be 0).
        """
        db_path = test_app.config['DATABASE_PATH']
        scan_data = {
            'sender': 'phish@example.xyz',
            'subject': 'Immediate Action Required',
            'body': 'Click http://evil.xyz/login to verify your password.',
            'risk_score': 75,
            'risk_level': 'CRITICAL',
            'verdict': 'Malicious',
            'ai_verdict': 'Malicious',
            'ai_confidence': 90,
            'rule_score': 50,
            'ai_score': 25,
            'indicators': [
                {'name': 'URGENCY_LANGUAGE', 'description': 'Urgent language detected', 'points': 10, 'evidence': 'Immediate'},
                {'name': 'SUSPICIOUS_TLD', 'description': 'Suspicious TLD .xyz', 'points': 10, 'evidence': '.xyz'},
            ],
            'evidence': ['Immediate Action Required', 'http://evil.xyz/login'],
            'reasons': ['Contains urgent threats', 'Links to unverified domain'],
            'recommended_actions': ['Do not click links', 'Report email to IT'],
            'ai_explanation': 'This email exhibits high risk indicators typical of phishing attacks.',
            'ollama_used': True,
        }

        scan_id = save_scan(db_path, scan_data)
        assert scan_id > 0

        res_page = client.get(f'/results/{scan_id}')
        assert res_page.status_code == 200
        html = res_page.get_data(as_text=True)
        assert "CRITICAL" in html
        assert "75/100" in html
        assert "50/60" in html
        assert "25/40" in html

    def test_results_page_without_ai(self, test_app, client):
        """Test results page when Ollama was not used (ai_confidence is None)."""
        db_path = test_app.config['DATABASE_PATH']
        scan_data = {
            'sender': 'alert@bank-update.xyz',
            'subject': 'Account Alert',
            'body': 'Your account is locked.',
            'risk_score': 40,
            'risk_level': 'MEDIUM',
            'verdict': 'Suspicious',
            'ai_verdict': None,
            'ai_confidence': None,
            'rule_score': 40,
            'ai_score': 0,
            'indicators': [
                {'name': 'URGENCY_LANGUAGE', 'description': 'Urgency', 'points': 10, 'evidence': 'locked'}
            ],
            'evidence': ['account is locked'],
            'reasons': [],
            'recommended_actions': ['Verify sender'],
            'ai_explanation': 'Rule-based evaluation flagged moderate risk.',
            'ollama_used': False,
        }

        scan_id = save_scan(db_path, scan_data)
        res_page = client.get(f'/results/{scan_id}')
        assert res_page.status_code == 200
        html = res_page.get_data(as_text=True)
        assert "Rule-Based Only" in html
        assert "40/60" in html

    def test_nonexistent_scan_returns_404(self, client):
        """Opening a scan that does not exist should return 404 Not Found."""
        res = client.get('/results/999999')
        assert res.status_code == 404
        assert "404" in res.get_data(as_text=True)
