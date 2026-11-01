"""
PhishGuard AI — Tests: Rule-Based Phishing Detection Engine
Tests cover clearly phishing emails, legitimate emails, ambiguous cases,
and edge inputs like malformed/oversized content.
"""
import pytest
import sys
import os

# Ensure the project root is in the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.phishing_detector import analyze_email, DetectionResult


# ================================================================
# Helper
# ================================================================
def get_indicator_names(result: DetectionResult) -> set:
    return {ind.name for ind in result.indicators}


# ================================================================
# CLEARLY PHISHING EMAILS
# ================================================================

class TestClearlyPhishingEmails:

    def test_classic_paypal_phishing(self):
        """Classic PayPal credential harvesting email."""
        result = analyze_email(
            sender='security@paypa1-support.com',
            subject='URGENT: Your account has been suspended!',
            body=(
                'Dear Customer, your PayPal account is SUSPENDED. '
                'Click http://paypal-verify.xyz/login to verify your password immediately. '
                'Failure to act within 24 hours will result in permanent closure.'
            )
        )
        assert result.rule_score > 0
        assert len(result.indicators) >= 2
        # Should detect urgency and URL
        names = get_indicator_names(result)
        assert 'URGENCY_LANGUAGE' in names or 'SUSPICIOUS_TLD' in names

    def test_credential_harvesting_email(self):
        """Email explicitly requesting password and OTP."""
        result = analyze_email(
            sender='admin@mybank-security.ml',
            subject='Verify your account',
            body='Please enter your password and OTP to confirm your identity.'
        )
        names = get_indicator_names(result)
        assert 'CREDENTIAL_REQUEST' in names
        assert result.rule_score > 10

    def test_payment_lure_email(self):
        """Email with financial lure / prize notification."""
        result = analyze_email(
            sender='winner@lottery-global.tk',
            subject='You have won $1,000,000!',
            body=(
                'Congratulations! You have won our lottery. '
                'Click here to pay a small processing fee and claim your prize. '
                'Wire transfer required within 48 hours.'
            )
        )
        names = get_indicator_names(result)
        assert 'PAYMENT_LURE' in names
        assert result.rule_score > 15

    def test_ip_url_phishing(self):
        """Email with IP-based URL (common in phishing)."""
        result = analyze_email(
            sender='noreply@gmail.com',
            subject='Account Verification',
            body='Click here to verify: http://192.168.1.100/verify?token=abc123'
        )
        names = get_indicator_names(result)
        assert 'IP_BASED_URL' in names

    def test_url_shortener_phishing(self):
        """Email using URL shortener to hide real destination."""
        result = analyze_email(
            sender='support@service.com',
            subject='Click to claim',
            body='Your reward is ready! Visit: https://bit.ly/3xK9pQr'
        )
        names = get_indicator_names(result)
        assert 'URL_SHORTENER' in names

    def test_brand_impersonation_with_domain_mismatch(self):
        """Email claiming to be from PayPal but sender is from Gmail."""
        result = analyze_email(
            sender='paypal.security@gmail.com',
            subject='PayPal security alert',
            body='Your PayPal account requires immediate verification.'
        )
        names = get_indicator_names(result)
        # Should detect brand impersonation or domain mismatch
        assert 'BRAND_DOMAIN_MISMATCH' in names or 'BRAND_IMPERSONATION' in names

    def test_sensitive_info_request(self):
        """Email requesting SSN and bank account number."""
        result = analyze_email(
            sender='irs-refund@irs.government.ml',
            subject='IRS Tax Refund Verification Required',
            body=(
                'To process your refund, please provide your Social Security Number '
                'and bank account number at your earliest convenience.'
            )
        )
        names = get_indicator_names(result)
        assert 'SENSITIVE_INFO_REQUEST' in names
        assert result.rule_score >= 15

    def test_all_caps_subject(self):
        """Email with ALL CAPS subject line."""
        result = analyze_email(
            sender='alerts@bank.com',
            subject='ACCOUNT SUSPENDED IMMEDIATELY',
            body='Your account has been locked. Please verify.'
        )
        names = get_indicator_names(result)
        assert 'ALL_CAPS_SUBJECT' in names

    def test_suspicious_tld(self):
        """Email with a link using a phishing-prone TLD (.xyz, .tk, etc.)."""
        result = analyze_email(
            sender='info@company.com',
            subject='Important update',
            body='Please update your account: https://bank-secure.xyz/update'
        )
        names = get_indicator_names(result)
        assert 'SUSPICIOUS_TLD' in names


# ================================================================
# LEGITIMATE EMAILS
# ================================================================

class TestLegitimateEmails:

    def test_simple_meeting_invite(self):
        """Legitimate internal meeting email."""
        result = analyze_email(
            sender='manager@company.com',
            subject='Team Meeting — Thursday 3 PM',
            body='Hi team, please join us for the weekly sync on Thursday at 3 PM in Room 204.'
        )
        assert result.rule_score == 0
        assert len(result.indicators) == 0

    def test_newsletter_email(self):
        """Standard company newsletter with legitimate URLs."""
        result = analyze_email(
            sender='newsletter@techcrunch.com',
            subject='This week in tech',
            body=(
                'Hello! Here are the top stories this week:\n\n'
                '- AI research advances: https://techcrunch.com/2024/ai-story\n'
                '- New startup funding: https://techcrunch.com/2024/startup\n\n'
                'Best regards, The TechCrunch Team'
            )
        )
        # Legitimate email might still trigger brand check — score should be low
        assert result.rule_score <= 10

    def test_job_offer_email(self):
        """Standard job offer email without suspicious elements."""
        result = analyze_email(
            sender='hr@bigcorp.com',
            subject='Job Offer — Software Developer Position',
            body=(
                'Dear Applicant,\n\n'
                'We are pleased to offer you the position of Software Developer. '
                'Please review the attached offer letter and respond by Friday.\n\n'
                'Sincerely, HR Department'
            )
        )
        assert result.rule_score <= 5
        assert len(result.indicators) == 0

    def test_order_confirmation_email(self):
        """Order confirmation from a recognizable retailer."""
        result = analyze_email(
            sender='orders@amazon.com',
            subject='Your Amazon order has been shipped',
            body=(
                'Hi, your order #1234-5678 has been shipped. '
                'Track your package at https://amazon.com/track/1234 '
                'Expected delivery: Monday.'
            )
        )
        # Might detect Amazon brand mention, but score should be low
        # because sender domain matches
        assert result.rule_score <= 15


# ================================================================
# AMBIGUOUS EMAILS
# ================================================================

class TestAmbiguousEmails:

    def test_security_notification_legitimate_domain(self):
        """Security alert from what appears to be a legitimate company domain."""
        result = analyze_email(
            sender='security@mycompany.com',
            subject='Security alert: new sign-in detected',
            body=(
                'We detected a new sign-in to your account from a new device. '
                'If this was you, no action is needed. If not, please contact us.'
            )
        )
        # Might have low-medium score due to urgency language but no definitive phishing signals
        assert isinstance(result.rule_score, int)
        assert 0 <= result.rule_score <= 60

    def test_password_reset_email(self):
        """Password reset email — contains 'password' but may be legitimate."""
        result = analyze_email(
            sender='noreply@service.com',
            subject='Password Reset Request',
            body=(
                'We received a request to reset your password. '
                'Click the link below to reset it. The link expires in 1 hour.'
            )
        )
        # May detect CREDENTIAL_REQUEST — this is a gray area
        assert isinstance(result, DetectionResult)
        assert isinstance(result.rule_score, int)


# ================================================================
# MALFORMED / EDGE INPUTS
# ================================================================

class TestMalformedInputs:

    def test_empty_body_still_runs(self):
        """Empty body should not crash the engine."""
        result = analyze_email(
            sender='test@test.com',
            subject='Test',
            body=''
        )
        assert isinstance(result, DetectionResult)
        assert result.rule_score >= 0

    def test_body_with_only_whitespace(self):
        """Body with only whitespace."""
        result = analyze_email(
            sender='test@test.com',
            subject='Test',
            body='   \n\t   '
        )
        assert isinstance(result, DetectionResult)

    def test_special_characters_in_body(self):
        """Body with SQL injection-like content — should not crash."""
        result = analyze_email(
            sender='attacker@evil.com',
            subject="Test'; DROP TABLE scans;--",
            body="Robert'); DROP TABLE scans;-- Please verify your password."
        )
        assert isinstance(result, DetectionResult)
        assert result.rule_score >= 0

    def test_html_in_body(self):
        """HTML body with hidden elements."""
        result = analyze_email(
            sender='phish@example.com',
            subject='Important',
            body='<p style="display:none">Hidden text</p><p>Click here to verify</p>'
        )
        names = get_indicator_names(result)
        assert 'HIDDEN_HTML_CONTENT' in names

    def test_oversized_body(self):
        """Extremely long body — should not crash."""
        long_body = 'This is a normal email sentence. ' * 2000  # ~64 KB
        result = analyze_email(
            sender='test@test.com',
            subject='Test',
            body=long_body
        )
        assert isinstance(result, DetectionResult)
        # Score should be capped at 60
        assert result.rule_score <= 60

    def test_unicode_content(self):
        """Email with Unicode/emoji content."""
        result = analyze_email(
            sender='unicode@例え.jp',
            subject='Вашa учетная запись заблокирована',
            body='Πατήστε εδώ για να επαληθεύσετε τον κωδικό σας 🔐'
        )
        assert isinstance(result, DetectionResult)

    def test_very_short_body(self):
        """Very short body."""
        result = analyze_email(
            sender='a@b.com',
            subject='Hi',
            body='Hi'
        )
        assert isinstance(result, DetectionResult)
        assert result.rule_score >= 0
