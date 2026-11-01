"""
PhishGuard AI — Tests: Risk Scoring System
Tests the scoring module with various rule and AI input combinations,
boundary conditions, and category mappings.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.scoring import calculate_score, RISK_LEVELS


# ================================================================
# Helpers
# ================================================================
def make_rule_result(score: int, indicators: list = None) -> dict:
    """Create a minimal rule_result dict."""
    return {
        'rule_score': score,
        'indicators': indicators or [],
        'evidence_snippets': [],
    }


def make_ai_result(verdict: str, confidence: int, reasons: list = None) -> dict:
    """Create a mock successful AI result dict."""
    return {
        'success': True,
        'data': {
            'verdict': verdict,
            'confidence': confidence,
            'reasons': reasons or ['Reason 1'],
            'evidence': ['Evidence snippet'],
            'uncertainty': '',
            'recommended_actions': ['Do not click links'],
        },
        'error': None,
    }


def make_failed_ai() -> dict:
    """Create a failed AI result (Ollama offline scenario)."""
    return {
        'success': False,
        'data': None,
        'error': 'Cannot connect to Ollama.',
    }


# ================================================================
# SCORE BOUNDARY TESTS
# ================================================================

class TestScoreBoundaries:

    def test_zero_rule_score_no_ai(self):
        """All-zero inputs produce score of 0."""
        result = calculate_score(make_rule_result(0), None)
        assert result.final_score == 0
        assert result.risk_level == 'LOW'
        assert result.verdict == 'Safe'

    def test_max_rule_score_no_ai(self):
        """Max rule score (60) with no AI gives final score of 60 → HIGH."""
        result = calculate_score(make_rule_result(60), None)
        assert result.final_score == 60
        assert result.risk_level == 'HIGH'

    def test_rule_score_capped_at_60(self):
        """Rule scores > 60 are capped."""
        result = calculate_score(make_rule_result(80), None)
        assert result.rule_score == 60
        assert result.final_score <= 60

    def test_max_ai_score(self):
        """Max AI contribution: Malicious verdict, 100% confidence → 40 pts."""
        result = calculate_score(make_rule_result(0), make_ai_result('Malicious', 100))
        assert result.ai_score == 40
        assert result.final_score == 40

    def test_total_capped_at_100(self):
        """Combined score cannot exceed 100."""
        result = calculate_score(make_rule_result(60), make_ai_result('Malicious', 100))
        assert result.final_score <= 100

    def test_final_score_is_integer(self):
        """Final score is always an integer."""
        result = calculate_score(make_rule_result(33), make_ai_result('Suspicious', 77))
        assert isinstance(result.final_score, int)


# ================================================================
# RISK CATEGORY MAPPING
# ================================================================

class TestRiskCategories:

    @pytest.mark.parametrize("score,expected_level,expected_verdict", [
        (0,   'LOW',      'Safe'),
        (10,  'LOW',      'Safe'),
        (24,  'LOW',      'Safe'),
        (25,  'MEDIUM',   'Suspicious'),
        (40,  'MEDIUM',   'Suspicious'),
        (49,  'MEDIUM',   'Suspicious'),
        (50,  'HIGH',     'Suspicious'),
        (65,  'HIGH',     'Suspicious'),
        (74,  'HIGH',     'Suspicious'),
        (75,  'CRITICAL', 'Malicious'),
        (90,  'CRITICAL', 'Malicious'),
        (100, 'CRITICAL', 'Malicious'),
    ])
    def test_risk_category(self, score, expected_level, expected_verdict):
        """Each score maps to the correct risk level and verdict."""
        # Rule score is capped at 60, so scores > 60 include AI contribution
        if score <= 60:
            result = calculate_score(make_rule_result(score), None)
        elif score < 75:
            # Score 61-74: rule score + Suspicious AI bonus (20 pts)
            rule_pts = score - 20
            result = calculate_score(make_rule_result(rule_pts), make_ai_result('Suspicious', 100))
        else:
            # Score 75-100: rule score + Malicious AI bonus (40 pts)
            rule_pts = score - 40
            result = calculate_score(make_rule_result(rule_pts), make_ai_result('Malicious', 100))

        assert result.final_score == score
        assert result.risk_level == expected_level, \
            f"Score {score}: expected {expected_level}, got {result.risk_level}"
        assert result.verdict == expected_verdict, \
            f"Score {score}: expected verdict {expected_verdict}, got {result.verdict}"


# ================================================================
# AI INTEGRATION IN SCORING
# ================================================================

class TestAIScoring:

    def test_ai_malicious_adds_to_score(self):
        """AI Malicious verdict should add more points than Safe."""
        result_mal = calculate_score(make_rule_result(20), make_ai_result('Malicious', 100))
        result_safe = calculate_score(make_rule_result(20), make_ai_result('Safe', 100))
        assert result_mal.ai_score > result_safe.ai_score

    def test_ai_confidence_scales_score(self):
        """Lower confidence should produce lower AI score."""
        result_high = calculate_score(make_rule_result(0), make_ai_result('Malicious', 100))
        result_low  = calculate_score(make_rule_result(0), make_ai_result('Malicious', 30))
        assert result_high.ai_score >= result_low.ai_score

    def test_failed_ai_gives_zero_ai_score(self):
        """Failed Ollama call contributes zero AI points."""
        result = calculate_score(make_rule_result(30), make_failed_ai())
        assert result.ai_score == 0
        assert result.ollama_used is False

    def test_ollama_used_flag(self):
        """ollama_used flag is True when AI succeeds."""
        result = calculate_score(make_rule_result(10), make_ai_result('Safe', 80))
        assert result.ollama_used is True

    def test_none_ai_result(self):
        """None AI result is handled gracefully."""
        result = calculate_score(make_rule_result(10), None)
        assert result.ai_score == 0
        assert result.ai_verdict is None

    def test_ai_malicious_verdict_overrides_safe_score(self):
        """If AI says Malicious and score is ≥ 50, verdict becomes Malicious."""
        result = calculate_score(make_rule_result(40), make_ai_result('Malicious', 100))
        if result.final_score >= 50:
            assert result.verdict == 'Malicious'


# ================================================================
# OUTPUT STRUCTURE
# ================================================================

class TestOutputStructure:

    def test_to_dict_has_required_keys(self):
        """ScoreResult.to_dict() includes all expected keys."""
        result = calculate_score(make_rule_result(30), make_ai_result('Suspicious', 70))
        d = result.to_dict()
        required_keys = [
            'rule_score', 'ai_score', 'final_score', 'risk_level',
            'risk_color', 'verdict', 'ai_confidence', 'explanation',
            'indicators', 'evidence', 'reasons', 'recommended_actions',
            'ai_verdict', 'ollama_used'
        ]
        for key in required_keys:
            assert key in d, f"Missing key in to_dict(): {key}"

    def test_explanation_is_non_empty_string(self):
        """Explanation is always a non-empty string."""
        result = calculate_score(make_rule_result(0), None)
        assert isinstance(result.explanation, str)
        assert len(result.explanation) > 20

    def test_recommended_actions_is_list(self):
        """recommended_actions is always a list."""
        result = calculate_score(make_rule_result(80), make_ai_result('Malicious', 95))
        assert isinstance(result.recommended_actions, list)
        assert len(result.recommended_actions) > 0

    def test_risk_color_values(self):
        """risk_color is one of the valid color strings."""
        valid_colors = {'green', 'yellow', 'orange', 'red'}
        for score in [0, 25, 50, 75]:
            result = calculate_score(make_rule_result(score), None)
            assert result.risk_color in valid_colors
