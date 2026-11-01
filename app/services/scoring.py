"""
PhishGuard AI - Risk Scoring Module
Combines rule-based detection scores with AI analysis to produce
a final, explainable risk score from 0 to 100.

Score breakdown:
  - Rule-based indicators: 0-60 points (hard cap)
  - AI assessment:         0-40 points (scaled from AI confidence)
  - Total:                 0-100 points (capped)

Risk Categories:
  0-24  → LOW      (green)
  25-49 → MEDIUM   (yellow)
  50-74 → HIGH     (orange)
  75-100→ CRITICAL (red)
"""
from dataclasses import dataclass, field
from typing import Optional


# -------------------------------------------------------------------
# Risk Level Configuration
# -------------------------------------------------------------------
RISK_LEVELS = [
    (0,  24,  'LOW',      'green',  'Safe',       0),
    (25, 49,  'MEDIUM',   'yellow', 'Suspicious',  1),
    (50, 74,  'HIGH',     'orange', 'Suspicious',  2),
    (75, 100, 'CRITICAL', 'red',    'Malicious',   3),
]

# How many AI points a "Malicious" verdict contributes
AI_VERDICT_BONUS = {
    'Malicious':  40,
    'Suspicious': 20,
    'Safe':        0,
}


@dataclass
class ScoreResult:
    """Complete scoring output."""
    rule_score: int
    ai_score: int
    final_score: int
    risk_level: str           # LOW / MEDIUM / HIGH / CRITICAL
    risk_color: str           # green / yellow / orange / red
    verdict: str              # Safe / Suspicious / Malicious
    ai_confidence: Optional[int]
    explanation: str
    indicators: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    reasons: list = field(default_factory=list)
    recommended_actions: list = field(default_factory=list)
    ai_verdict: Optional[str] = None
    ai_uncertainty: str = ''
    ollama_used: bool = False

    def to_dict(self) -> dict:
        return {
            'rule_score': self.rule_score,
            'ai_score': self.ai_score,
            'final_score': self.final_score,
            'risk_level': self.risk_level,
            'risk_color': self.risk_color,
            'verdict': self.verdict,
            'ai_confidence': self.ai_confidence,
            'explanation': self.explanation,
            'indicators': self.indicators,
            'evidence': self.evidence,
            'reasons': self.reasons,
            'recommended_actions': self.recommended_actions,
            'ai_verdict': self.ai_verdict,
            'ai_uncertainty': self.ai_uncertainty,
            'ollama_used': self.ollama_used,
        }


# -------------------------------------------------------------------
# Public API
# -------------------------------------------------------------------
def calculate_score(
    rule_result: dict,
    ai_result: Optional[dict] = None
) -> ScoreResult:
    """
    Calculate the final risk score by combining rule-based and AI scores.

    Args:
        rule_result: Output from phishing_detector.analyze_email().to_dict()
        ai_result:   Validated AI response dict from ollama_service, or None.

    Returns:
        A ScoreResult containing the final score and all metadata.
    """
    rule_score = min(rule_result.get('rule_score', 0), 60)
    indicators = rule_result.get('indicators', [])
    evidence = rule_result.get('evidence_snippets', [])

    ai_score = 0
    ai_confidence = None
    ai_verdict = None
    ai_uncertainty = ''
    reasons = []
    ai_actions = []
    ollama_used = False

    if ai_result and ai_result.get('success') and ai_result.get('data'):
        data = ai_result['data']
        ai_verdict = data.get('verdict', 'Suspicious')
        ai_confidence = data.get('confidence', 50)
        ai_uncertainty = data.get('uncertainty', '')
        reasons = data.get('reasons', [])
        ai_actions = data.get('recommended_actions', [])
        ollama_used = True

        # AI score: weighted by confidence and verdict
        base = AI_VERDICT_BONUS.get(ai_verdict, 20)
        # Scale by confidence: 0.5x at 50% confidence, 1.0x at 100%
        scale = max(0.5, ai_confidence / 100.0)
        ai_score = min(40, int(base * scale))

        # Add AI evidence to our evidence list (deduplicated)
        ai_evidence = data.get('evidence', [])
        for item in ai_evidence:
            if item and item not in evidence:
                evidence.append(item)

    # Combine scores
    final_score = min(100, rule_score + ai_score)

    # Determine risk level and verdict
    risk_level, risk_color, verdict = _get_risk_level(final_score)

    # Override verdict if AI says Malicious and score is borderline
    if ai_verdict == 'Malicious' and final_score >= 50:
        verdict = 'Malicious'
    elif ai_verdict == 'Safe' and final_score <= 24:
        verdict = 'Safe'

    # Build recommended actions (merge rule defaults + AI suggestions)
    recommended_actions = _build_recommended_actions(
        verdict, risk_level, indicators, ai_actions
    )

    # Build explanation paragraph
    explanation = _build_explanation(
        rule_score, ai_score, final_score,
        risk_level, verdict, len(indicators),
        ai_verdict, ai_confidence, ollama_used
    )

    return ScoreResult(
        rule_score=rule_score,
        ai_score=ai_score,
        final_score=final_score,
        risk_level=risk_level,
        risk_color=risk_color,
        verdict=verdict,
        ai_confidence=ai_confidence,
        explanation=explanation,
        indicators=[_format_indicator(ind) for ind in indicators],
        evidence=evidence[:10],     # Limit displayed evidence
        reasons=reasons[:8],         # Limit AI reasons
        recommended_actions=recommended_actions[:6],
        ai_verdict=ai_verdict,
        ai_uncertainty=ai_uncertainty,
        ollama_used=ollama_used,
    )


# -------------------------------------------------------------------
# Private Helpers
# -------------------------------------------------------------------

def _get_risk_level(score: int) -> tuple[str, str, str]:
    """Return (risk_level, color, verdict) for a given score."""
    for low, high, level, color, verdict, _ in RISK_LEVELS:
        if low <= score <= high:
            return level, color, verdict
    return 'CRITICAL', 'red', 'Malicious'


def _format_indicator(ind: dict) -> dict:
    """Ensure indicator dict has consistent keys for the template."""
    return {
        'name': ind.get('name', ''),
        'description': ind.get('description', ''),
        'points': ind.get('points', 0),
        'evidence': ind.get('evidence', ''),
    }


def _build_recommended_actions(
    verdict: str,
    risk_level: str,
    indicators: list,
    ai_actions: list
) -> list:
    """Produce a deduplicated list of recommended actions."""
    actions = list(ai_actions)  # Start with AI suggestions

    # Add rule-based defaults
    defaults = []
    if verdict == 'Safe':
        defaults = [
            "No immediate action required.",
            "Always remain cautious with unexpected emails.",
        ]
    elif verdict == 'Suspicious':
        defaults = [
            "Do not click any links in this email.",
            "Do not reply to this email or provide personal information.",
            "Verify the sender's identity through a separate, known contact method.",
            "Report the email to your IT department or email provider.",
        ]
    else:  # Malicious
        defaults = [
            "Do NOT click any links or open any attachments.",
            "Delete this email immediately.",
            "Report it as phishing to your email provider.",
            "If you already clicked a link, change your passwords immediately.",
            "Alert your IT/security team right away.",
            "Check for unauthorized account activity.",
        ]

    # Check indicators for specific advice
    indicator_names = {ind.get('name', '') for ind in indicators}
    if 'CREDENTIAL_REQUEST' in indicator_names:
        defaults.append("Never share your password, OTP, or PIN via email.")
    if 'PAYMENT_LURE' in indicator_names:
        defaults.append("Verify any payment requests directly with the organization via their official website.")

    # Deduplicate
    seen = set()
    result = []
    for action in (actions + defaults):
        if action.lower() not in seen:
            seen.add(action.lower())
            result.append(action)
    return result


def _build_explanation(
    rule_score: int,
    ai_score: int,
    final_score: int,
    risk_level: str,
    verdict: str,
    num_indicators: int,
    ai_verdict: Optional[str],
    ai_confidence: Optional[int],
    ollama_used: bool,
) -> str:
    """Generate a human-readable explanation of the score."""
    parts = [
        f"This email received a final risk score of {final_score}/100, "
        f"placing it in the {risk_level} risk category.",
        f"The rule-based engine detected {num_indicators} suspicious indicator(s), "
        f"contributing {rule_score} points.",
    ]

    if ollama_used and ai_verdict:
        parts.append(
            f"The AI model (Llama 3.2) assessed the email as '{ai_verdict}' "
            f"with {ai_confidence}% confidence, contributing {ai_score} additional points."
        )
    else:
        parts.append(
            "AI analysis was not available for this scan. "
            "The score is based on rule-based detection only."
        )

    if verdict == 'Safe':
        parts.append(
            "Based on this analysis, the email appears to be safe. "
            "However, no automated system is perfect — always exercise caution."
        )
    elif verdict == 'Suspicious':
        parts.append(
            "The email shows characteristics consistent with phishing or social engineering. "
            "It is strongly advised NOT to click any links or provide information."
        )
    else:
        parts.append(
            "The email displays strong phishing indicators. "
            "It is likely malicious. Do not interact with this email and report it immediately."
        )

    parts.append(
        "⚠️  This analysis is advisory only. PhishGuard AI assists in identifying risks "
        "but cannot guarantee 100% accuracy. Use your own judgement."
    )

    return " ".join(parts)
