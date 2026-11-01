"""
PhishGuard AI - Rule-Based Phishing Detection Engine
Applies a set of deterministic rules to identify phishing indicators
in email sender, subject, and body. Each check is independent and
returns a list of Indicator objects.

Rule points are capped so that the combined rule score never exceeds
60 points (the remaining 40 points come from AI analysis).
"""
import re
from dataclasses import dataclass, field
from typing import Optional


# -------------------------------------------------------------------
# Data Structures
# -------------------------------------------------------------------
@dataclass
class Indicator:
    """Represents a single detected phishing signal."""
    name: str            # Short name / ID
    description: str     # Human-readable description shown to user
    points: int          # Risk points contributed (1-15 per indicator)
    evidence: str = ''   # The specific text/URL that triggered this


@dataclass
class DetectionResult:
    """Aggregated output of the rule engine."""
    indicators: list[Indicator] = field(default_factory=list)
    evidence_snippets: list[str] = field(default_factory=list)
    rule_score: int = 0          # Sum of indicator points, capped at 60

    def to_dict(self) -> dict:
        return {
            'indicators': [
                {
                    'name': ind.name,
                    'description': ind.description,
                    'points': ind.points,
                    'evidence': ind.evidence,
                }
                for ind in self.indicators
            ],
            'evidence_snippets': self.evidence_snippets,
            'rule_score': self.rule_score,
        }


# -------------------------------------------------------------------
# Compiled Regex Patterns  (compiled once at module load for speed)
# -------------------------------------------------------------------

# Urgency / threat keywords
_URGENCY_PATTERNS = re.compile(
    r'\b(urgent|immediately|act now|expires?|expire[sd]?|deadline|'
    r'limited time|last chance|final notice|account (will be )?suspend|'
    r'within \d+ hours?|action required|verify now|confirm now|'
    r'your account has been|unauthorized access|unusual activity|'
    r'suspicious login|security alert|alert:|warning:)\b',
    re.IGNORECASE
)

# Password / credential harvesting
_CREDENTIAL_PATTERNS = re.compile(
    r'\b(password|passcode|OTP|one.time.pin|one.time.password|'
    r'verification code|security code|PIN|login credential|'
    r'enter your.{0,30}(password|credential|pin))\b',
    re.IGNORECASE
)

# Payment / financial lure
_PAYMENT_PATTERNS = re.compile(
    r'\b(click here to pay|payment (required|due|overdue|pending)|'
    r'invoice (attached|overdue)|billing (issue|problem|error)|'
    r'credit card|bank account|wire transfer|PayPal|Zelle|Venmo|'
    r'gift card|send money|refund (processing|pending)|prize|'
    r'lottery|you (have )?won|free gift|claim (your )?(reward|prize))\b',
    re.IGNORECASE
)

# Suspicious URL patterns
_SUSPICIOUS_URL_PATTERNS = re.compile(
    r'(https?://\S+)',
    re.IGNORECASE
)
_URL_SHORTENERS = re.compile(
    r'(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|'
    r'adf\.ly|rebrand\.ly|short\.io|cutt\.ly|tiny\.cc)',
    re.IGNORECASE
)
_IP_URL_PATTERN = re.compile(
    r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    re.IGNORECASE
)
_MISLEADING_LINK_PATTERN = re.compile(
    r'<a[^>]+href=["\']?(https?://[^"\'>\s]+)["\']?[^>]*>\s*(https?://[^<\s]+)\s*</a>',
    re.IGNORECASE
)

# Phishing-associated top-level domains (commonly abused)
_SUSPICIOUS_TLDS = re.compile(
    r'https?://[^\s/]+\.(tk|ml|ga|cf|gq|xyz|top|click|link|download|'
    r'loan|win|racing|bid|date|faith|review|trade|webcam|work|party)(/|\s|$)',
    re.IGNORECASE
)

# Sensitive info requests
_SENSITIVE_REQUEST = re.compile(
    r'\b(social security|SSN|date of birth|DOB|bank account number|'
    r'routing number|credit card number|CVV|card number|'
    r'national id|passport number|driver.{0,5}license)\b',
    re.IGNORECASE
)

# Impersonation keywords for well-known brands
_IMPERSONATION = re.compile(
    r'\b(paypal|amazon|apple|google|microsoft|netflix|facebook|instagram|'
    r'twitter|linkedin|bank of america|chase|wells fargo|citibank|'
    r'irs|internal revenue|government|federal bureau|fbi|interpol|'
    r'your bank|your account)\b',
    re.IGNORECASE
)

# Free hosting / suspicious domains commonly used in phishing
_SUSPICIOUS_DOMAINS = re.compile(
    r'https?://[^\s/]*(000webhost|weebly|wix\.com|blogspot|'
    r'netlify|github\.io|glitch\.me|replit\.dev|vercel\.app)[^\s]*',
    re.IGNORECASE
)

# Legitimate-looking sender spoofing cues
_SPOOFING_KEYWORDS = re.compile(
    r'\b(no.?reply|do.?not.?reply|support|security|account|billing|'
    r'help|admin|alert|notification|service|team)@',
    re.IGNORECASE
)

# HTML-based tricks
_HTML_HIDDEN = re.compile(
    r'(display:\s*none|visibility:\s*hidden|font-size:\s*0)',
    re.IGNORECASE
)

# Excessive exclamation marks
_EXCESSIVE_PUNCTUATION = re.compile(r'!{3,}|\?{3,}|[A-Z\s]{20,}')


# -------------------------------------------------------------------
# Public API
# -------------------------------------------------------------------
def analyze_email(sender: str, subject: str, body: str) -> DetectionResult:
    """
    Run all rule-based checks against the provided email fields.

    Args:
        sender:  Sender address or display-name + address.
        subject: Email subject line.
        body:    Email body (plain text or HTML).

    Returns:
        A DetectionResult containing all triggered indicators,
        evidence snippets, and the raw rule score (0-60).
    """
    result = DetectionResult()
    full_text = f"{subject}\n{body}"  # Subject + body combined for keyword searches

    # --- Run each check ---
    _check_urgency(full_text, result)
    _check_credentials(full_text, result)
    _check_payment(full_text, result)
    _check_urls(body, result)
    _check_sensitive_info(full_text, result)
    _check_impersonation(full_text, sender, result)
    _check_sender(sender, result)
    _check_subject_tricks(subject, result)
    _check_html_tricks(body, result)
    _check_excessive_punctuation(full_text, result)

    # Cap rule score at 60
    raw_score = sum(ind.points for ind in result.indicators)
    result.rule_score = min(raw_score, 60)

    return result


# -------------------------------------------------------------------
# Individual Check Functions
# -------------------------------------------------------------------

def _check_urgency(text: str, result: DetectionResult) -> None:
    """Detect urgency and threat language."""
    matches = _URGENCY_PATTERNS.findall(text)
    if matches:
        unique = list(set(m if isinstance(m, str) else m[0] for m in matches))
        snippet = ', '.join(f'"{m}"' for m in unique[:3])
        result.indicators.append(Indicator(
            name='URGENCY_LANGUAGE',
            description='Email uses urgent or threatening language to pressure the reader.',
            points=10,
            evidence=f"Found: {snippet}"
        ))
        result.evidence_snippets.append(f"Urgency keywords detected: {snippet}")


def _check_credentials(text: str, result: DetectionResult) -> None:
    """Detect requests for passwords, OTPs, or PINs."""
    matches = _CREDENTIAL_PATTERNS.findall(text)
    if matches:
        unique = list(set(m if isinstance(m, str) else m[0] for m in matches))
        snippet = ', '.join(f'"{m}"' for m in unique[:3])
        result.indicators.append(Indicator(
            name='CREDENTIAL_REQUEST',
            description='Email requests passwords, OTPs, PINs, or other credentials.',
            points=15,
            evidence=f"Found: {snippet}"
        ))
        result.evidence_snippets.append(f"Credential request keywords: {snippet}")


def _check_payment(text: str, result: DetectionResult) -> None:
    """Detect payment lures or financial deception."""
    matches = _PAYMENT_PATTERNS.findall(text)
    if matches:
        unique = list(set(m if isinstance(m, str) else m[0] for m in matches))
        snippet = ', '.join(f'"{m}"' for m in unique[:3])
        result.indicators.append(Indicator(
            name='PAYMENT_LURE',
            description='Email contains financial lures, payment requests, or prize notifications.',
            points=10,
            evidence=f"Found: {snippet}"
        ))
        result.evidence_snippets.append(f"Financial keywords: {snippet}")


def _check_urls(text: str, result: DetectionResult) -> None:
    """Analyze URLs in the email body for suspicious patterns."""
    urls = _SUSPICIOUS_URL_PATTERNS.findall(text)
    if not urls:
        return

    # IP-based URLs
    ip_urls = [u for u in urls if _IP_URL_PATTERN.match(u)]
    if ip_urls:
        result.indicators.append(Indicator(
            name='IP_BASED_URL',
            description='Email contains URLs using raw IP addresses instead of domain names.',
            points=12,
            evidence=ip_urls[0][:100]
        ))
        result.evidence_snippets.append(f"IP-based URL: {ip_urls[0][:80]}")

    # URL shorteners
    short_urls = [u for u in urls if _URL_SHORTENERS.search(u)]
    if short_urls:
        result.indicators.append(Indicator(
            name='URL_SHORTENER',
            description='Email uses URL shortening services to hide the real destination.',
            points=8,
            evidence=short_urls[0][:100]
        ))
        result.evidence_snippets.append(f"Shortened URL detected: {short_urls[0][:80]}")

    # Suspicious TLDs
    sus_tld = [u for u in urls if _SUSPICIOUS_TLDS.search(u)]
    if sus_tld:
        result.indicators.append(Indicator(
            name='SUSPICIOUS_TLD',
            description='Email links use suspicious top-level domains commonly associated with phishing.',
            points=10,
            evidence=sus_tld[0][:100]
        ))
        result.evidence_snippets.append(f"Suspicious TLD in URL: {sus_tld[0][:80]}")

    # Suspicious hosting platforms (when used as phishing pages)
    sus_host = [u for u in urls if _SUSPICIOUS_DOMAINS.search(u)]
    if sus_host:
        result.indicators.append(Indicator(
            name='FREE_HOSTING_URL',
            description='Email links to a free hosting service, which is commonly abused for phishing pages.',
            points=7,
            evidence=sus_host[0][:100]
        ))
        result.evidence_snippets.append(f"Free-host URL: {sus_host[0][:80]}")

    # Misleading link text
    misleading = _MISLEADING_LINK_PATTERN.findall(text)
    if misleading:
        href, link_text = misleading[0]
        if not _same_domain(href, link_text):
            result.indicators.append(Indicator(
                name='MISLEADING_LINK',
                description='Email shows a different URL than where the link actually leads.',
                points=12,
                evidence=f"Displayed: {link_text[:60]} → Actual: {href[:60]}"
            ))
            result.evidence_snippets.append(
                f"Misleading link — shown: {link_text[:50]}, real: {href[:50]}"
            )


def _check_sensitive_info(text: str, result: DetectionResult) -> None:
    """Detect requests for highly sensitive personal information."""
    matches = _SENSITIVE_REQUEST.findall(text)
    if matches:
        unique = list(set(m if isinstance(m, str) else m[0] for m in matches))
        snippet = ', '.join(f'"{m}"' for m in unique[:3])
        result.indicators.append(Indicator(
            name='SENSITIVE_INFO_REQUEST',
            description='Email requests highly sensitive personal information (SSN, bank account, etc.).',
            points=15,
            evidence=f"Found: {snippet}"
        ))
        result.evidence_snippets.append(f"Sensitive info request: {snippet}")


def _check_impersonation(text: str, sender: str, result: DetectionResult) -> None:
    """Detect brand impersonation."""
    combined = text + ' ' + sender
    matches = _IMPERSONATION.findall(combined)
    if matches:
        brands = list(set(m.lower() for m in matches))[:3]
        snippet = ', '.join(f'"{b}"' for b in brands)

        # Check for domain mismatch (e.g., claims to be PayPal but sends from gmail.com)
        domain_mismatch = False
        sender_domain = _extract_domain(sender)
        for brand in brands:
            # Strip common suffixes to get core brand name
            brand_core = brand.split()[0]
            if brand_core and sender_domain and brand_core not in sender_domain:
                domain_mismatch = True
                break

        if domain_mismatch:
            result.indicators.append(Indicator(
                name='BRAND_DOMAIN_MISMATCH',
                description=f'Email claims to be from {brands[0]} but the sender domain does not match.',
                points=15,
                evidence=f"Brand mentioned: {snippet}, Sender domain: {sender_domain}"
            ))
            result.evidence_snippets.append(
                f"Brand impersonation: Claims '{brands[0]}' but sent from '{sender_domain}'"
            )
        else:
            result.indicators.append(Indicator(
                name='BRAND_IMPERSONATION',
                description=f'Email mentions well-known brands which may indicate impersonation.',
                points=5,
                evidence=f"Brands mentioned: {snippet}"
            ))
            result.evidence_snippets.append(f"Brand references: {snippet}")


def _check_sender(sender: str, result: DetectionResult) -> None:
    """Check sender address for suspicious patterns."""
    # Generic/service account names (common in phishing)
    if _SPOOFING_KEYWORDS.search(sender):
        domain = _extract_domain(sender)
        # These are suspicious when combined with free email providers
        if domain and _is_free_email_domain(domain):
            result.indicators.append(Indicator(
                name='SUSPICIOUS_SENDER',
                description='Sender uses a service-like display name with a free email provider domain.',
                points=8,
                evidence=f"Sender: {sender[:80]}"
            ))
            result.evidence_snippets.append(f"Suspicious sender pattern: {sender[:60]}")

    # Sender domain is a free consumer email service
    domain = _extract_domain(sender)
    if domain and _is_free_email_domain(domain):
        result.indicators.append(Indicator(
            name='FREE_EMAIL_SENDER',
            description='Email was sent from a free consumer email service (unusual for official communications).',
            points=4,
            evidence=f"Sender domain: {domain}"
        ))


def _check_subject_tricks(subject: str, result: DetectionResult) -> None:
    """Check the subject line for phishing tricks."""
    # ALL CAPS subject (shouting for urgency)
    if len(subject) > 5 and subject.upper() == subject and any(c.isalpha() for c in subject):
        result.indicators.append(Indicator(
            name='ALL_CAPS_SUBJECT',
            description='Subject line is written in ALL CAPS, a common phishing tactic to create panic.',
            points=4,
            evidence=f"Subject: {subject[:80]}"
        ))
        result.evidence_snippets.append(f"ALL CAPS subject: '{subject[:60]}'")

    # Re: or Fwd: spoofing (injected thread history)
    if re.match(r'^(Re:|Fwd:|FW:)', subject, re.IGNORECASE) and len(subject) < 15:
        result.indicators.append(Indicator(
            name='FAKE_REPLY_FORWARD',
            description='Subject mimics a reply or forwarded message with little content, a common trick.',
            points=5,
            evidence=f"Subject: {subject}"
        ))


def _check_html_tricks(body: str, result: DetectionResult) -> None:
    """Detect HTML-based obfuscation tricks."""
    if _HTML_HIDDEN.search(body):
        result.indicators.append(Indicator(
            name='HIDDEN_HTML_CONTENT',
            description='Email uses CSS to hide text, possibly to evade spam filters.',
            points=8,
            evidence="Hidden CSS detected (display:none or visibility:hidden)"
        ))
        result.evidence_snippets.append("Hidden HTML elements detected in email body")


def _check_excessive_punctuation(text: str, result: DetectionResult) -> None:
    """Detect excessive use of !!! or ALL CAPS blocks."""
    matches = _EXCESSIVE_PUNCTUATION.findall(text)
    if matches:
        result.indicators.append(Indicator(
            name='EXCESSIVE_PUNCTUATION',
            description='Email uses excessive exclamation marks or ALL CAPS to create false urgency.',
            points=3,
            evidence=f"e.g., '{matches[0][:40]}'"
        ))


# -------------------------------------------------------------------
# Helper Functions
# -------------------------------------------------------------------

def _extract_domain(email_str: str) -> Optional[str]:
    """Extract the domain part from an email address string."""
    match = re.search(r'@([\w.-]+)', email_str)
    return match.group(1).lower() if match else None


_FREE_DOMAINS = frozenset([
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com',
    'aol.com', 'icloud.com', 'protonmail.com', 'mail.com', 'yandex.com',
    'gmx.com', 'zoho.com', 'inbox.com', 'rediffmail.com', 'tutanota.com',
])

def _is_free_email_domain(domain: str) -> bool:
    return domain.lower() in _FREE_DOMAINS


def _same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs share the same domain."""
    def extract(url: str) -> str:
        m = re.search(r'https?://([^/?\s]+)', url)
        return m.group(1).lower() if m else ''
    return extract(url1) == extract(url2)
